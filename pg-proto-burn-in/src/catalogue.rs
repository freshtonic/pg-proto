//! Authoritative protocol catalogue assembly and evidence auditing.

use std::{
    collections::{BTreeMap, BTreeSet},
    error::Error,
    path::PathBuf,
};

use serde::{Deserialize, Serialize};

use crate::{atomic_write, option};

const GENERATED_SNAPSHOT: &str = include_str!("../catalogue/generated-v1.json");
const CATALOGUE_LOCK: &str = include_str!("../catalogue/catalogue-lock-v1.json");
const SUPPLEMENTAL: &str = include_str!("../catalogue/supplemental-v1.json");
const MIGRATIONS: &str = include_str!("../catalogue/migrations-v1.json");
const EXEMPTIONS: &str = include_str!("../catalogue/exemptions-v1.json");
const DISPOSITIONS: &str = include_str!("../catalogue/dispositions-v1.json");

#[derive(Debug, Deserialize)]
struct GeneratedSnapshot {
    schema_version: u32,
    ids: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SupplementalCatalogue {
    schema_version: u32,
    entries: Vec<SupplementalEntry>,
}

#[derive(Debug, Deserialize)]
struct SupplementalEntry {
    id: String,
    category: String,
    description: String,
}

#[derive(Debug, Deserialize)]
struct MigrationRegistry {
    schema_version: u32,
    migrations: Vec<Migration>,
}

#[derive(Debug, Deserialize)]
struct Migration {
    id: String,
    kind: MigrationKind,
    from: Vec<String>,
    to: Vec<String>,
    reason: String,
    review: String,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum MigrationKind {
    Rename,
    Split,
    Merge,
    Retire,
}

#[derive(Debug, Deserialize)]
struct ExemptionRegistry {
    schema_version: u32,
    exemptions: Vec<Exemption>,
}

#[derive(Debug, Deserialize)]
struct ReviewedDispositionRegistry {
    schema_version: u32,
    generated_real_postgres: Vec<String>,
    generated_indirect_evidence: String,
    supplemental_real_postgres: Vec<String>,
    supplemental_scripted: Vec<String>,
    supplemental_indirect: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct Exemption {
    id: String,
    reason: String,
    postgres_versions: Vec<String>,
    scripted_coverage: Option<String>,
    owner: String,
    reviewed_by: String,
    review: String,
    expires_on: String,
}

#[derive(Debug, Default, Deserialize)]
struct EvidenceArtifact {
    #[serde(default)]
    coverage: EvidenceCoverage,
}

#[derive(Debug, Default, Deserialize)]
struct EvidenceCoverage {
    #[serde(default)]
    real_postgres: Vec<String>,
    #[serde(default)]
    scripted: Vec<String>,
    #[serde(default)]
    indirect: Vec<String>,
    #[serde(default)]
    exempted: Vec<String>,
}

#[derive(Debug, Serialize)]
struct CatalogueResult {
    schema_version: u32,
    catalogue_version: u32,
    generated_entries: usize,
    supplemental_entries: usize,
    catalogue_entries: usize,
    disposed_entries: usize,
    missing_entries: usize,
    dispositions: Vec<Disposition>,
    missing: Vec<String>,
    success: bool,
}

#[derive(Debug, Serialize)]
struct Disposition {
    id: String,
    kind: DispositionKind,
    evidence: String,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "kebab-case")]
enum DispositionKind {
    RealPostgres,
    Scripted,
    Indirect,
    Exempted,
}

struct Authority {
    generated: BTreeSet<String>,
    supplemental: BTreeSet<String>,
    all: BTreeSet<String>,
    exemptions: Vec<Exemption>,
}

pub(crate) async fn run(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let artifacts = PathBuf::from(option(arguments, "--output-dir")?);
    let as_of = option(arguments, "--as-of")?;
    let authority = load_authority(as_of)?;
    let mut dispositions = BTreeMap::new();
    if arguments.iter().any(|argument| argument == "--approved") {
        add_reviewed_dispositions(&authority, &mut dispositions)?;
    }
    for input in option_values(arguments, "--input")? {
        let artifact: EvidenceArtifact = serde_json::from_slice(&tokio::fs::read(input).await?)?;
        add_evidence(&authority.all, &mut dispositions, &artifact.coverage, input)?;
    }
    for exemption in authority.exemptions {
        insert_disposition(
            &authority.all,
            &mut dispositions,
            &exemption.id,
            DispositionKind::Exempted,
            format!(
                "reviewed exemption {} expiring {}",
                exemption.review, exemption.expires_on
            ),
        )?;
    }

    let missing = missing_ids(&authority.all, &dispositions);
    let result = CatalogueResult {
        schema_version: 1,
        catalogue_version: 1,
        generated_entries: authority.generated.len(),
        supplemental_entries: authority.supplemental.len(),
        catalogue_entries: authority.all.len(),
        disposed_entries: dispositions.len(),
        missing_entries: missing.len(),
        dispositions: dispositions.into_values().collect(),
        success: missing.is_empty(),
        missing,
    };
    tokio::fs::create_dir_all(&artifacts).await?;
    atomic_write(
        &artifacts.join("result.json"),
        &serde_json::to_vec_pretty(&result)?,
    )
    .await?;
    let summary = format!(
        "# Protocol catalogue\n\n{}: {} of {} entries disposed; {} missing.\n",
        if result.success { "PASS" } else { "FAIL" },
        result.disposed_entries,
        result.catalogue_entries,
        result.missing_entries,
    );
    atomic_write(&artifacts.join("summary.md"), summary.as_bytes()).await?;
    if result.success {
        Ok(())
    } else {
        Err(format!("catalogue has {} missing entries", result.missing_entries).into())
    }
}

fn add_reviewed_dispositions(
    authority: &Authority,
    dispositions: &mut BTreeMap<String, Disposition>,
) -> Result<(), Box<dyn Error>> {
    let registry: ReviewedDispositionRegistry = serde_json::from_str(DISPOSITIONS)?;
    if registry.schema_version != 1 {
        return Err(format!(
            "unsupported disposition registry schema {}",
            registry.schema_version
        )
        .into());
    }
    let generated_real = unique(
        registry.generated_real_postgres,
        "generated real PostgreSQL dispositions",
    )?;
    if !generated_real.is_subset(&authority.generated) {
        return Err("generated real PostgreSQL dispositions contain an unknown ID".into());
    }
    if registry.generated_indirect_evidence.trim().is_empty() {
        return Err("generated indirect dispositions lack evidence metadata".into());
    }
    let reviewed_generated = generated_ids_snapshot()?;
    for id in &authority.generated {
        if !reviewed_generated.contains(id) {
            continue;
        }
        let (kind, evidence) = if generated_real.contains(id) {
            (
                DispositionKind::RealPostgres,
                "conformance smoke artifact through public Intermediary and PostgreSQL 14-18"
                    .to_owned(),
            )
        } else {
            (
                DispositionKind::Indirect,
                registry.generated_indirect_evidence.clone(),
            )
        };
        insert_disposition(&authority.all, dispositions, id, kind, evidence)?;
    }
    for (kind, ids, evidence) in [
        (
            DispositionKind::RealPostgres,
            registry.supplemental_real_postgres,
            "real PostgreSQL profile artifact",
        ),
        (
            DispositionKind::Scripted,
            registry.supplemental_scripted,
            "bounded scripted public-facade profile artifact",
        ),
        (
            DispositionKind::Indirect,
            registry.supplemental_indirect,
            "public authentication policy test proves PLUS-only rejection; client credentials do not yet provide channel binding",
        ),
    ] {
        let ids = unique(ids, "supplemental dispositions")?;
        if !ids.is_subset(&authority.supplemental) {
            return Err("supplemental dispositions contain an unknown or generated ID".into());
        }
        for id in ids {
            insert_disposition(&authority.all, dispositions, &id, kind, evidence.to_owned())?;
        }
    }
    Ok(())
}

fn generated_ids_snapshot() -> Result<BTreeSet<String>, Box<dyn Error>> {
    let snapshot: GeneratedSnapshot = serde_json::from_str(GENERATED_SNAPSHOT)?;
    unique(snapshot.ids, "generated catalogue snapshot")
}

fn missing_ids(
    catalogue: &BTreeSet<String>,
    dispositions: &BTreeMap<String, Disposition>,
) -> Vec<String> {
    catalogue
        .iter()
        .filter(|id| !dispositions.contains_key(*id))
        .cloned()
        .collect()
}

fn generated_ids() -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    macro_rules! extend {
        ($grammar:ident) => {
            ids.extend(
                pg_proto::grammar::$grammar::TRANSITIONS
                    .iter()
                    .map(|transition| transition.id.to_owned()),
            );
        };
    }
    extend!(frontend);
    extend!(backend);
    extend!(pre_startup);
    extend!(server_pre_startup);
    extend!(authentication);
    extend!(server_authentication);
    ids
}

fn load_authority(as_of: &str) -> Result<Authority, Box<dyn Error>> {
    validate_date(as_of)?;
    let generated = generated_ids();
    let snapshot: GeneratedSnapshot = serde_json::from_str(GENERATED_SNAPSHOT)?;
    let catalogue_lock: GeneratedSnapshot = serde_json::from_str(CATALOGUE_LOCK)?;
    let supplemental: SupplementalCatalogue = serde_json::from_str(SUPPLEMENTAL)?;
    let migrations: MigrationRegistry = serde_json::from_str(MIGRATIONS)?;
    let exemptions: ExemptionRegistry = serde_json::from_str(EXEMPTIONS)?;
    for version in [
        snapshot.schema_version,
        catalogue_lock.schema_version,
        supplemental.schema_version,
        migrations.schema_version,
        exemptions.schema_version,
    ] {
        if version != 1 {
            return Err(format!("unsupported catalogue registry schema {version}").into());
        }
    }
    let snapshot_ids = unique(snapshot.ids, "generated catalogue snapshot")?;
    let supplemental_ids = unique(
        supplemental
            .entries
            .iter()
            .map(|entry| {
                if entry.category.trim().is_empty() || entry.description.trim().is_empty() {
                    return Err(format!("supplemental entry {} lacks metadata", entry.id));
                }
                Ok(entry.id.clone())
            })
            .collect::<Result<Vec<_>, _>>()?,
        "supplemental catalogue",
    )?;
    if let Some(duplicate) = generated.intersection(&supplemental_ids).next() {
        return Err(format!("catalogue ID {duplicate} is both generated and supplemental").into());
    }
    let all = generated.union(&supplemental_ids).cloned().collect();
    let locked_ids = unique(catalogue_lock.ids, "catalogue lock")?;
    if !snapshot_ids.is_subset(&locked_ids) {
        return Err("generated snapshot contains IDs absent from the catalogue lock".into());
    }
    validate_migrations(&locked_ids, &all, &migrations.migrations)?;
    validate_exemptions(&all, &exemptions.exemptions, as_of)?;
    Ok(Authority {
        generated,
        supplemental: supplemental_ids,
        all,
        exemptions: exemptions.exemptions,
    })
}

fn unique(values: Vec<String>, label: &str) -> Result<BTreeSet<String>, Box<dyn Error>> {
    let mut unique = BTreeSet::new();
    for value in values {
        if value.trim().is_empty() || !unique.insert(value.clone()) {
            return Err(format!("{label} contains an empty or duplicate ID: {value}").into());
        }
    }
    Ok(unique)
}

fn validate_migrations(
    previous: &BTreeSet<String>,
    current: &BTreeSet<String>,
    migrations: &[Migration],
) -> Result<(), Box<dyn Error>> {
    let mut migration_ids = BTreeSet::new();
    let mut migrated_from = BTreeSet::new();
    let mut migrated_to = BTreeSet::new();
    for migration in migrations {
        if !migration_ids.insert(&migration.id)
            || migration.reason.trim().is_empty()
            || migration.review.trim().is_empty()
        {
            return Err(format!("invalid or duplicate coverage migration {}", migration.id).into());
        }
        let cardinality_ok = match migration.kind {
            MigrationKind::Rename => migration.from.len() == 1 && migration.to.len() == 1,
            MigrationKind::Split => migration.from.len() == 1 && migration.to.len() > 1,
            MigrationKind::Merge => migration.from.len() > 1 && migration.to.len() == 1,
            MigrationKind::Retire => !migration.from.is_empty() && migration.to.is_empty(),
        };
        if !cardinality_ok {
            return Err(format!(
                "coverage migration {} has invalid cardinality",
                migration.id
            )
            .into());
        }
        for source in &migration.from {
            if !previous.contains(source) || !migrated_from.insert(source.clone()) {
                return Err(format!(
                    "coverage migration {} has unknown or duplicate source {source}",
                    migration.id
                )
                .into());
            }
        }
        for destination in &migration.to {
            if !current.contains(destination) || !migrated_to.insert(destination.clone()) {
                return Err(format!(
                    "coverage migration {} has unknown or duplicate destination {destination}",
                    migration.id
                )
                .into());
            }
        }
    }
    let removed: BTreeSet<_> = previous.difference(current).cloned().collect();
    let unmigrated: Vec<_> = removed.difference(&migrated_from).cloned().collect();
    if !unmigrated.is_empty() {
        return Err(format!("unmigrated coverage IDs: {}", unmigrated.join(", ")).into());
    }
    let stale: Vec<_> = migrated_from.difference(&removed).cloned().collect();
    if !stale.is_empty() {
        return Err(format!("migration sources remain current: {}", stale.join(", ")).into());
    }
    Ok(())
}

fn validate_exemptions(
    catalogue: &BTreeSet<String>,
    exemptions: &[Exemption],
    as_of: &str,
) -> Result<(), Box<dyn Error>> {
    let mut ids = BTreeSet::new();
    for exemption in exemptions {
        validate_date(&exemption.expires_on)?;
        if !catalogue.contains(&exemption.id) {
            return Err(format!("exemption has unknown coverage ID {}", exemption.id).into());
        }
        if !ids.insert(&exemption.id) {
            return Err(format!("duplicate exemption for {}", exemption.id).into());
        }
        if exemption.expires_on.as_str() < as_of {
            return Err(format!("expired exemption for {}", exemption.id).into());
        }
        if exemption.reason.trim().is_empty()
            || exemption.postgres_versions.is_empty()
            || exemption
                .postgres_versions
                .iter()
                .any(|scope| scope.trim().is_empty())
            || exemption.owner.trim().is_empty()
            || exemption.reviewed_by.trim().is_empty()
            || exemption.review.trim().is_empty()
        {
            return Err(format!(
                "exemption for {} lacks required review metadata",
                exemption.id
            )
            .into());
        }
        if exemption
            .scripted_coverage
            .as_ref()
            .is_some_and(|value| !catalogue.contains(value))
        {
            return Err(format!(
                "exemption for {} names unknown scripted coverage",
                exemption.id
            )
            .into());
        }
    }
    Ok(())
}

fn validate_date(value: &str) -> Result<(), Box<dyn Error>> {
    let parts: Vec<_> = value.split('-').collect();
    let structure_valid = parts.len() == 3
        && parts[0].len() == 4
        && parts[1].len() == 2
        && parts[2].len() == 2
        && parts
            .iter()
            .all(|part| part.bytes().all(|byte| byte.is_ascii_digit()));
    let valid = structure_valid
        && parts[0].parse::<u16>().is_ok_and(|year| {
            parts[1].parse::<u8>().is_ok_and(|month| {
                parts[2].parse::<u8>().is_ok_and(|day| {
                    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
                    let maximum = match month {
                        2 if leap => 29,
                        2 => 28,
                        4 | 6 | 9 | 11 => 30,
                        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
                        _ => 0,
                    };
                    (1..=maximum).contains(&day)
                })
            })
        });
    if valid {
        Ok(())
    } else {
        Err(format!("invalid ISO date: {value}").into())
    }
}

fn option_values<'a>(arguments: &'a [String], name: &str) -> Result<Vec<&'a str>, Box<dyn Error>> {
    let mut values = Vec::new();
    for (index, argument) in arguments.iter().enumerate() {
        if argument == name {
            values.push(
                arguments
                    .get(index + 1)
                    .map(String::as_str)
                    .ok_or_else(|| format!("missing value for {name}"))?,
            );
        }
    }
    Ok(values)
}

fn add_evidence(
    catalogue: &BTreeSet<String>,
    dispositions: &mut BTreeMap<String, Disposition>,
    coverage: &EvidenceCoverage,
    source: &str,
) -> Result<(), Box<dyn Error>> {
    if !coverage.exempted.is_empty() {
        return Err(
            "artifact exemptions are not authoritative; use the reviewed exemption registry".into(),
        );
    }
    for (kind, ids) in [
        (DispositionKind::RealPostgres, &coverage.real_postgres),
        (DispositionKind::Scripted, &coverage.scripted),
        (DispositionKind::Indirect, &coverage.indirect),
    ] {
        for id in ids {
            insert_disposition(catalogue, dispositions, id, kind, source.to_owned())?;
        }
    }
    Ok(())
}

fn insert_disposition(
    catalogue: &BTreeSet<String>,
    dispositions: &mut BTreeMap<String, Disposition>,
    id: &str,
    kind: DispositionKind,
    evidence: String,
) -> Result<(), Box<dyn Error>> {
    if !catalogue.contains(id) {
        return Err(format!("unknown coverage ID: {id}").into());
    }
    if dispositions.contains_key(id) {
        return Err(format!("duplicate coverage disposition: {id}").into());
    }
    dispositions.insert(
        id.to_owned(),
        Disposition {
            id: id.to_owned(),
            kind,
            evidence,
        },
    );
    Ok(())
}

#[cfg(test)]
/// Tests for catalogue closure and migration validation.
mod tests {
    use super::*;

    fn set(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    fn migration(kind: MigrationKind, from: &[&str], to: &[&str]) -> Migration {
        Migration {
            id: "migration-1".into(),
            kind,
            from: from.iter().map(|value| (*value).into()).collect(),
            to: to.iter().map(|value| (*value).into()).collect(),
            reason: "reviewed change".into(),
            review: "ADR-1".into(),
        }
    }

    #[test]
    fn removed_generated_id_requires_a_migration() {
        let error = validate_migrations(&set(&["old"]), &set(&["new"]), &[])
            .unwrap_err()
            .to_string();
        assert!(error.contains("unmigrated coverage IDs: old"));
        validate_migrations(
            &set(&["old"]),
            &set(&["new"]),
            &[migration(MigrationKind::Rename, &["old"], &["new"])],
        )
        .unwrap();
    }

    #[test]
    fn dangling_destinations_and_current_sources_make_migrations_invalid() {
        let dangling = validate_migrations(
            &set(&["old"]),
            &set(&["new"]),
            &[migration(MigrationKind::Rename, &["old"], &["missing"])],
        )
        .unwrap_err()
        .to_string();
        assert!(dangling.contains("unknown or duplicate destination missing"));

        let cycle_like = validate_migrations(
            &set(&["first", "second"]),
            &set(&["first", "second"]),
            &[
                migration(MigrationKind::Rename, &["first"], &["second"]),
                Migration {
                    id: "migration-2".into(),
                    ..migration(MigrationKind::Rename, &["second"], &["first"])
                },
            ],
        )
        .unwrap_err()
        .to_string();
        assert!(cycle_like.contains("migration sources remain current"));
    }

    #[test]
    fn expired_exemptions_fail_and_reviewed_current_exemptions_pass() {
        let catalogue = set(&["entry", "scripted-substitute"]);
        let exemption = |expires_on: &str| Exemption {
            id: "entry".into(),
            reason: "driver cannot emit it".into(),
            postgres_versions: vec!["14-18".into()],
            scripted_coverage: Some("scripted-substitute".into()),
            owner: "protocol-team".into(),
            reviewed_by: "reviewer".into(),
            review: "ADR-2".into(),
            expires_on: expires_on.into(),
        };
        assert!(
            validate_exemptions(&catalogue, &[exemption("2026-08-15")], "2026-08-16")
                .unwrap_err()
                .to_string()
                .contains("expired exemption")
        );
        validate_exemptions(&catalogue, &[exemption("2026-09-01")], "2026-08-16").unwrap();
    }

    #[test]
    fn complete_union_has_exactly_one_disposition_per_entry() {
        let authority = load_authority("2026-08-16").unwrap();
        let catalogue = authority.all;
        let mut dispositions = BTreeMap::new();
        for id in &catalogue {
            insert_disposition(
                &catalogue,
                &mut dispositions,
                id,
                DispositionKind::Indirect,
                "complete.json".into(),
            )
            .unwrap();
        }
        assert_eq!(dispositions.len(), catalogue.len());
    }

    #[test]
    fn newly_added_generated_or_supplemental_id_becomes_missing() {
        let mut catalogue = set(&["existing"]);
        let mut dispositions = BTreeMap::new();
        insert_disposition(
            &catalogue,
            &mut dispositions,
            "existing",
            DispositionKind::Indirect,
            "existing evidence".into(),
        )
        .unwrap();
        assert!(missing_ids(&catalogue, &dispositions).is_empty());

        catalogue.insert("generated.new-transition".into());
        assert_eq!(
            missing_ids(&catalogue, &dispositions),
            ["generated.new-transition"]
        );

        catalogue.remove("generated.new-transition");
        catalogue.insert("supplemental.new-case".into());
        assert_eq!(
            missing_ids(&catalogue, &dispositions),
            ["supplemental.new-case"]
        );
    }

    #[test]
    fn approved_registry_does_not_silently_dispose_protocol_growth() {
        let mut authority = load_authority("2026-08-17").unwrap();
        authority
            .generated
            .insert("backend.NewState.NewEvent".into());
        authority.all.insert("backend.NewState.NewEvent".into());
        authority
            .supplemental
            .insert("supplemental.new-case".into());
        authority.all.insert("supplemental.new-case".into());

        let mut dispositions = BTreeMap::new();
        add_reviewed_dispositions(&authority, &mut dispositions).unwrap();

        assert_eq!(
            missing_ids(&authority.all, &dispositions),
            ["backend.NewState.NewEvent", "supplemental.new-case"]
        );
    }
}
