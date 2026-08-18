//! Command-line parsing, help text, and argument validation.

use std::{error::Error, path::PathBuf};

use clap::{Args, Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "pg-proto-burn-in",
    about = "Exercise pg-proto against real and scripted PostgreSQL protocol peers",
    version
)]
pub(crate) struct Cli {
    /// Run every conventional burn-in permutation and generate REPORT.md.
    #[arg(long)]
    run_all: bool,
    /// Wall-clock duration of the soak phase performed by --run-all.
    #[arg(long, requires = "run_all")]
    soak_duration_seconds: Option<u64>,
    /// Root directory for all artifacts produced by --run-all.
    #[arg(long = "output-dir", requires = "run_all")]
    run_all_output_dir: Option<PathBuf>,
    /// Burn-in operation to perform.
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run a protocol conformance profile.
    Conformance(ConformanceArgs),
    /// Run a bounded, deterministic soak workload.
    Soak(SoakArgs),
    /// Replay a previously recorded soak schedule.
    Replay(ReplayArgs),
    /// Audit evidence against the authoritative protocol catalogue.
    Catalogue(CatalogueArgs),
    /// Capture or evaluate controlled performance evidence.
    Performance(PerformanceArgs),
    /// Run isolated PostgreSQL fault-injection scenarios.
    Faults(OutputArgs),
    /// Build REPORT.md from conventional burn-in run directories.
    MakeReport(MakeReportArgs),
    /// Chart controlled throughput across historical report roots.
    Trends(TrendsArgs),
    /// Internal soak workload driver.
    #[command(hide = true)]
    SoakDriverChild(SoakDriverArgs),
    /// Internal resource checkpoint driver.
    #[command(hide = true)]
    ResourceDriverChild(AddressArgs),
    /// Internal process held open for abrupt-termination checks.
    #[command(hide = true)]
    ResourceHoldChild(AddressArgs),
    /// Internal public-facade intermediary process.
    #[command(hide = true)]
    IntermediaryChild(IntermediaryArgs),
    /// Internal SQL client process.
    #[command(hide = true)]
    DriverChild(DriverArgs),
}

#[derive(Debug, Args)]
struct ConformanceArgs {
    /// Conformance profile: smoke, authentication, replication, rewrites, or scripted.
    #[arg(long)]
    profile: String,
    /// PostgreSQL major version used by the smoke profile (14 through 18).
    #[arg(long, default_value = "18")]
    postgres_version: String,
    /// Directory in which this run writes its evidence artifacts.
    #[arg(long)]
    output_dir: PathBuf,
}

#[derive(Debug, Args)]
#[command(group(
    clap::ArgGroup::new("budget")
        .required(true)
        .multiple(false)
        .args(["iterations", "duration_seconds"])
))]
struct SoakArgs {
    /// Seed used to generate the deterministic workload schedule.
    #[arg(long)]
    seed: u64,
    /// Number of weighted operations to add to each workload phase.
    #[arg(long)]
    iterations: Option<u64>,
    /// Wall-clock duration for which the workload should run.
    #[arg(long)]
    duration_seconds: Option<u64>,
    /// Existing JSON schedule to execute instead of generating one.
    #[arg(long)]
    schedule: Option<PathBuf>,
    /// Retain bounded, redacted diagnostic payloads in failure evidence.
    #[arg(long)]
    capture_payloads: bool,
    /// Directory in which this run writes its evidence artifacts.
    #[arg(long)]
    output_dir: PathBuf,
}

#[derive(Debug, Args)]
struct ReplayArgs {
    /// Recorded soak result JSON whose exact schedule should be replayed.
    #[arg(long)]
    input: PathBuf,
    /// Attempt to reduce a reproduced failure to its shortest tested prefix.
    #[arg(long)]
    reduce: bool,
    /// Directory in which this run writes its evidence artifacts.
    #[arg(long)]
    output_dir: PathBuf,
}

#[derive(Debug, Args)]
struct CatalogueArgs {
    /// Date used to validate time-bounded exemptions, in YYYY-MM-DD form.
    #[arg(long)]
    as_of: String,
    /// Apply the checked-in, reviewed disposition registry.
    #[arg(long)]
    approved: bool,
    /// Evidence artifact to merge; may be supplied more than once.
    #[arg(long)]
    input: Vec<PathBuf>,
    /// Directory in which this run writes its evidence artifacts.
    #[arg(long)]
    output_dir: PathBuf,
}

#[derive(Debug, Args)]
struct PerformanceArgs {
    /// Stable runner identity used to key performance baselines.
    #[arg(long)]
    runner: Option<String>,
    /// Enforce promoted baseline thresholds instead of reporting advisory evidence.
    #[arg(long)]
    enforce: bool,
    /// Assert that the current Linux host is a stable performance runner.
    #[arg(long)]
    stable_runner: bool,
    /// PostgreSQL major version recorded in the performance baseline key.
    #[arg(long, default_value = "18")]
    postgres_version: String,
    /// Build mode: optimized or allocator-diagnostic.
    #[arg(long, default_value = "optimized")]
    build_mode: String,
    /// Existing measurement JSON to evaluate instead of capturing a workload.
    #[arg(long, conflicts_with_all = ["profile", "seed", "duration_seconds"])]
    input: Option<PathBuf>,
    /// Capture profile: controlled, scheduled-soak, overnight, or diagnostic.
    #[arg(long, required_unless_present = "input")]
    profile: Option<String>,
    /// Seed used by a captured performance workload.
    #[arg(long, required_unless_present = "input")]
    seed: Option<u64>,
    /// Wall-clock duration of a captured performance workload.
    #[arg(long, required_unless_present = "input")]
    duration_seconds: Option<u64>,
    /// Promoted baseline JSON against which measurements are compared.
    #[arg(long)]
    baseline: Option<PathBuf>,
    /// Directory in which this run writes its evidence artifacts.
    #[arg(long)]
    output_dir: PathBuf,
}

#[derive(Debug, Args)]
struct OutputArgs {
    /// Directory in which this run writes its evidence artifacts.
    #[arg(long)]
    output_dir: PathBuf,
}

#[derive(Debug, Args)]
struct MakeReportArgs {
    /// Directory containing the conventional burn-in run subdirectories.
    #[arg(long)]
    dir: PathBuf,
}

#[derive(Debug, Args)]
struct TrendsArgs {
    /// Directory containing at least two conventionally named report roots.
    #[arg(long)]
    dir: PathBuf,
}

#[derive(Debug, Args)]
struct AddressArgs {
    /// Socket address of the internal process to connect to.
    #[arg(long)]
    address: String,
}

#[derive(Debug, Args)]
struct SoakDriverArgs {
    /// Socket address of the intermediary process.
    #[arg(long)]
    address: String,
    /// JSON-encoded deterministic workload sequence.
    #[arg(long)]
    sequence: String,
    /// Delay after each operation, in milliseconds, for wall-clock soak budgets.
    #[arg(long)]
    pace_millis: Option<u64>,
}

#[derive(Debug, Args)]
struct IntermediaryArgs {
    /// Socket address of the upstream PostgreSQL server.
    #[arg(long)]
    address: String,
    /// Number of client connections to accept before graceful teardown.
    #[arg(long, default_value_t = 1)]
    connections: usize,
    /// Permit clients used by fault scenarios to disconnect abruptly.
    #[arg(long)]
    allow_abrupt_disconnects: bool,
    /// Enable non-identity reconstruction of rich protocol messages.
    #[arg(long)]
    rich_rewrites: bool,
    /// Password used to authenticate the upstream connection.
    #[arg(long)]
    password: Option<String>,
    /// DER certificate used to authenticate the upstream TLS endpoint.
    #[arg(long)]
    tls_root: Option<PathBuf>,
}

#[derive(Debug, Args)]
struct DriverArgs {
    /// Socket address of the intermediary process.
    #[arg(long)]
    address: String,
    /// Password used by the test client.
    #[arg(long)]
    password: Option<String>,
    /// Exercise non-identity reconstruction of rich protocol messages.
    #[arg(long)]
    rich_rewrites: bool,
    /// Run only the minimal scalar validation scenario.
    #[arg(long)]
    basic: bool,
    /// Direct PostgreSQL socket used to trigger asynchronous notifications.
    #[arg(long)]
    notify_address: Option<String>,
}

impl Cli {
    pub(crate) fn parse(arguments: Vec<String>) -> Result<Option<Vec<String>>, Box<dyn Error>> {
        let executable = arguments
            .first()
            .cloned()
            .unwrap_or_else(|| "pg-proto-burn-in".into());
        let cli = match Self::try_parse_from(arguments) {
            Ok(cli) => cli,
            Err(error) if error.use_stderr() => return Err(error.into()),
            Err(error) => {
                error.print()?;
                return Ok(None);
            }
        };
        match (cli.run_all, cli.command) {
            (true, None) => {
                let Some(duration) = cli.soak_duration_seconds else {
                    return Err(
                        "--run-all requires --soak-duration-seconds and --output-dir".into(),
                    );
                };
                let Some(output_dir) = cli.run_all_output_dir else {
                    return Err(
                        "--run-all requires --soak-duration-seconds and --output-dir".into(),
                    );
                };
                Ok(Some(vec![
                    executable,
                    "run-all".into(),
                    "--soak-duration-seconds".into(),
                    duration.to_string(),
                    "--output-dir".into(),
                    output_dir.to_string_lossy().into_owned(),
                ]))
            }
            (false, Some(command)) => Ok(Some(command.into_arguments(executable))),
            (true, Some(_)) => Err("--run-all cannot be combined with a subcommand".into()),
            (false, None) => Err("a subcommand or --run-all is required; use --help".into()),
        }
    }
}

impl Command {
    fn into_arguments(self, executable: String) -> Vec<String> {
        let mut output = vec![executable];
        match self {
            Self::Conformance(args) => {
                push(&mut output, "conformance");
                pair(&mut output, "--profile", args.profile);
                pair(&mut output, "--postgres-version", args.postgres_version);
                path_pair(&mut output, "--output-dir", args.output_dir);
            }
            Self::Soak(args) => {
                push(&mut output, "soak");
                pair(&mut output, "--seed", args.seed.to_string());
                optional_pair(
                    &mut output,
                    "--iterations",
                    args.iterations.map(|v| v.to_string()),
                );
                optional_pair(
                    &mut output,
                    "--duration-seconds",
                    args.duration_seconds.map(|v| v.to_string()),
                );
                optional_path_pair(&mut output, "--schedule", args.schedule);
                flag(&mut output, "--capture-payloads", args.capture_payloads);
                path_pair(&mut output, "--output-dir", args.output_dir);
            }
            Self::Replay(args) => {
                push(&mut output, "replay");
                path_pair(&mut output, "--input", args.input);
                flag(&mut output, "--reduce", args.reduce);
                path_pair(&mut output, "--output-dir", args.output_dir);
            }
            Self::Catalogue(args) => {
                push(&mut output, "catalogue");
                pair(&mut output, "--as-of", args.as_of);
                flag(&mut output, "--approved", args.approved);
                for input in args.input {
                    path_pair(&mut output, "--input", input);
                }
                path_pair(&mut output, "--output-dir", args.output_dir);
            }
            Self::Performance(args) => {
                push(&mut output, "performance");
                optional_pair(&mut output, "--runner", args.runner);
                flag(&mut output, "--enforce", args.enforce);
                flag(&mut output, "--stable-runner", args.stable_runner);
                pair(&mut output, "--postgres-version", args.postgres_version);
                pair(&mut output, "--build-mode", args.build_mode);
                optional_path_pair(&mut output, "--input", args.input);
                optional_pair(&mut output, "--profile", args.profile);
                optional_pair(&mut output, "--seed", args.seed.map(|v| v.to_string()));
                optional_pair(
                    &mut output,
                    "--duration-seconds",
                    args.duration_seconds.map(|v| v.to_string()),
                );
                optional_path_pair(&mut output, "--baseline", args.baseline);
                path_pair(&mut output, "--output-dir", args.output_dir);
            }
            Self::Faults(args) => {
                push(&mut output, "faults");
                path_pair(&mut output, "--output-dir", args.output_dir);
            }
            Self::MakeReport(args) => {
                push(&mut output, "make-report");
                path_pair(&mut output, "--dir", args.dir);
            }
            Self::Trends(args) => {
                push(&mut output, "trends");
                path_pair(&mut output, "--dir", args.dir);
            }
            Self::SoakDriverChild(args) => {
                push(&mut output, "soak-driver-child");
                pair(&mut output, "--address", args.address);
                pair(&mut output, "--sequence", args.sequence);
                optional_pair(
                    &mut output,
                    "--pace-millis",
                    args.pace_millis.map(|value| value.to_string()),
                );
            }
            Self::ResourceDriverChild(args) => address(&mut output, "resource-driver-child", args),
            Self::ResourceHoldChild(args) => address(&mut output, "resource-hold-child", args),
            Self::IntermediaryChild(args) => {
                push(&mut output, "intermediary-child");
                pair(&mut output, "--address", args.address);
                pair(&mut output, "--connections", args.connections.to_string());
                flag(
                    &mut output,
                    "--allow-abrupt-disconnects",
                    args.allow_abrupt_disconnects,
                );
                flag(&mut output, "--rich-rewrites", args.rich_rewrites);
                optional_pair(&mut output, "--password", args.password);
                optional_path_pair(&mut output, "--tls-root", args.tls_root);
            }
            Self::DriverChild(args) => {
                push(&mut output, "driver-child");
                pair(&mut output, "--address", args.address);
                optional_pair(&mut output, "--password", args.password);
                flag(&mut output, "--rich-rewrites", args.rich_rewrites);
                flag(&mut output, "--basic", args.basic);
                optional_pair(&mut output, "--notify-address", args.notify_address);
            }
        }
        output
    }
}

fn address(output: &mut Vec<String>, command: &str, args: AddressArgs) {
    push(output, command);
    pair(output, "--address", args.address);
}

fn push(output: &mut Vec<String>, value: impl Into<String>) {
    output.push(value.into());
}

fn pair(output: &mut Vec<String>, name: &str, value: String) {
    push(output, name);
    push(output, value);
}

fn path_pair(output: &mut Vec<String>, name: &str, value: PathBuf) {
    pair(output, name, value.to_string_lossy().into_owned());
}

fn optional_pair(output: &mut Vec<String>, name: &str, value: Option<String>) {
    if let Some(value) = value {
        pair(output, name, value);
    }
}

fn optional_path_pair(output: &mut Vec<String>, name: &str, value: Option<PathBuf>) {
    if let Some(value) = value {
        path_pair(output, name, value);
    }
}

fn flag(output: &mut Vec<String>, name: &str, enabled: bool) {
    if enabled {
        push(output, name);
    }
}
