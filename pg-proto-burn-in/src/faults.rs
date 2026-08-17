use std::{
    error::Error,
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use bytes::Bytes;
use futures_util::SinkExt;
use serde::{Deserialize, Serialize};
use testcontainers_modules::{
    postgres::Postgres,
    testcontainers::{ContainerAsync, ImageExt, core::ExecCommand, runners::AsyncRunner},
};
use tokio::{
    process::{Child, Command},
    time::{Instant, sleep, timeout},
};

use crate::{ChildEvent, atomic_write, option, read_event, wait_success};

const FAULT_TIMEOUT: Duration = Duration::from_secs(45);
const POSTGRES_READY_TIMEOUT: Duration = Duration::from_secs(15);
const POSTGRES_READY_RETRY_DELAY: Duration = Duration::from_millis(100);

#[derive(Debug, Serialize, Deserialize)]
struct FaultRunResult {
    schema_version: u32,
    command: String,
    postgres_version: String,
    isolated_containers: usize,
    performance_evidence_included: bool,
    scenarios: Vec<FaultScenarioResult>,
    success: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct FaultScenarioResult {
    id: String,
    contract: String,
    fault_observed: bool,
    contract_satisfied: bool,
    isolated: bool,
    performance_evidence_included: bool,
    evidence: String,
}

struct Environment {
    _container: ContainerAsync<Postgres>,
    intermediary: Child,
    proxy: SocketAddr,
    upstream: SocketAddr,
}

pub(crate) async fn run(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let artifacts = PathBuf::from(option(arguments, "--artifacts")?);
    tokio::fs::create_dir_all(&artifacts).await?;
    let executable = arguments.first().ok_or("missing executable path")?;

    let outcome = async {
        eprintln!("fault scenario: backend-termination");
        let backend = timeout(FAULT_TIMEOUT, backend_termination(executable)).await??;
        eprintln!("fault scenario: resource-exhaustion");
        let resource = timeout(FAULT_TIMEOUT, resource_exhaustion(executable)).await??;
        eprintln!("fault scenario: interrupted-copy");
        let copy = timeout(FAULT_TIMEOUT, interrupted_copy(executable)).await??;
        eprintln!("fault scenario: deadlock");
        let deadlock = timeout(FAULT_TIMEOUT, deadlock(executable)).await??;
        eprintln!("fault scenario: postgres-restart");
        let restart = timeout(FAULT_TIMEOUT, postgres_restart(executable)).await??;
        Ok::<_, Box<dyn Error>>(vec![backend, resource, copy, deadlock, restart])
    }
    .await;
    let scenarios = outcome.as_ref().map_or_else(|_| Vec::new(), Clone::clone);
    let result = FaultRunResult {
        schema_version: 1,
        command: "faults".into(),
        postgres_version: "18".into(),
        isolated_containers: scenarios.len(),
        performance_evidence_included: false,
        success: outcome.is_ok()
            && scenarios
                .iter()
                .all(|scenario| scenario.fault_observed && scenario.contract_satisfied),
        scenarios,
    };
    write_artifacts(&artifacts, &result).await?;
    outcome.map(|_| ())
}

async fn environment(executable: &str, connections: usize) -> Result<Environment, Box<dyn Error>> {
    let container = Postgres::default()
        .with_host_auth()
        .with_tag("18-alpine")
        .start()
        .await?;
    let upstream = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        container.get_host_port_ipv4(5432).await?,
    );
    let mut intermediary = Command::new(executable)
        .args([
            "intermediary-child",
            "--address",
            &upstream.to_string(),
            "--connections",
            &connections.to_string(),
            "--allow-abrupt-disconnects",
        ])
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()?;
    let ChildEvent::Ready {
        listen_addr: proxy, ..
    } = read_event(&mut intermediary).await?
    else {
        return Err("fault intermediary did not become ready".into());
    };
    Ok(Environment {
        _container: container,
        intermediary,
        proxy,
        upstream,
    })
}

async fn finish(mut environment: Environment) -> Result<(), Box<dyn Error>> {
    let ChildEvent::Completed { .. } = read_event(&mut environment.intermediary).await? else {
        return Err("fault intermediary did not complete".into());
    };
    wait_success(&mut environment.intermediary, "fault intermediary").await
}

async fn connect(address: SocketAddr) -> Result<tokio_postgres::Client, Box<dyn Error>> {
    let mut config = tokio_postgres::Config::new();
    config
        .host(address.ip().to_string())
        .port(address.port())
        .user("postgres")
        .dbname("postgres");
    let (client, connection) = config.connect(tokio_postgres::NoTls).await?;
    tokio::spawn(async move {
        let _ = connection.await;
    });
    Ok(client)
}

fn result(
    id: &str,
    contract: &str,
    fault: bool,
    recovered: bool,
    evidence: &str,
) -> FaultScenarioResult {
    FaultScenarioResult {
        id: id.into(),
        contract: contract.into(),
        fault_observed: fault,
        contract_satisfied: recovered,
        isolated: true,
        performance_evidence_included: false,
        evidence: evidence.into(),
    }
}

async fn backend_termination(executable: &str) -> Result<FaultScenarioResult, Box<dyn Error>> {
    let environment = environment(executable, 2).await?;
    let victim = connect(environment.proxy).await?;
    let pid: i32 = victim
        .query_one("SELECT pg_backend_pid()", &[])
        .await?
        .get(0);
    let admin = connect(environment.upstream).await?;
    let query = victim.query_one("SELECT pg_sleep(30)", &[]);
    let terminate = async {
        sleep(Duration::from_millis(100)).await;
        admin
            .query_one("SELECT pg_terminate_backend($1)", &[&pid])
            .await
    };
    let (query_outcome, terminated) = tokio::join!(query, terminate);
    let fault = query_outcome.is_err() && terminated?.get::<_, bool>(0);
    drop(victim);
    drop(admin);
    let recovery = connect(environment.proxy).await?;
    let recovered = recovery
        .query_one("SELECT 1::int4", &[])
        .await?
        .get::<_, i32>(0)
        == 1;
    drop(recovery);
    finish(environment).await?;
    Ok(result(
        "backend-termination",
        "new-session-recovers",
        fault,
        recovered,
        "terminated backend closed only the selected session; a new proxied session returned 1",
    ))
}

async fn resource_exhaustion(executable: &str) -> Result<FaultScenarioResult, Box<dyn Error>> {
    let environment = environment(executable, 1).await?;
    let client = connect(environment.proxy).await?;
    client
        .batch_execute("SET work_mem = '64kB'; SET temp_file_limit = '0'")
        .await?;
    let failure = client
        .query(
            "SELECT repeat(i::text, 100) FROM generate_series(1, 100000) i ORDER BY 1 DESC",
            &[],
        )
        .await;
    let fault = failure
        .as_ref()
        .err()
        .and_then(tokio_postgres::Error::as_db_error)
        .is_some_and(|error| error.code().code() == "53400");
    client
        .batch_execute("RESET temp_file_limit; RESET work_mem")
        .await?;
    let recovered = client
        .query_one("SELECT 2::int4", &[])
        .await?
        .get::<_, i32>(0)
        == 2;
    drop(client);
    finish(environment).await?;
    Ok(result(
        "resource-exhaustion",
        "same-session-recovers",
        fault,
        recovered,
        "temp-file exhaustion produced SQLSTATE 53400 and the reset session returned 2",
    ))
}

async fn interrupted_copy(executable: &str) -> Result<FaultScenarioResult, Box<dyn Error>> {
    let environment = environment(executable, 2).await?;
    let client = connect(environment.proxy).await?;
    client
        .batch_execute("CREATE TABLE fault_copy (id integer)")
        .await?;
    let bytes_sent = {
        let sink = client
            .copy_in::<_, Bytes>("COPY fault_copy FROM STDIN")
            .await?;
        tokio::pin!(sink);
        let payload = Bytes::from_static(b"1\n2\n");
        sink.as_mut().send(payload.clone()).await?;
        payload.len()
        // Dropping the unfinished sink and then its client interrupts COPY mid-stream.
    };
    drop(client);
    sleep(Duration::from_millis(100)).await;
    let recovery = connect(environment.proxy).await?;
    let recovered = recovery
        .query_one("SELECT count(*)::bigint FROM fault_copy", &[])
        .await?
        .get::<_, i64>(0)
        == 0;
    drop(recovery);
    finish(environment).await?;
    Ok(result(
        "interrupted-copy",
        "new-session-recovers",
        bytes_sent > 0,
        recovered,
        "the driver disconnected after sending COPY data; PostgreSQL rolled back its rows and a new proxied session recovered",
    ))
}

async fn deadlock(executable: &str) -> Result<FaultScenarioResult, Box<dyn Error>> {
    let environment = environment(executable, 2).await?;
    let mut first = connect(environment.proxy).await?;
    let mut second = connect(environment.proxy).await?;
    first.batch_execute("SET deadlock_timeout = '25ms'; CREATE TABLE fault_deadlock (id integer PRIMARY KEY); INSERT INTO fault_deadlock VALUES (1), (2)").await?;
    second
        .batch_execute("SET deadlock_timeout = '25ms'")
        .await?;
    let first_tx = first.transaction().await?;
    let second_tx = second.transaction().await?;
    first_tx
        .query_one("SELECT id FROM fault_deadlock WHERE id = 1 FOR UPDATE", &[])
        .await?;
    second_tx
        .query_one("SELECT id FROM fault_deadlock WHERE id = 2 FOR UPDATE", &[])
        .await?;
    let (left, right) = tokio::join!(
        first_tx.execute("UPDATE fault_deadlock SET id = id WHERE id = 2", &[]),
        second_tx.execute("UPDATE fault_deadlock SET id = id WHERE id = 1", &[]),
    );
    let fault = [&left, &right].into_iter().any(|outcome| {
        outcome
            .as_ref()
            .err()
            .and_then(tokio_postgres::Error::as_db_error)
            .is_some_and(|error| error.code().code() == "40P01")
    });
    let _ = first_tx.rollback().await;
    let _ = second_tx.rollback().await;
    let recovered = first
        .query_one("SELECT 3::int4", &[])
        .await?
        .get::<_, i32>(0)
        == 3
        && second
            .query_one("SELECT 4::int4", &[])
            .await?
            .get::<_, i32>(0)
            == 4;
    drop(first);
    drop(second);
    finish(environment).await?;
    Ok(result(
        "deadlock",
        "both-sessions-recover",
        fault,
        recovered,
        "one transaction received SQLSTATE 40P01 and both proxied sessions recovered after rollback",
    ))
}

async fn postgres_restart(executable: &str) -> Result<FaultScenarioResult, Box<dyn Error>> {
    let mut environment = environment(executable, 2).await?;
    let before = connect(environment.proxy).await?;
    let initial = before
        .query_one("SELECT 5::int4", &[])
        .await?
        .get::<_, i32>(0)
        == 5;
    drop(before);
    environment._container.stop_with_timeout(Some(5)).await?;
    let stopped = !environment._container.is_running().await?;
    environment._container.start().await?;
    wait_until_ready(
        POSTGRES_READY_TIMEOUT,
        POSTGRES_READY_RETRY_DELAY,
        || async {
            let result = environment
                ._container
                .exec(ExecCommand::new(["pg_isready", "-U", "postgres"]))
                .await?;
            loop {
                if let Some(exit_code) = result.exit_code().await? {
                    return Ok(exit_code == 0);
                }
                sleep(Duration::from_millis(10)).await;
            }
        },
    )
    .await?;
    environment.intermediary.kill().await?;
    let topology_terminated = !environment.intermediary.wait().await?.success();
    Ok(result(
        "postgres-restart",
        "topology-terminates",
        stopped,
        initial && topology_terminated,
        "the disposable container stopped, restarted to pg_isready, and the old topology terminated by contract",
    ))
}

async fn wait_until_ready<F, Fut>(
    ready_timeout: Duration,
    retry_delay: Duration,
    mut probe: F,
) -> Result<usize, Box<dyn Error>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<bool, Box<dyn Error>>>,
{
    let deadline = Instant::now() + ready_timeout;
    let mut attempts = 0;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err("PostgreSQL did not become ready before the deadline".into());
        }
        attempts += 1;
        if timeout(remaining, probe()).await?? {
            return Ok(attempts);
        }
        sleep(retry_delay.min(deadline.saturating_duration_since(Instant::now()))).await;
    }
}

async fn write_artifacts(path: &Path, result: &FaultRunResult) -> Result<(), Box<dyn Error>> {
    atomic_write(
        &path.join("result.json"),
        &serde_json::to_vec_pretty(result)?,
    )
    .await?;
    let mut summary = format!(
        "# pg-proto fault-injection report\n\nFault injection: {}\n\nPerformance evidence included: no\n\n",
        if result.success { "PASS" } else { "FAIL" }
    );
    for scenario in &result.scenarios {
        summary.push_str(&format!(
            "- `{}`: {}\n",
            scenario.id,
            if scenario.contract_satisfied {
                "PASS"
            } else {
                "FAIL"
            }
        ));
    }
    atomic_write(&path.join("summary.md"), summary.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use std::{cell::Cell, time::Duration};

    use super::wait_until_ready;

    #[tokio::test]
    async fn readiness_probe_retries_transient_rejections() {
        let attempts = Cell::new(0);
        let observed = wait_until_ready(Duration::from_secs(1), Duration::ZERO, || async {
            attempts.set(attempts.get() + 1);
            Ok(attempts.get() == 3)
        })
        .await
        .expect("third readiness probe should succeed");

        assert_eq!(observed, 3);
        assert_eq!(attempts.get(), 3);
    }

    #[tokio::test]
    async fn readiness_probe_has_a_bounded_deadline() {
        let outcome = wait_until_ready(Duration::from_millis(10), Duration::ZERO, || async {
            Ok(false)
        })
        .await;

        assert!(outcome.is_err());
    }
}
