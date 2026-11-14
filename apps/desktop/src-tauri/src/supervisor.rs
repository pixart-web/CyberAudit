use crate::runtime::{inspect_resources, RuntimeLayout};
use crate::secrets::InstallationSecrets;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const DATABASE_OWNER_USER: &str = "cyberaudit";
const DATABASE_APPLICATION_USER: &str = "cyberaudit_app";
const DATABASE_NAME: &str = "cyberaudit";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(45);
const MIGRATION_TIMEOUT: Duration = Duration::from_secs(180);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(15);
const PROBE_INTERVAL: Duration = Duration::from_millis(100);
const MAX_RESTARTS: u8 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SupervisorState {
    VerifyingResources,
    DatabaseStarting,
    DatabaseReady,
    MigrationsRunning,
    MigrationsComplete,
    BrokerStarting,
    BrokerReady,
    ApiStarting,
    ApiReady,
    WorkerStarting,
    WorkerReady,
    WebStarting,
    Ready,
    Stopping,
    Stopped,
    Failed,
}

pub struct StartupStateMachine {
    state: SupervisorState,
}

impl StartupStateMachine {
    pub fn new() -> Self {
        Self {
            state: SupervisorState::VerifyingResources,
        }
    }

    pub fn state(&self) -> SupervisorState {
        self.state
    }

    pub fn transition(&mut self, next: SupervisorState) -> Result<(), SupervisorError> {
        let allowed = matches!(
            (self.state, next),
            (
                SupervisorState::VerifyingResources,
                SupervisorState::DatabaseStarting
            ) | (
                SupervisorState::DatabaseStarting,
                SupervisorState::DatabaseReady
            ) | (
                SupervisorState::DatabaseReady,
                SupervisorState::MigrationsRunning
            ) | (
                SupervisorState::MigrationsRunning,
                SupervisorState::MigrationsComplete
            ) | (
                SupervisorState::MigrationsComplete,
                SupervisorState::BrokerStarting
            ) | (
                SupervisorState::BrokerStarting,
                SupervisorState::BrokerReady
            ) | (SupervisorState::BrokerReady, SupervisorState::ApiStarting)
                | (SupervisorState::ApiStarting, SupervisorState::ApiReady)
                | (SupervisorState::ApiReady, SupervisorState::WorkerStarting)
                | (
                    SupervisorState::WorkerStarting,
                    SupervisorState::WorkerReady
                )
                | (SupervisorState::WorkerReady, SupervisorState::WebStarting)
                | (SupervisorState::WebStarting, SupervisorState::Ready)
                | (SupervisorState::Ready, SupervisorState::Stopping)
                | (SupervisorState::Stopping, SupervisorState::Stopped)
        ) || (next == SupervisorState::Failed
            && !matches!(
                self.state,
                SupervisorState::Stopped | SupervisorState::Failed
            ))
            || (next == SupervisorState::Stopping
                && !matches!(
                    self.state,
                    SupervisorState::Stopped | SupervisorState::Stopping
                ));
        if !allowed {
            return Err(SupervisorError::InvalidTransition {
                from: self.state,
                to: next,
            });
        }
        self.state = next;
        Ok(())
    }
}

impl Default for StartupStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimePorts {
    pub database: u16,
    pub broker: u16,
    pub api: u16,
    pub web: u16,
}

pub struct PortReservations {
    database: Option<TcpListener>,
    broker: Option<TcpListener>,
    api: Option<TcpListener>,
    web: Option<TcpListener>,
    ports: RuntimePorts,
}

impl PortReservations {
    pub fn reserve() -> Result<Self, SupervisorError> {
        let database = reserve_loopback()?;
        let broker = reserve_loopback()?;
        let api = reserve_loopback()?;
        let web = reserve_loopback()?;
        let ports = RuntimePorts {
            database: listener_port(&database)?,
            broker: listener_port(&broker)?,
            api: listener_port(&api)?,
            web: listener_port(&web)?,
        };
        Ok(Self {
            database: Some(database),
            broker: Some(broker),
            api: Some(api),
            web: Some(web),
            ports,
        })
    }

    pub fn ports(&self) -> RuntimePorts {
        self.ports
    }

    pub fn release_database(&mut self) {
        self.database.take();
    }

    pub fn release_broker(&mut self) {
        self.broker.take();
    }

    pub fn release_api(&mut self) {
        self.api.take();
    }

    pub fn release_web(&mut self) {
        self.web.take();
    }

    pub fn release_all(mut self) {
        self.release_database();
        self.release_broker();
        self.release_api();
        self.release_web();
    }
}

fn reserve_loopback() -> Result<TcpListener, SupervisorError> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(SupervisorError::PortReservation)
}

fn listener_port(listener: &TcpListener) -> Result<u16, SupervisorError> {
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(SupervisorError::PortReservation)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeProcess {
    Database,
    Migration,
    Broker,
    Api,
    Worker,
    Web,
}

impl RuntimeProcess {
    fn sidecar(self) -> &'static str {
        match self {
            Self::Database => "cyberaudit-postgres",
            Self::Migration | Self::Api => "cyberaudit-api",
            Self::Broker => "cyberaudit-valkey",
            Self::Worker => "cyberaudit-worker",
            Self::Web => "cyberaudit-web",
        }
    }

    fn fixed_arguments(self) -> &'static [&'static str] {
        match self {
            Self::Migration => &["migrate"],
            Self::Api => &["serve"],
            _ => &[],
        }
    }
}

#[derive(Clone)]
pub struct LaunchStep {
    process: RuntimeProcess,
    executable: PathBuf,
    arguments: &'static [&'static str],
    environment: BTreeMap<&'static str, String>,
    log_directory: PathBuf,
}

impl LaunchStep {
    pub fn process(&self) -> RuntimeProcess {
        self.process
    }

    pub fn executable(&self) -> &Path {
        &self.executable
    }

    pub fn arguments(&self) -> &'static [&'static str] {
        self.arguments
    }

    pub fn spawn(&self) -> Result<ManagedChild, SupervisorError> {
        if !is_regular_nonsymlink(&self.executable) {
            return Err(SupervisorError::InvalidSidecar(self.process.sidecar()));
        }
        let stdout = secure_log_file(&self.log_directory, self.process, "stdout")?;
        let stderr = secure_log_file(&self.log_directory, self.process, "stderr")?;
        let mut command = Command::new(&self.executable);
        command
            .args(self.arguments)
            .env_clear()
            .envs(&self.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            command.process_group(0);
        }
        let child = command
            .spawn()
            .map_err(|source| SupervisorError::ProcessStart {
                process: self.process,
                source,
            })?;
        Ok(ManagedChild {
            process: self.process,
            child,
        })
    }
}

pub struct ManagedChild {
    process: RuntimeProcess,
    child: Child,
}

impl ManagedChild {
    pub fn process(&self) -> RuntimeProcess {
        self.process
    }

    pub fn id(&self) -> u32 {
        self.child.id()
    }

    pub fn try_wait(&mut self) -> Result<Option<ExitStatus>, SupervisorError> {
        self.child
            .try_wait()
            .map_err(|source| SupervisorError::ProcessControl {
                process: self.process,
                source,
            })
    }

    pub fn force_stop(&mut self) -> Result<(), SupervisorError> {
        terminate_process_group(&mut self.child, self.process, true)
    }

    pub fn graceful_stop(&mut self, timeout: Duration) -> Result<(), SupervisorError> {
        if self.try_wait()?.is_some() {
            return Ok(());
        }
        terminate_process_group(&mut self.child, self.process, false)?;
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.try_wait()?.is_some() {
                return Ok(());
            }
            thread::sleep(PROBE_INTERVAL);
        }
        self.force_stop()?;
        self.child
            .wait()
            .map(|_| ())
            .map_err(|source| SupervisorError::ProcessControl {
                process: self.process,
                source,
            })
    }
}

#[cfg(unix)]
fn terminate_process_group(
    child: &mut Child,
    process: RuntimeProcess,
    force: bool,
) -> Result<(), SupervisorError> {
    let signal = if force { libc::SIGKILL } else { libc::SIGTERM };
    let result = unsafe { libc::kill(-(child.id() as i32), signal) };
    if result == 0 {
        return Ok(());
    }
    let source = std::io::Error::last_os_error();
    if source.raw_os_error() == Some(libc::ESRCH) {
        return Ok(());
    }
    Err(SupervisorError::ProcessControl { process, source })
}

#[cfg(windows)]
fn terminate_process_group(
    child: &mut Child,
    process: RuntimeProcess,
    _force: bool,
) -> Result<(), SupervisorError> {
    child
        .kill()
        .map_err(|source| SupervisorError::ProcessControl { process, source })
}

pub struct RuntimeLaunchPlan {
    steps: Vec<LaunchStep>,
    ports: RuntimePorts,
}

pub struct SingleInstanceGuard {
    file: File,
}

impl SingleInstanceGuard {
    pub fn acquire(configuration: &Path) -> Result<Self, SupervisorError> {
        let path = configuration.join("runtime.lock");
        let mut options = fs::OpenOptions::new();
        options.create(true).read(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options.open(path).map_err(SupervisorError::InstanceLock)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result != 0 {
                let source = std::io::Error::last_os_error();
                if source.raw_os_error() == Some(libc::EWOULDBLOCK) {
                    return Err(SupervisorError::AlreadyRunning);
                }
                return Err(SupervisorError::InstanceLock(source));
            }
        }
        Ok(Self { file })
    }
}

impl Drop for SingleInstanceGuard {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            unsafe {
                libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
            }
        }
    }
}

pub struct RuntimeSupervisor {
    machine: StartupStateMachine,
    plan: RuntimeLaunchPlan,
    children: BTreeMap<RuntimeProcess, ManagedChild>,
    restart_counts: BTreeMap<RuntimeProcess, u8>,
    _instance: SingleInstanceGuard,
}

impl RuntimeSupervisor {
    pub fn start(
        resource_root: &Path,
        layout: &RuntimeLayout,
        session_secret_file: &Path,
        secrets: &InstallationSecrets,
    ) -> Result<Self, SupervisorError> {
        let integrity = inspect_resources(resource_root);
        if !integrity.ready {
            let details = integrity
                .missing_resources
                .into_iter()
                .chain(integrity.invalid_resources)
                .collect::<Vec<_>>()
                .join(", ");
            return Err(SupervisorError::ResourceIntegrity(details));
        }
        let worker_ready = layout.configuration.join("worker-ready");
        remove_regular_file_if_present(&worker_ready)?;
        let instance = SingleInstanceGuard::acquire(&layout.configuration)?;
        let mut reservations = PortReservations::reserve()?;
        let plan = build_launch_plan(
            &resource_root.join("runtime/bin"),
            layout,
            session_secret_file,
            secrets,
            reservations.ports(),
        )?;
        let mut supervisor = Self {
            machine: StartupStateMachine::new(),
            plan,
            children: BTreeMap::new(),
            restart_counts: BTreeMap::new(),
            _instance: instance,
        };
        if let Err(error) = supervisor.start_in_order(&mut reservations, secrets, &worker_ready) {
            let _ = supervisor.machine.transition(SupervisorState::Failed);
            let _ = supervisor.stop_all();
            return Err(error);
        }
        Ok(supervisor)
    }

    pub fn state(&self) -> SupervisorState {
        self.machine.state()
    }

    pub fn ports(&self) -> RuntimePorts {
        self.plan.ports()
    }

    fn start_in_order(
        &mut self,
        reservations: &mut PortReservations,
        secrets: &InstallationSecrets,
        worker_ready: &Path,
    ) -> Result<(), SupervisorError> {
        self.machine.transition(SupervisorState::DatabaseStarting)?;
        reservations.release_database();
        self.spawn_persistent(RuntimeProcess::Database)?;
        self.wait_postgresql(secrets.database_password(), STARTUP_TIMEOUT)?;
        self.machine.transition(SupervisorState::DatabaseReady)?;

        self.machine
            .transition(SupervisorState::MigrationsRunning)?;
        let mut migration = self.step(RuntimeProcess::Migration)?.spawn()?;
        wait_for_exit(&mut migration, MIGRATION_TIMEOUT)?;
        self.machine
            .transition(SupervisorState::MigrationsComplete)?;

        self.machine.transition(SupervisorState::BrokerStarting)?;
        reservations.release_broker();
        self.spawn_persistent(RuntimeProcess::Broker)?;
        self.wait_valkey(secrets.broker_password(), STARTUP_TIMEOUT)?;
        self.machine.transition(SupervisorState::BrokerReady)?;

        self.machine.transition(SupervisorState::ApiStarting)?;
        reservations.release_api();
        self.spawn_persistent(RuntimeProcess::Api)?;
        self.wait_http(
            RuntimeProcess::Api,
            self.plan.ports.api,
            "/ready",
            "\"status\":\"ready\"",
            STARTUP_TIMEOUT,
        )?;
        self.machine.transition(SupervisorState::ApiReady)?;

        self.machine.transition(SupervisorState::WorkerStarting)?;
        self.spawn_persistent(RuntimeProcess::Worker)?;
        self.wait_worker(worker_ready, STARTUP_TIMEOUT)?;
        self.machine.transition(SupervisorState::WorkerReady)?;

        self.machine.transition(SupervisorState::WebStarting)?;
        reservations.release_web();
        self.spawn_persistent(RuntimeProcess::Web)?;
        self.wait_http(
            RuntimeProcess::Web,
            self.plan.ports.web,
            "/setup",
            "CyberAudit",
            STARTUP_TIMEOUT,
        )?;
        self.machine.transition(SupervisorState::Ready)?;
        Ok(())
    }

    fn step(&self, process: RuntimeProcess) -> Result<&LaunchStep, SupervisorError> {
        self.plan
            .steps()
            .iter()
            .find(|step| step.process == process)
            .ok_or(SupervisorError::MissingLaunchStep(process))
    }

    fn spawn_persistent(&mut self, process: RuntimeProcess) -> Result<(), SupervisorError> {
        let child = self.step(process)?.spawn()?;
        self.children.insert(process, child);
        Ok(())
    }

    fn wait_postgresql(
        &mut self,
        password: &str,
        timeout: Duration,
    ) -> Result<(), SupervisorError> {
        let runtime_root = runtime_root(self.step(RuntimeProcess::Database)?.executable())?;
        let psql = runtime_root
            .join("tools")
            .join("postgresql")
            .join("bin")
            .join(executable_name("psql"));
        wait_for_probe(
            self.children
                .get_mut(&RuntimeProcess::Database)
                .ok_or(SupervisorError::MissingLaunchStep(RuntimeProcess::Database))?,
            timeout,
            || postgres_identity(&psql, self.plan.ports.database, password),
        )
    }

    fn wait_valkey(&mut self, password: &str, timeout: Duration) -> Result<(), SupervisorError> {
        let runtime_root = runtime_root(self.step(RuntimeProcess::Broker)?.executable())?;
        let cli = runtime_root
            .join("tools")
            .join("valkey")
            .join("bin")
            .join(executable_name("valkey-cli"));
        wait_for_probe(
            self.children
                .get_mut(&RuntimeProcess::Broker)
                .ok_or(SupervisorError::MissingLaunchStep(RuntimeProcess::Broker))?,
            timeout,
            || valkey_identity(&cli, self.plan.ports.broker, password),
        )
    }

    fn wait_http(
        &mut self,
        process: RuntimeProcess,
        port: u16,
        path: &str,
        expected: &str,
        timeout: Duration,
    ) -> Result<(), SupervisorError> {
        wait_for_probe(
            self.children
                .get_mut(&process)
                .ok_or(SupervisorError::MissingLaunchStep(process))?,
            timeout,
            || http_identity(port, path, expected),
        )
    }

    fn wait_worker(&mut self, ready_file: &Path, timeout: Duration) -> Result<(), SupervisorError> {
        wait_for_probe(
            self.children
                .get_mut(&RuntimeProcess::Worker)
                .ok_or(SupervisorError::MissingLaunchStep(RuntimeProcess::Worker))?,
            timeout,
            || Ok(is_regular_nonsymlink(ready_file)),
        )
    }

    pub fn monitor_once(&mut self) -> Result<(), SupervisorError> {
        if self.machine.state() != SupervisorState::Ready {
            return Ok(());
        }
        let processes = self.children.keys().copied().collect::<Vec<_>>();
        for process in processes {
            let exited = self
                .children
                .get_mut(&process)
                .ok_or(SupervisorError::MissingLaunchStep(process))?
                .try_wait()?;
            if let Some(status) = exited {
                self.children.remove(&process);
                if matches!(
                    process,
                    RuntimeProcess::Api | RuntimeProcess::Worker | RuntimeProcess::Web
                ) && self.consume_restart(process)
                {
                    self.restart_process(process)?;
                    return Ok(());
                }
                self.machine.transition(SupervisorState::Failed)?;
                return Err(SupervisorError::UnexpectedExit { process, status });
            }
        }
        Ok(())
    }

    fn restart_process(&mut self, process: RuntimeProcess) -> Result<(), SupervisorError> {
        if process == RuntimeProcess::Worker {
            let ready_file = self
                .step(RuntimeProcess::Worker)?
                .environment
                .get("CYBERAUDIT_DESKTOP_READY_FILE")
                .map(PathBuf::from)
                .ok_or(SupervisorError::UnsafeReadinessFile)?;
            remove_regular_file_if_present(&ready_file)?;
            self.spawn_persistent(process)?;
            return self.wait_worker(&ready_file, STARTUP_TIMEOUT);
        }
        self.spawn_persistent(process)?;
        match process {
            RuntimeProcess::Api => self.wait_http(
                process,
                self.plan.ports.api,
                "/ready",
                "\"status\":\"ready\"",
                STARTUP_TIMEOUT,
            ),
            RuntimeProcess::Web => self.wait_http(
                process,
                self.plan.ports.web,
                "/setup",
                "CyberAudit",
                STARTUP_TIMEOUT,
            ),
            _ => Err(SupervisorError::MissingLaunchStep(process)),
        }
    }

    fn consume_restart(&mut self, process: RuntimeProcess) -> bool {
        let count = self.restart_counts.entry(process).or_insert(0);
        if *count >= MAX_RESTARTS {
            return false;
        }
        *count += 1;
        true
    }

    pub fn stop(&mut self) -> Result<(), SupervisorError> {
        if self.machine.state() == SupervisorState::Stopped {
            return Ok(());
        }
        if self.machine.state() != SupervisorState::Stopping {
            self.machine.transition(SupervisorState::Stopping)?;
        }
        self.stop_all()
    }

    fn stop_all(&mut self) -> Result<(), SupervisorError> {
        let mut first_error = None;
        for process in [
            RuntimeProcess::Web,
            RuntimeProcess::Worker,
            RuntimeProcess::Api,
            RuntimeProcess::Broker,
            RuntimeProcess::Database,
        ] {
            if let Some(mut child) = self.children.remove(&process) {
                if let Err(error) = child.graceful_stop(SHUTDOWN_TIMEOUT) {
                    first_error.get_or_insert(error);
                }
            }
        }
        if self.machine.state() != SupervisorState::Stopping {
            let _ = self.machine.transition(SupervisorState::Stopping);
        }
        if let Some(error) = first_error {
            return Err(error);
        }
        if self.machine.state() == SupervisorState::Stopping {
            self.machine.transition(SupervisorState::Stopped)?;
        }
        Ok(())
    }
}

impl Drop for RuntimeSupervisor {
    fn drop(&mut self) {
        let _ = self.stop_all();
    }
}

impl RuntimeLaunchPlan {
    pub fn steps(&self) -> &[LaunchStep] {
        &self.steps
    }

    pub fn ports(&self) -> RuntimePorts {
        self.ports
    }

    pub fn sanitized_steps(&self) -> Vec<SanitizedLaunchStep> {
        self.steps
            .iter()
            .map(|step| SanitizedLaunchStep {
                process: step.process,
                executable: step
                    .executable
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or("invalid-sidecar")
                    .to_owned(),
                arguments: step
                    .arguments
                    .iter()
                    .map(|value| (*value).to_owned())
                    .collect(),
            })
            .collect()
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct SanitizedLaunchStep {
    pub process: RuntimeProcess,
    pub executable: String,
    pub arguments: Vec<String>,
}

pub fn build_launch_plan(
    binary_root: &Path,
    layout: &RuntimeLayout,
    session_secret_file: &Path,
    secrets: &InstallationSecrets,
    ports: RuntimePorts,
) -> Result<RuntimeLaunchPlan, SupervisorError> {
    validate_session_file(layout, session_secret_file)?;
    let processes = [
        RuntimeProcess::Database,
        RuntimeProcess::Migration,
        RuntimeProcess::Broker,
        RuntimeProcess::Api,
        RuntimeProcess::Worker,
        RuntimeProcess::Web,
    ];
    let mut steps = Vec::with_capacity(processes.len());
    for process in processes {
        let executable = binary_root.join(executable_name(process.sidecar()));
        if !is_regular_nonsymlink(&executable) {
            return Err(SupervisorError::InvalidSidecar(process.sidecar()));
        }
        steps.push(LaunchStep {
            process,
            executable,
            arguments: process.fixed_arguments(),
            environment: runtime_environment(process, layout, session_secret_file, secrets, ports),
            log_directory: layout.logs.clone(),
        });
    }
    Ok(RuntimeLaunchPlan { steps, ports })
}

fn runtime_root(sidecar: &Path) -> Result<PathBuf, SupervisorError> {
    sidecar
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or(SupervisorError::InvalidRuntimeRoot)
}

fn remove_regular_file_if_present(path: &Path) -> Result<(), SupervisorError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {
            fs::remove_file(path).map_err(SupervisorError::RuntimeDirectory)
        }
        Ok(_) => Err(SupervisorError::UnsafeReadinessFile),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(SupervisorError::RuntimeDirectory(error)),
    }
}

fn wait_for_exit(child: &mut ManagedChild, timeout: Duration) -> Result<(), SupervisorError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(SupervisorError::UnexpectedExit {
                    process: child.process(),
                    status,
                })
            };
        }
        if Instant::now() >= deadline {
            child.force_stop()?;
            return Err(SupervisorError::ReadinessTimeout(child.process()));
        }
        thread::sleep(PROBE_INTERVAL);
    }
}

fn wait_for_probe(
    child: &mut ManagedChild,
    timeout: Duration,
    mut probe: impl FnMut() -> Result<bool, std::io::Error>,
) -> Result<(), SupervisorError> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Err(SupervisorError::UnexpectedExit {
                process: child.process(),
                status,
            });
        }
        if probe().unwrap_or(false) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(SupervisorError::ReadinessTimeout(child.process()));
        }
        thread::sleep(PROBE_INTERVAL);
    }
}

fn postgres_identity(program: &Path, port: u16, password: &str) -> Result<bool, std::io::Error> {
    if !is_regular_nonsymlink(program) {
        return Ok(false);
    }
    let output = Command::new(program)
        .env_clear()
        .env("TZ", "UTC")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("PGPASSWORD", password)
        .args([
            "--host",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--username",
            DATABASE_OWNER_USER,
            "--dbname",
            DATABASE_NAME,
            "--tuples-only",
            "--no-align",
            "--no-password",
            "--command",
            "SELECT current_database() || '|' || current_user",
        ])
        .stdin(Stdio::null())
        .output()?;
    Ok(output.status.success()
        && matches!(
            output.stdout.as_slice(),
            b"cyberaudit|cyberaudit\n" | b"cyberaudit|cyberaudit\r\n"
        ))
}

fn valkey_identity(program: &Path, port: u16, password: &str) -> Result<bool, std::io::Error> {
    if !is_regular_nonsymlink(program) {
        return Ok(false);
    }
    let output = Command::new(program)
        .env_clear()
        .env("REDISCLI_AUTH", password)
        .args(["-h", "127.0.0.1", "-p", &port.to_string(), "PING"])
        .stdin(Stdio::null())
        .output()?;
    Ok(output.status.success() && matches!(output.stdout.as_slice(), b"PONG\n" | b"PONG\r\n"))
}

fn http_identity(port: u16, path: &str, expected: &str) -> Result<bool, std::io::Error> {
    let response = http_response(port, path)?;
    let success = response.starts_with("HTTP/1.1 200 ") || response.starts_with("HTTP/1.0 200 ");
    Ok(success && response.contains(expected))
}

fn http_response(port: u16, path: &str) -> Result<String, std::io::Error> {
    http_request(port, "GET", path, None, None)
}

fn http_request(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
    bearer: Option<&str>,
) -> Result<String, std::io::Error> {
    http_request_with_timeout(port, method, path, body, bearer, Duration::from_secs(1))
}

fn http_request_with_timeout(
    port: u16,
    method: &str,
    path: &str,
    body: Option<&str>,
    bearer: Option<&str>,
    read_timeout: Duration,
) -> Result<String, std::io::Error> {
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port);
    let mut stream = TcpStream::connect_timeout(&address.into(), Duration::from_millis(250))?;
    stream.set_read_timeout(Some(read_timeout))?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    let body = body.unwrap_or("");
    write!(stream, "{method} {path} HTTP/1.1\r\n")?;
    write!(stream, "Host: 127.0.0.1:{port}\r\n")?;
    write!(stream, "Connection: close\r\nAccept: application/json\r\n")?;
    if !body.is_empty() {
        write!(
            stream,
            "Content-Type: application/json\r\nContent-Length: {}\r\n",
            body.len()
        )?;
    }
    if let Some(token) = bearer {
        write!(stream, "Authorization: Bearer {token}\r\n")?;
    }
    write!(stream, "\r\n{body}")?;
    let mut response = Vec::with_capacity(4096);
    stream.take(64 * 1024).read_to_end(&mut response)?;
    Ok(String::from_utf8_lossy(&response).into_owned())
}

fn validate_session_file(
    layout: &RuntimeLayout,
    session_secret_file: &Path,
) -> Result<(), SupervisorError> {
    if session_secret_file.parent() != Some(layout.configuration.as_path())
        || !is_regular_nonsymlink(session_secret_file)
    {
        return Err(SupervisorError::InvalidSessionCapability);
    }
    Ok(())
}

fn runtime_environment(
    process: RuntimeProcess,
    layout: &RuntimeLayout,
    session_secret_file: &Path,
    secrets: &InstallationSecrets,
    ports: RuntimePorts,
) -> BTreeMap<&'static str, String> {
    let mut environment = BTreeMap::new();
    match process {
        RuntimeProcess::Database => {
            environment.insert(
                "CYBERAUDIT_DATABASE_DIRECTORY",
                layout.database.to_string_lossy().into_owned(),
            );
            environment.insert(
                "CYBERAUDIT_POSTGRES_ADMIN_PASSWORD",
                secrets.database_password().to_owned(),
            );
            environment.insert(
                "CYBERAUDIT_POSTGRES_RUNTIME_PASSWORD",
                secrets.database_runtime_password().to_owned(),
            );
            environment.insert("CYBERAUDIT_DATABASE_PORT", ports.database.to_string());
        }
        RuntimeProcess::Broker => {
            environment.insert(
                "CYBERAUDIT_BROKER_DIRECTORY",
                layout.broker.to_string_lossy().into_owned(),
            );
            environment.insert(
                "CYBERAUDIT_BROKER_PASSWORD",
                secrets.broker_password().to_owned(),
            );
            environment.insert("CYBERAUDIT_BROKER_PORT", ports.broker.to_string());
        }
        RuntimeProcess::Migration | RuntimeProcess::Api | RuntimeProcess::Worker => {
            environment.insert("ENVIRONMENT", "desktop".to_owned());
            environment.insert("DESKTOP_MODE", "true".to_owned());
            environment.insert(
                "DESKTOP_SESSION_SECRET_FILE",
                session_secret_file.to_string_lossy().into_owned(),
            );
            let (database_user, database_password) = if process == RuntimeProcess::Migration {
                (DATABASE_OWNER_USER, secrets.database_password())
            } else {
                (
                    DATABASE_APPLICATION_USER,
                    secrets.database_runtime_password(),
                )
            };
            environment.insert(
                "DATABASE_URL",
                format!(
                    "postgresql+asyncpg://{database_user}:{database_password}@127.0.0.1:{}/{DATABASE_NAME}",
                    ports.database
                ),
            );
            environment.insert(
                "REDIS_URL",
                format!(
                    "redis://:{}@127.0.0.1:{}/0",
                    secrets.broker_password(),
                    ports.broker
                ),
            );
            environment.insert("JWT_SECRET", secrets.jwt_secret().to_owned());
            environment.insert("ENCRYPTION_KEY", secrets.encryption_key().to_owned());
            environment.insert("APP_ORIGIN", format!("http://127.0.0.1:{}", ports.web));
            environment.insert("ALLOWED_HOSTS", r#"["127.0.0.1","localhost"]"#.to_owned());
            environment.insert("API_DOCS_ENABLED", "false".to_owned());
            environment.insert("DEBUG", "false".to_owned());
            environment.insert("TRUSTED_PROXY", "false".to_owned());
            environment.insert("RLS_REQUIRED", "true".to_owned());
            environment.insert("DATABASE_RUNTIME_ROLE", "cyberaudit_runtime".to_owned());
            environment.insert("OBJECT_STORAGE_PROVIDER", "filesystem".to_owned());
            environment.insert("UPLOAD_DIR", layout.evidence.to_string_lossy().into_owned());
            if process == RuntimeProcess::Api {
                environment.insert("BOOTSTRAP_TOKEN", secrets.bootstrap_token().to_owned());
                environment.insert("CYBERAUDIT_DESKTOP_API_HOST", "127.0.0.1".to_owned());
                environment.insert("CYBERAUDIT_DESKTOP_API_PORT", ports.api.to_string());
            }
            if process == RuntimeProcess::Worker {
                environment.insert(
                    "CYBERAUDIT_DESKTOP_READY_FILE",
                    layout
                        .configuration
                        .join("worker-ready")
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
        RuntimeProcess::Web => {
            environment.insert(
                "CYBERAUDIT_DESKTOP_API_URL",
                format!("http://127.0.0.1:{}/api/v1", ports.api),
            );
            environment.insert(
                "CYBERAUDIT_DESKTOP_SESSION_FILE",
                session_secret_file.to_string_lossy().into_owned(),
            );
            environment.insert("CYBERAUDIT_WEB_PORT", ports.web.to_string());
            environment.insert(
                "CYBERAUDIT_DESKTOP_WEB_ORIGIN",
                format!("http://127.0.0.1:{}", ports.web),
            );
        }
    }
    environment.insert(
        "CYBERAUDIT_TEMPORARY_DIRECTORY",
        layout.temporary.to_string_lossy().into_owned(),
    );
    environment.insert(
        "CYBERAUDIT_LOG_DIRECTORY",
        layout.logs.to_string_lossy().into_owned(),
    );
    environment
}

fn is_regular_nonsymlink(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
}

fn secure_log_file(
    log_directory: &Path,
    process: RuntimeProcess,
    stream: &str,
) -> Result<File, SupervisorError> {
    fs::create_dir_all(log_directory).map_err(SupervisorError::LogFile)?;
    let mut nonce = [0_u8; 8];
    getrandom::fill(&mut nonce).map_err(|_| SupervisorError::Random)?;
    let nonce = nonce
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let path =
        log_directory.join(format!("{:?}-{stream}-{nonce}.log", process).to_ascii_lowercase());
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    options.open(path).map_err(SupervisorError::LogFile)
}

fn executable_name(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SupervisorError {
    #[error("invalid runtime supervisor transition from {from:?} to {to:?}")]
    InvalidTransition {
        from: SupervisorState,
        to: SupervisorState,
    },
    #[error("unable to reserve a loopback port")]
    PortReservation(#[source] std::io::Error),
    #[error("desktop runtime resources failed integrity verification: {0}")]
    ResourceIntegrity(String),
    #[error("another CyberAudit desktop runtime instance is already active")]
    AlreadyRunning,
    #[error("unable to acquire the desktop runtime instance lock")]
    InstanceLock(#[source] std::io::Error),
    #[error("unable to initialize a private runtime directory")]
    RuntimeDirectory(#[source] std::io::Error),
    #[error("the worker readiness path is not a regular file")]
    UnsafeReadinessFile,
    #[error("the runtime root could not be resolved from its fixed sidecar path")]
    InvalidRuntimeRoot,
    #[error("runtime sidecar {0} is missing or invalid")]
    InvalidSidecar(&'static str),
    #[error("the {0:?} process has no allowlisted launch step")]
    MissingLaunchStep(RuntimeProcess),
    #[error("the {0:?} process did not become ready before its deadline")]
    ReadinessTimeout(RuntimeProcess),
    #[error("the {process:?} process exited unexpectedly with {status}")]
    UnexpectedExit {
        process: RuntimeProcess,
        status: ExitStatus,
    },
    #[error("desktop session capability is outside the protected configuration directory")]
    InvalidSessionCapability,
    #[error("unable to open a private runtime log")]
    LogFile(#[source] std::io::Error),
    #[error("secure random generation failed")]
    Random,
    #[error("unable to start the {process:?} runtime process")]
    ProcessStart {
        process: RuntimeProcess,
        #[source]
        source: std::io::Error,
    },
    #[error("unable to control the {process:?} runtime process")]
    ProcessControl {
        process: RuntimeProcess,
        #[source]
        source: std::io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::provision_session_secret;
    use crate::secrets::{provision_installation_secrets, SecretStore, SecretStoreError};
    use std::collections::HashMap;
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Mutex;

    static NEXT_FIXTURE_ID: AtomicU64 = AtomicU64::new(1);

    #[derive(Default)]
    struct MemorySecretStore(Mutex<HashMap<String, String>>);

    impl SecretStore for MemorySecretStore {
        fn get(&self, account: &str) -> Result<Option<String>, SecretStoreError> {
            Ok(self.0.lock().expect("store lock").get(account).cloned())
        }

        fn set(&self, account: &str, value: &str) -> Result<(), SecretStoreError> {
            self.0
                .lock()
                .expect("store lock")
                .insert(account.to_owned(), value.to_owned());
            Ok(())
        }
    }

    fn fixture() -> (PathBuf, RuntimeLayout, PathBuf, InstallationSecrets) {
        let root = std::env::temp_dir().join(format!(
            "cyberaudit-supervisor-{}-{}",
            std::process::id(),
            NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let layout = RuntimeLayout::initialize(&root).expect("layout should initialize");
        let session =
            provision_session_secret(&layout.configuration).expect("session should provision");
        let secrets = provision_installation_secrets(&MemorySecretStore::default())
            .expect("secrets should provision");
        (root, layout, session, secrets)
    }

    #[test]
    fn reserves_distinct_loopback_ports() {
        let reservations = PortReservations::reserve().expect("ports should reserve");
        let ports = reservations.ports();
        let distinct = [ports.database, ports.broker, ports.api, ports.web]
            .into_iter()
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(distinct.len(), 4);
        reservations.release_all();
    }

    #[test]
    fn startup_state_machine_requires_dependency_order() {
        let mut machine = StartupStateMachine::new();
        for state in [
            SupervisorState::DatabaseStarting,
            SupervisorState::DatabaseReady,
            SupervisorState::MigrationsRunning,
            SupervisorState::MigrationsComplete,
            SupervisorState::BrokerStarting,
            SupervisorState::BrokerReady,
            SupervisorState::ApiStarting,
            SupervisorState::ApiReady,
            SupervisorState::WorkerStarting,
            SupervisorState::WorkerReady,
            SupervisorState::WebStarting,
            SupervisorState::Ready,
        ] {
            machine
                .transition(state)
                .expect("transition should be valid");
        }
        assert_eq!(machine.state(), SupervisorState::Ready);
    }

    #[test]
    fn startup_state_machine_rejects_skips_and_allows_failure_cleanup() {
        let mut machine = StartupStateMachine::new();
        assert!(matches!(
            machine.transition(SupervisorState::ApiStarting),
            Err(SupervisorError::InvalidTransition { .. })
        ));
        machine
            .transition(SupervisorState::DatabaseStarting)
            .expect("database may start first");
        machine
            .transition(SupervisorState::Failed)
            .expect("active startup may fail");
        machine
            .transition(SupervisorState::Stopping)
            .expect("failed startup may clean up");
        machine
            .transition(SupervisorState::Stopped)
            .expect("cleanup may stop");
        assert!(machine.transition(SupervisorState::Ready).is_err());
    }

    #[test]
    fn creates_only_the_fixed_launch_sequence() {
        let (root, layout, session, secrets) = fixture();
        let binary_root = root.join("runtime/bin");
        fs::create_dir_all(&binary_root).expect("binary directory should initialize");
        for sidecar in [
            "cyberaudit-postgres",
            "cyberaudit-valkey",
            "cyberaudit-api",
            "cyberaudit-worker",
            "cyberaudit-web",
        ] {
            fs::write(binary_root.join(executable_name(sidecar)), b"fixture")
                .expect("sidecar should exist");
        }
        let ports = RuntimePorts {
            database: 15432,
            broker: 16379,
            api: 18000,
            web: 13000,
        };

        let plan = build_launch_plan(&binary_root, &layout, &session, &secrets, ports)
            .expect("launch plan should build");

        assert_eq!(
            plan.steps()
                .iter()
                .map(LaunchStep::process)
                .collect::<Vec<_>>(),
            vec![
                RuntimeProcess::Database,
                RuntimeProcess::Migration,
                RuntimeProcess::Broker,
                RuntimeProcess::Api,
                RuntimeProcess::Worker,
                RuntimeProcess::Web,
            ]
        );
        assert_eq!(plan.steps()[1].arguments(), &["migrate"]);
        assert_eq!(plan.steps()[3].arguments(), &["serve"]);
        assert!(plan.steps().iter().all(|step| step.arguments().len() <= 1));
        assert_eq!(
            plan.steps()[3].environment.get("ALLOWED_HOSTS"),
            Some(&r#"["127.0.0.1","localhost"]"#.to_owned())
        );
        assert!(!plan.steps()[5].environment.contains_key("DATABASE_URL"));
        assert!(!plan.steps()[5].environment.contains_key("JWT_SECRET"));
        assert_eq!(
            plan.steps()[5]
                .environment
                .get("CYBERAUDIT_DESKTOP_API_URL"),
            Some(&"http://127.0.0.1:18000/api/v1".to_owned())
        );
        assert!(!plan.steps()[2].environment.contains_key("DATABASE_URL"));
        assert!(!plan.steps()[0].environment.contains_key("REDIS_URL"));
        let serialized = serde_json::to_string(&plan.sanitized_steps())
            .expect("sanitized plan should serialize");
        assert!(!serialized.contains(secrets.jwt_secret()));
        assert!(!serialized.contains(secrets.database_password()));
        assert!(!serialized.contains(secrets.database_runtime_password()));
        assert!(plan.steps()[1]
            .environment
            .get("DATABASE_URL")
            .is_some_and(|url| url.contains("cyberaudit:")));
        assert!(plan.steps()[3]
            .environment
            .get("DATABASE_URL")
            .is_some_and(|url| url.contains("cyberaudit_app:")));
        fs::remove_dir_all(root).expect("fixture should be removed");
    }

    #[test]
    fn rejects_a_session_file_outside_configuration() {
        let (root, layout, _session, secrets) = fixture();
        let external = root.join("desktop-session");
        fs::write(&external, "not-a-capability").expect("fixture should exist");
        let result = build_launch_plan(
            &root.join("runtime/bin"),
            &layout,
            &external,
            &secrets,
            RuntimePorts {
                database: 15432,
                broker: 16379,
                api: 18000,
                web: 13000,
            },
        );
        assert!(matches!(
            result,
            Err(SupervisorError::InvalidSessionCapability)
        ));
        fs::remove_dir_all(root).expect("fixture should be removed");
    }

    #[test]
    fn creates_distinct_private_log_files_without_following_existing_paths() {
        let (root, layout, _session, _secrets) = fixture();
        let first = secure_log_file(&layout.logs, RuntimeProcess::Api, "stdout")
            .expect("first log should open");
        let second = secure_log_file(&layout.logs, RuntimeProcess::Api, "stdout")
            .expect("second log should open");
        drop((first, second));
        let logs = fs::read_dir(&layout.logs)
            .expect("logs should be readable")
            .collect::<Result<Vec<_>, _>>()
            .expect("logs should enumerate");
        assert_eq!(logs.len(), 2);
        assert_ne!(logs[0].path(), logs[1].path());
        assert!(logs
            .iter()
            .all(|entry| entry.file_type().is_ok_and(|kind| kind.is_file())));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert!(logs.iter().all(|entry| {
                entry
                    .metadata()
                    .is_ok_and(|metadata| metadata.permissions().mode() & 0o077 == 0)
            }));
        }
        fs::remove_dir_all(root).expect("fixture should be removed");
    }

    #[test]
    fn instance_lock_is_exclusive_and_recovers_after_release() {
        let (root, layout, _session, _secrets) = fixture();
        let first = SingleInstanceGuard::acquire(&layout.configuration)
            .expect("first instance should acquire the lock");
        assert!(matches!(
            SingleInstanceGuard::acquire(&layout.configuration),
            Err(SupervisorError::AlreadyRunning)
        ));
        drop(first);
        SingleInstanceGuard::acquire(&layout.configuration)
            .expect("released instance lock should be recoverable");
        fs::remove_dir_all(root).expect("fixture should be removed");
    }

    #[cfg(unix)]
    fn sleeping_child(process: RuntimeProcess) -> ManagedChild {
        use std::os::unix::process::CommandExt;
        let mut command = Command::new("/bin/sleep");
        command.arg("30").process_group(0);
        ManagedChild {
            process,
            child: command.spawn().expect("sleep fixture should start"),
        }
    }

    #[cfg(unix)]
    #[test]
    fn readiness_deadline_is_bounded() {
        let mut child = sleeping_child(RuntimeProcess::Api);
        let error = wait_for_probe(&mut child, Duration::from_millis(1), || Ok(false))
            .expect_err("probe should time out");
        assert!(matches!(
            error,
            SupervisorError::ReadinessTimeout(RuntimeProcess::Api)
        ));
        child.force_stop().expect("fixture should stop");
        child.child.wait().expect("fixture should be reaped");
    }

    #[cfg(unix)]
    #[test]
    fn graceful_shutdown_reaps_the_owned_process_group() {
        let mut child = sleeping_child(RuntimeProcess::Web);
        child
            .graceful_stop(Duration::from_secs(2))
            .expect("owned process group should stop");
        assert!(child.try_wait().expect("wait should succeed").is_some());
    }

    #[test]
    #[ignore = "requires CYBERAUDIT_DESKTOP_INTEGRATION_RESOURCE_DIR with a complete runtime"]
    fn complete_packaged_runtime_starts_stops_and_restarts() {
        let resource_directory = std::env::var_os("CYBERAUDIT_DESKTOP_INTEGRATION_RESOURCE_DIR")
            .map(PathBuf::from)
            .expect("integration resource directory is required");
        let root = std::env::temp_dir().join(format!(
            "cyberaudit-runtime-integration-{}-{}",
            std::process::id(),
            NEXT_FIXTURE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let layout = RuntimeLayout::initialize(&root).expect("layout should initialize");
        let store = MemorySecretStore::default();
        let secrets =
            provision_installation_secrets(&store).expect("secrets should provision once");

        let administrator_email = "desktop.admin@example.com";
        let administrator_password = "DesktopTest!2026Strong";
        let tenant_admin_email = "desktop.admin@tenant-boundary.example.com";
        let tenant_admin_password = "TenantBoundary!2026Strong";
        let tenant_admin_active_password = "TenantBoundary!2026Rotated";
        let mut engagement_id = String::new();
        let mut job_id = String::new();

        for cycle in 0..2 {
            let session = provision_session_secret(&layout.configuration)
                .expect("session capability should provision");
            let mut supervisor =
                RuntimeSupervisor::start(&resource_directory, &layout, &session, &secrets)
                    .expect("complete runtime should become ready");
            assert_eq!(supervisor.state(), SupervisorState::Ready);
            let web_port = supervisor.ports().web;
            let proxy = http_response(web_port, "/api/v1/setup/status")
                .expect("local proxy request should complete");
            assert!(
                proxy.starts_with("HTTP/1.1 200 ") && proxy.contains("\"initialized\""),
                "same-origin proxy did not return setup status: {}",
                proxy.chars().take(1200).collect::<String>()
            );

            if cycle == 0 {
                assert!(proxy.contains("\"initialized\":false"));
                let setup = http_request_with_timeout(
                    web_port,
                    "POST",
                    "/api/v1/setup/initialize",
                    Some(
                        r#"{"name":"CyberAudit Desktop","slug":"cyberaudit-desktop","timezone":"Europe/Lisbon","locale":"pt-PT","admin_name":"Desktop Administrator","admin_email":"desktop.admin@example.com","admin_password":"DesktopTest!2026Strong"}"#,
                    ),
                    None,
                    Duration::from_secs(30),
                )
                .expect("desktop bootstrap should complete through the proxy");
                assert_http_status(&setup, 201, "desktop bootstrap");

                let token = desktop_login(web_port, administrator_email, administrator_password);
                let client = authenticated_json_request(
                    web_port,
                    "POST",
                    "/api/v1/clients",
                    r#"{"name":"Persistent Desktop Client","legal_name":"Persistent Desktop Client Ltd","status":"active"}"#,
                    &token,
                    201,
                );
                let client_id = client["id"]
                    .as_str()
                    .expect("client response should contain an id");
                let engagement_payload = serde_json::json!({
                    "client_id": client_id,
                    "name": "Persistent Desktop Assessment",
                    "code": "DESKTOP-001",
                    "description": "Native runtime persistence acceptance",
                    "mode": "laboratory",
                    "risk_level": "low"
                });
                let engagement = authenticated_json_request(
                    web_port,
                    "POST",
                    "/api/v1/engagements",
                    &engagement_payload.to_string(),
                    &token,
                    201,
                );
                engagement_id = engagement["id"]
                    .as_str()
                    .expect("engagement response should contain an id")
                    .to_owned();
                let scope = authenticated_json_request(
                    web_port,
                    "POST",
                    "/api/v1/scopes",
                    &serde_json::json!({
                        "engagement_id": engagement_id,
                        "name": "Desktop Local Scope",
                        "maximum_intensity": "passive",
                        "allowed_techniques": ["asset-inventory"]
                    })
                    .to_string(),
                    &token,
                    201,
                );
                let scope_id = scope["id"]
                    .as_str()
                    .expect("scope response should contain an id");
                authenticated_json_request(
                    web_port,
                    "POST",
                    "/api/v1/scope-targets",
                    &serde_json::json!({
                        "scope_id": scope_id,
                        "target_type": "ip",
                        "target_value": "127.0.0.1"
                    })
                    .to_string(),
                    &token,
                    201,
                );
                for status in ["pending_authorization", "authorized"] {
                    authenticated_json_request(
                        web_port,
                        "PATCH",
                        &format!("/api/v1/engagements/{engagement_id}/status"),
                        &serde_json::json!({"status": status}).to_string(),
                        &token,
                        200,
                    );
                }
                let asset_payload = serde_json::json!({
                    "engagement_id": engagement_id,
                    "name": "Persistent Desktop Host",
                    "asset_type": "host",
                    "identifier": "desktop-host-001",
                    "hostname": "desktop-host.local",
                    "ip_address": "127.0.0.1",
                    "criticality": "low",
                    "status": "active"
                });
                authenticated_json_request(
                    web_port,
                    "POST",
                    "/api/v1/assets",
                    &asset_payload.to_string(),
                    &token,
                    201,
                );
                let profiles = http_request(
                    web_port,
                    "GET",
                    "/api/v1/scan-profiles?page_size=100",
                    None,
                    Some(&token),
                )
                .expect("scan profile query should complete");
                assert_http_status(&profiles, 200, "scan profile query");
                let profiles = response_json(&profiles);
                let profile_id = profiles["items"]
                    .as_array()
                    .expect("scan profile response should contain items")
                    .iter()
                    .find(|profile| {
                        profile["adapter_code"].as_str() == Some("cyberaudit.asset_inventory")
                    })
                    .and_then(|profile| profile["id"].as_str())
                    .expect("safe local inventory profile should be provisioned")
                    .to_owned();
                let job = authenticated_json_request(
                    web_port,
                    "POST",
                    "/api/v1/jobs",
                    &serde_json::json!({
                        "engagement_id": engagement_id,
                        "scope_id": scope_id,
                        "scan_profile_id": profile_id,
                        "target_type": "ip",
                        "target_value": "127.0.0.1",
                        "technique": "asset-inventory",
                        "intensity": "passive",
                        "configuration": {"sources": ["platform"]}
                    })
                    .to_string(),
                    &token,
                    201,
                );
                job_id = job["id"]
                    .as_str()
                    .expect("job response should contain an id")
                    .to_owned();
                wait_for_completed_job(web_port, &job_id, &token);
                let results = http_request(
                    web_port,
                    "GET",
                    &format!("/api/v1/jobs/{job_id}/results"),
                    None,
                    Some(&token),
                )
                .expect("job results should be available");
                assert_http_status(&results, 200, "job results");
                let results = response_json(&results);
                assert_eq!(results["summary"]["evidence_created"], 1);
                assert_eq!(results["raw_result"]["sanitized"], true);

                authenticated_json_request(
                    web_port,
                    "POST",
                    "/api/v1/platform/organizations",
                    &serde_json::json!({
                        "name": "Desktop Tenant Boundary",
                        "slug": "desktop-tenant-boundary",
                        "admin_name": "Tenant Boundary Administrator",
                        "admin_email": tenant_admin_email,
                        "admin_password": tenant_admin_password
                    })
                    .to_string(),
                    &token,
                    201,
                );
                change_password(
                    web_port,
                    tenant_admin_email,
                    tenant_admin_password,
                    tenant_admin_active_password,
                );
                assert_tenant_isolation(
                    web_port,
                    tenant_admin_email,
                    tenant_admin_active_password,
                    &job_id,
                );
                authenticated_json_request(
                    web_port,
                    "POST",
                    "/api/v1/users",
                    r#"{"name":"Desktop Auditor","email":"desktop.auditor@example.com","password":"DesktopAuditor!2026Strong","role":"Auditor"}"#,
                    &token,
                    201,
                );
                authenticated_json_request(
                    web_port,
                    "POST",
                    &format!("/api/v1/engagements/{engagement_id}/reports"),
                    r#"{"report_type":"technical_findings","include_ai_summary":false}"#,
                    &token,
                    201,
                );
            } else {
                assert!(proxy.contains("\"initialized\":true"));
                let token = desktop_login(web_port, administrator_email, administrator_password);
                for (path, marker) in [
                    (
                        "/api/v1/clients?q=Persistent%20Desktop",
                        "Persistent Desktop Client",
                    ),
                    (
                        "/api/v1/engagements?q=DESKTOP-001",
                        "Persistent Desktop Assessment",
                    ),
                    (
                        "/api/v1/assets?q=desktop-host-001",
                        "Persistent Desktop Host",
                    ),
                    (
                        "/api/v1/users?q=desktop.auditor",
                        "desktop.auditor@example.com",
                    ),
                ] {
                    let response = http_request(web_port, "GET", path, None, Some(&token))
                        .expect("persisted resource query should complete");
                    assert_http_status(&response, 200, path);
                    assert!(response.contains(marker), "{path} did not contain {marker}");
                }
                let reports = http_request(
                    web_port,
                    "GET",
                    &format!("/api/v1/engagements/{engagement_id}/reports"),
                    None,
                    Some(&token),
                )
                .expect("persisted report query should complete");
                assert_http_status(&reports, 200, "persisted reports");
                assert!(reports.contains("technical_findings"));
                let job = http_request(
                    web_port,
                    "GET",
                    &format!("/api/v1/jobs/{job_id}"),
                    None,
                    Some(&token),
                )
                .expect("persisted job query should complete");
                assert_http_status(&job, 200, "persisted job");
                assert_eq!(response_json(&job)["status"], "completed");
                assert_tenant_isolation(
                    web_port,
                    tenant_admin_email,
                    tenant_admin_active_password,
                    &job_id,
                );
            }
            supervisor.stop().expect("runtime should stop cleanly");
            assert_eq!(supervisor.state(), SupervisorState::Stopped);
        }
        assert!(layout.database.join("PG_VERSION").is_file());
        fs::remove_dir_all(root).expect("integration fixture should be removed");
    }

    fn assert_http_status(response: &str, status: u16, operation: &str) {
        assert!(
            response.starts_with(&format!("HTTP/1.1 {status} "))
                || response.starts_with(&format!("HTTP/1.0 {status} ")),
            "{operation} returned an unexpected response: {}",
            response.chars().take(1200).collect::<String>()
        );
    }

    fn response_json(response: &str) -> serde_json::Value {
        let start = response.find('{').expect("response should contain JSON");
        let end = response.rfind('}').expect("response should contain JSON");
        serde_json::from_str(&response[start..=end]).expect("response JSON should parse")
    }

    fn desktop_login(port: u16, email: &str, password: &str) -> String {
        let payload = serde_json::json!({"email": email, "password": password});
        let response = http_request_with_timeout(
            port,
            "POST",
            "/api/v1/auth/login",
            Some(&payload.to_string()),
            None,
            Duration::from_secs(30),
        )
        .expect("desktop login should complete");
        assert_http_status(&response, 200, "desktop login");
        response_json(&response)["access_token"]
            .as_str()
            .expect("login response should contain an access token")
            .to_owned()
    }

    fn change_password(port: u16, email: &str, current_password: &str, new_password: &str) {
        let token = desktop_login(port, email, current_password);
        let payload = serde_json::json!({
            "current_password": current_password,
            "new_password": new_password,
        });
        let response = http_request_with_timeout(
            port,
            "POST",
            "/api/v1/auth/change-password",
            Some(&payload.to_string()),
            Some(&token),
            Duration::from_secs(30),
        )
        .expect("forced password change should complete");
        assert_http_status(&response, 204, "forced password change");
    }

    fn authenticated_json_request(
        port: u16,
        method: &str,
        path: &str,
        body: &str,
        token: &str,
        expected_status: u16,
    ) -> serde_json::Value {
        let response = http_request_with_timeout(
            port,
            method,
            path,
            Some(body),
            Some(token),
            Duration::from_secs(30),
        )
        .expect("authenticated request should complete");
        assert_http_status(&response, expected_status, path);
        response_json(&response)
    }

    fn wait_for_completed_job(port: u16, job_id: &str, token: &str) {
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            let response = http_request(
                port,
                "GET",
                &format!("/api/v1/jobs/{job_id}"),
                None,
                Some(token),
            )
            .expect("job status query should complete");
            assert_http_status(&response, 200, "job status");
            let job = response_json(&response);
            match job["status"].as_str() {
                Some("completed" | "completed_with_warnings") => return,
                Some("denied" | "failed" | "timed_out" | "cancelled") => {
                    panic!("local worker job failed: {job}")
                }
                _ if Instant::now() < deadline => thread::sleep(PROBE_INTERVAL),
                _ => panic!("local worker job did not complete before its deadline: {job}"),
            }
        }
    }

    fn assert_tenant_isolation(port: u16, email: &str, password: &str, foreign_job_id: &str) {
        let token = desktop_login(port, email, password);
        let clients = http_request(
            port,
            "GET",
            "/api/v1/clients?q=Persistent%20Desktop",
            None,
            Some(&token),
        )
        .expect("second tenant client query should complete");
        assert_http_status(&clients, 200, "second tenant client query");
        assert_eq!(response_json(&clients)["total"], 0);
        let foreign_job = http_request(
            port,
            "GET",
            &format!("/api/v1/jobs/{foreign_job_id}"),
            None,
            Some(&token),
        )
        .expect("cross-tenant job query should complete");
        assert_http_status(&foreign_job, 404, "cross-tenant job query");
    }
}
