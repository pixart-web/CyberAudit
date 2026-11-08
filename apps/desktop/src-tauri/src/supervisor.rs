use crate::runtime::RuntimeLayout;
use crate::secrets::InstallationSecrets;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::net::{Ipv4Addr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};

const DATABASE_OWNER_USER: &str = "cyberaudit";
const DATABASE_APPLICATION_USER: &str = "cyberaudit_app";
const DATABASE_NAME: &str = "cyberaudit";

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
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
        let child = Command::new(&self.executable)
            .args(self.arguments)
            .env_clear()
            .envs(&self.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
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
        self.child
            .kill()
            .map_err(|source| SupervisorError::ProcessControl {
                process: self.process,
                source,
            })
    }
}

pub struct RuntimeLaunchPlan {
    steps: Vec<LaunchStep>,
    ports: RuntimePorts,
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
                layout
                    .database
                    .join("valkey")
                    .to_string_lossy()
                    .into_owned(),
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
    #[error("unable to reserve a loopback port")]
    PortReservation(#[source] std::io::Error),
    #[error("runtime sidecar {0} is missing or invalid")]
    InvalidSidecar(&'static str),
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
}
