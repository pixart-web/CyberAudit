use cyberaudit_runtime_host::{
    packaged_tool, random_hex, replace_process, require_success, restrict_file, runtime_root,
    validated_directory, validated_port, validated_secret, HostError, DATABASE_NAME, DATABASE_USER,
};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);

fn main() {
    if let Err(error) = run() {
        eprintln!("CyberAudit database runtime error: {error}");
        std::process::exit(78);
    }
}

fn run() -> Result<(), HostError> {
    let root = runtime_root()?;
    let tools = PostgresTools::load(&root)?;
    let data = validated_directory("CYBERAUDIT_DATABASE_DIRECTORY")?;
    let temporary = validated_directory("CYBERAUDIT_TEMPORARY_DIRECTORY")?;
    let port = validated_port("CYBERAUDIT_DATABASE_PORT")?;
    let password = validated_secret("CYBERAUDIT_POSTGRES_PASSWORD")?;

    if !data.join("PG_VERSION").is_file() {
        initialize_cluster(&tools, &data, &temporary, &password)?;
    }
    let bootstrap_marker = data.join("cyberaudit-bootstrap-v1");
    if !bootstrap_marker.is_file() {
        bootstrap_database(&tools, &data, port, &password, &bootstrap_marker)?;
    }

    let command = postgres_command(&tools.postgres, &data, port);
    replace_process(command)
}

struct PostgresTools {
    initdb: PathBuf,
    postgres: PathBuf,
    pg_isready: PathBuf,
    pg_ctl: PathBuf,
    createdb: PathBuf,
    psql: PathBuf,
}

impl PostgresTools {
    fn load(root: &Path) -> Result<Self, HostError> {
        Ok(Self {
            initdb: packaged_tool(root, &["postgresql", "bin", "initdb"])?,
            postgres: packaged_tool(root, &["postgresql", "bin", "postgres"])?,
            pg_isready: packaged_tool(root, &["postgresql", "bin", "pg_isready"])?,
            pg_ctl: packaged_tool(root, &["postgresql", "bin", "pg_ctl"])?,
            createdb: packaged_tool(root, &["postgresql", "bin", "createdb"])?,
            psql: packaged_tool(root, &["postgresql", "bin", "psql"])?,
        })
    }
}

struct EphemeralPasswordFile(PathBuf);

impl Drop for EphemeralPasswordFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn initialize_cluster(
    tools: &PostgresTools,
    data: &Path,
    temporary: &Path,
    password: &str,
) -> Result<(), HostError> {
    if fs::read_dir(data).map_err(HostError::Io)?.next().is_some() {
        return Err(HostError::InvalidConfiguration(
            "CYBERAUDIT_DATABASE_DIRECTORY",
        ));
    }
    let password_path = temporary.join(format!("postgres-bootstrap-{}", random_hex(12)?));
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut password_file = options.open(&password_path).map_err(HostError::Io)?;
    restrict_file(&password_path)?;
    password_file
        .write_all(format!("{password}\n").as_bytes())
        .map_err(HostError::Io)?;
    password_file.sync_all().map_err(HostError::Io)?;
    drop(password_file);
    let password_file = EphemeralPasswordFile(password_path);

    let status = Command::new(&tools.initdb)
        .env_clear()
        .env("TZ", "UTC")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .arg("--pgdata")
        .arg(data)
        .arg("--username")
        .arg(DATABASE_USER)
        .arg("--pwfile")
        .arg(&password_file.0)
        .arg("--auth-host=scram-sha-256")
        .arg("--auth-local=scram-sha-256")
        .arg("--encoding=UTF8")
        .arg("--locale=C")
        .arg("--data-checksums")
        .arg("--no-instructions")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .map_err(HostError::ProcessStart)?;
    require_success(status)
}

fn bootstrap_database(
    tools: &PostgresTools,
    data: &Path,
    port: u16,
    password: &str,
    marker: &Path,
) -> Result<(), HostError> {
    let mut server = postgres_command(&tools.postgres, data, port)
        .spawn()
        .map_err(HostError::ProcessStart)?;
    let result = (|| {
        wait_until_ready(tools, port, password, &mut server)?;
        if !database_exists(tools, port, password)? {
            create_database(tools, port, password)?;
        }
        write_bootstrap_marker(marker)?;
        stop_database(tools, data)?;
        require_success(server.wait().map_err(HostError::ProcessStart)?)
    })();
    if result.is_err() {
        let _ = server.kill();
        let _ = server.wait();
    }
    result
}

fn postgres_command(postgres: &Path, data: &Path, port: u16) -> Command {
    let mut command = Command::new(postgres);
    command
        .env_clear()
        .env("TZ", "UTC")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .arg(format!(
            "--config-file={}",
            data.join("postgresql.conf").to_string_lossy()
        ))
        .arg("-D")
        .arg(data)
        .arg("-h")
        .arg("127.0.0.1")
        .arg("-p")
        .arg(port.to_string())
        .arg("-c")
        .arg("password_encryption=scram-sha-256")
        .arg("-c")
        .arg("listen_addresses=127.0.0.1")
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    #[cfg(unix)]
    command.arg("-c").arg("unix_socket_directories=");
    command
}

fn wait_until_ready(
    tools: &PostgresTools,
    port: u16,
    password: &str,
    server: &mut Child,
) -> Result<(), HostError> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        if let Some(status) = server.try_wait().map_err(HostError::ProcessStart)? {
            return Err(HostError::ProcessFailed(status.code()));
        }
        let status = database_command(&tools.pg_isready, port, password)
            .arg("--dbname")
            .arg("postgres")
            .arg("--timeout=1")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(HostError::ProcessStart)?;
        if status.success() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HostError::ProcessFailed(None));
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn database_exists(tools: &PostgresTools, port: u16, password: &str) -> Result<bool, HostError> {
    let output = database_command(&tools.psql, port, password)
        .arg("--dbname")
        .arg("postgres")
        .arg("--tuples-only")
        .arg("--no-align")
        .arg("--no-password")
        .arg("--command")
        .arg("SELECT 1 FROM pg_database WHERE datname = 'cyberaudit'")
        .output()
        .map_err(HostError::ProcessStart)?;
    require_success(output.status)?;
    Ok(output.stdout == b"1\n" || output.stdout == b"1\r\n")
}

fn create_database(tools: &PostgresTools, port: u16, password: &str) -> Result<(), HostError> {
    let status = database_command(&tools.createdb, port, password)
        .arg("--no-password")
        .arg("--owner")
        .arg(DATABASE_USER)
        .arg("--encoding=UTF8")
        .arg("--template=template0")
        .arg(DATABASE_NAME)
        .status()
        .map_err(HostError::ProcessStart)?;
    require_success(status)
}

fn database_command(program: &Path, port: u16, password: &str) -> Command {
    let mut command = Command::new(program);
    command
        .env_clear()
        .env("TZ", "UTC")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .env("PGPASSWORD", password)
        .arg("--host")
        .arg("127.0.0.1")
        .arg("--port")
        .arg(port.to_string())
        .arg("--username")
        .arg(DATABASE_USER)
        .stdin(Stdio::null());
    command
}

fn stop_database(tools: &PostgresTools, data: &Path) -> Result<(), HostError> {
    let status = Command::new(&tools.pg_ctl)
        .env_clear()
        .env("TZ", "UTC")
        .env("LC_ALL", "C")
        .env("LANG", "C")
        .arg("--pgdata")
        .arg(data)
        .arg("--wait")
        .arg("--timeout=30")
        .arg("--mode=fast")
        .arg("stop")
        .status()
        .map_err(HostError::ProcessStart)?;
    require_success(status)
}

fn write_bootstrap_marker(marker: &Path) -> Result<(), HostError> {
    let temporary = marker.with_extension(format!("tmp-{}", random_hex(8)?));
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary).map_err(HostError::Io)?;
    file.write_all(b"1\n").map_err(HostError::Io)?;
    file.sync_all().map_err(HostError::Io)?;
    drop(file);
    fs::rename(temporary, marker).map_err(HostError::Io)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "cyberaudit-postgres-host-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("valid system time")
                .as_nanos()
        ))
    }

    #[test]
    fn database_password_is_environment_only_and_never_an_argument() {
        let password = "a".repeat(64);
        let command = database_command(Path::new("/packaged/psql"), 55432, &password);
        let arguments = command
            .get_args()
            .map(|argument| argument.to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(!arguments.iter().any(|argument| argument == &password));
        assert!(command.get_envs().any(|(name, value)| {
            name == "PGPASSWORD" && value.is_some_and(|value| value == password.as_str())
        }));
    }

    #[test]
    fn ephemeral_password_file_is_removed_on_drop() {
        let root = temp_root();
        fs::create_dir_all(&root).expect("temporary root should initialize");
        let path = root.join("password");
        fs::write(&path, "secret").expect("fixture should exist");
        let guard = EphemeralPasswordFile(path.clone());
        assert!(path.exists());
        drop(guard);
        assert!(!path.exists());
        fs::remove_dir_all(root).expect("temporary root should be removed");
    }
}
