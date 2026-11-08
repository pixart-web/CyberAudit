use std::ffi::OsString;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, ExitStatus};

pub const DATABASE_OWNER_USER: &str = "cyberaudit";
pub const DATABASE_APPLICATION_USER: &str = "cyberaudit_app";
pub const DATABASE_RUNTIME_ROLE: &str = "cyberaudit_runtime";
pub const DATABASE_NAME: &str = "cyberaudit";

pub fn runtime_root() -> Result<PathBuf, HostError> {
    runtime_root_from_executable(&std::env::current_exe().map_err(HostError::CurrentExecutable)?)
}

pub fn runtime_root_from_executable(executable: &Path) -> Result<PathBuf, HostError> {
    let binary_directory = executable.parent().ok_or(HostError::InvalidRuntimeLayout)?;
    if binary_directory
        .file_name()
        .and_then(|value| value.to_str())
        != Some("bin")
    {
        return Err(HostError::InvalidRuntimeLayout);
    }
    binary_directory
        .parent()
        .map(Path::to_path_buf)
        .ok_or(HostError::InvalidRuntimeLayout)
}

pub fn packaged_tool(root: &Path, relative: &[&str]) -> Result<PathBuf, HostError> {
    let mut path = root.join("tools");
    for component in relative {
        if component.is_empty()
            || component.contains(['/', '\\'])
            || matches!(*component, "." | "..")
        {
            return Err(HostError::InvalidRuntimeLayout);
        }
        path.push(component);
    }
    if cfg!(windows) {
        path.set_extension("exe");
    }
    require_regular_file(&path)?;
    Ok(path)
}

pub fn require_regular_file(path: &Path) -> Result<(), HostError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| HostError::MissingRuntimeResource)?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(HostError::MissingRuntimeResource);
    }
    Ok(())
}

pub fn required_env(name: &'static str) -> Result<OsString, HostError> {
    std::env::var_os(name).ok_or(HostError::MissingConfiguration(name))
}

pub fn required_utf8_env(name: &'static str) -> Result<String, HostError> {
    required_env(name)?
        .into_string()
        .map_err(|_| HostError::InvalidConfiguration(name))
}

pub fn validated_port(name: &'static str) -> Result<u16, HostError> {
    let value = required_utf8_env(name)?
        .parse::<u16>()
        .map_err(|_| HostError::InvalidConfiguration(name))?;
    if value < 1024 {
        return Err(HostError::InvalidConfiguration(name));
    }
    Ok(value)
}

pub fn validated_secret(name: &'static str) -> Result<String, HostError> {
    let value = required_utf8_env(name)?;
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(HostError::InvalidConfiguration(name));
    }
    Ok(value)
}

pub fn validated_directory(name: &'static str) -> Result<PathBuf, HostError> {
    let path = PathBuf::from(required_env(name)?);
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::ParentDir | Component::CurDir))
    {
        return Err(HostError::InvalidConfiguration(name));
    }
    fs::create_dir_all(&path).map_err(HostError::Io)?;
    let metadata = fs::symlink_metadata(&path).map_err(HostError::Io)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(HostError::InvalidConfiguration(name));
    }
    restrict_directory(&path)?;
    Ok(path)
}

#[cfg(unix)]
pub fn replace_process(mut command: Command) -> Result<(), HostError> {
    use std::os::unix::process::CommandExt;
    Err(HostError::ProcessExec(command.exec()))
}

#[cfg(windows)]
pub fn replace_process(mut command: Command) -> Result<(), HostError> {
    let status = command.status().map_err(HostError::ProcessStart)?;
    require_success(status)
}

pub fn require_success(status: ExitStatus) -> Result<(), HostError> {
    if status.success() {
        Ok(())
    } else {
        Err(HostError::ProcessFailed(status.code()))
    }
}

pub fn random_hex(bytes: usize) -> Result<String, HostError> {
    let mut value = vec![0_u8; bytes];
    getrandom::fill(&mut value).map_err(|_| HostError::Random)?;
    Ok(value
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>())
}

#[cfg(unix)]
pub fn restrict_directory(path: &Path) -> Result<(), HostError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700)).map_err(HostError::Io)
}

#[cfg(not(unix))]
pub fn restrict_directory(_path: &Path) -> Result<(), HostError> {
    Ok(())
}

#[cfg(unix)]
pub fn restrict_file(path: &Path) -> Result<(), HostError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(HostError::Io)
}

#[cfg(not(unix))]
pub fn restrict_file(_path: &Path) -> Result<(), HostError> {
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum HostError {
    #[error("the runtime executable location is invalid")]
    InvalidRuntimeLayout,
    #[error("a required packaged runtime resource is unavailable")]
    MissingRuntimeResource,
    #[error("required runtime configuration {0} is missing")]
    MissingConfiguration(&'static str),
    #[error("runtime configuration {0} is invalid")]
    InvalidConfiguration(&'static str),
    #[error("unable to access a private runtime path")]
    Io(#[source] std::io::Error),
    #[error("unable to resolve the runtime executable")]
    CurrentExecutable(#[source] std::io::Error),
    #[error("unable to start a packaged runtime process")]
    ProcessStart(#[source] std::io::Error),
    #[error("unable to replace the runtime host process")]
    ProcessExec(#[source] std::io::Error),
    #[error("packaged runtime process failed with code {0:?}")]
    ProcessFailed(Option<i32>),
    #[error("secure random generation failed")]
    Random,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "cyberaudit-runtime-host-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("valid system time")
                .as_nanos()
        ))
    }

    #[test]
    fn resolves_runtime_root_only_from_the_fixed_bin_directory() {
        let root = temp_root();
        assert_eq!(
            runtime_root_from_executable(&root.join("bin/cyberaudit-web")).expect("valid layout"),
            root
        );
        assert!(runtime_root_from_executable(&PathBuf::from("/tmp/cyberaudit-web")).is_err());
    }

    #[test]
    fn packaged_tools_cannot_escape_the_tools_directory() {
        let root = temp_root();
        assert!(matches!(
            packaged_tool(&root, &["..", "outside"]),
            Err(HostError::InvalidRuntimeLayout)
        ));
        assert!(matches!(
            packaged_tool(&root, &["node/../../outside"]),
            Err(HostError::InvalidRuntimeLayout)
        ));
    }

    #[test]
    fn random_values_are_fixed_length_and_distinct() {
        let first = random_hex(32).expect("random value");
        let second = random_hex(32).expect("random value");
        assert_eq!(first.len(), 64);
        assert_eq!(second.len(), 64);
        assert_ne!(first, second);
    }
}
