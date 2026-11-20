use cyberaudit_runtime_host::{
    packaged_tool, replace_process, require_regular_file, required_utf8_env, runtime_root,
    validated_port, HostError,
};
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn main() {
    if let Err(error) = run() {
        eprintln!("CyberAudit web runtime error: {error}");
        std::process::exit(78);
    }
}

fn run() -> Result<(), HostError> {
    let root = runtime_root()?;
    let node = packaged_tool(&root, &["node", "bin", "node"])?;
    let server = root.join("web/apps/web/server.js");
    require_regular_file(&server)?;
    let port = validated_port("CYBERAUDIT_WEB_PORT")?;
    let api_url = required_utf8_env("CYBERAUDIT_DESKTOP_API_URL")?;
    validate_loopback_api_url(&api_url)?;
    let session_file = PathBuf::from(cyberaudit_runtime_host::required_env(
        "CYBERAUDIT_DESKTOP_SESSION_FILE",
    )?);
    require_regular_file(&session_file)?;

    let mut command = Command::new(node);
    command
        .arg(server)
        .env_clear()
        .env("NODE_ENV", "production")
        .env("HOSTNAME", "127.0.0.1")
        .env("PORT", port.to_string())
        .env("CYBERAUDIT_DESKTOP_API_URL", api_url)
        .env("CYBERAUDIT_DESKTOP_SESSION_FILE", session_file)
        .env(
            "CYBERAUDIT_DESKTOP_WEB_ORIGIN",
            format!("http://127.0.0.1:{port}"),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    replace_process(command)
}

fn validate_loopback_api_url(value: &str) -> Result<(), HostError> {
    let Some(port) = value
        .strip_prefix("http://127.0.0.1:")
        .and_then(|rest| rest.strip_suffix("/api/v1"))
    else {
        return Err(HostError::InvalidConfiguration(
            "CYBERAUDIT_DESKTOP_API_URL",
        ));
    };
    let port = port
        .parse::<u16>()
        .map_err(|_| HostError::InvalidConfiguration("CYBERAUDIT_DESKTOP_API_URL"))?;
    if port < 1024 {
        return Err(HostError::InvalidConfiguration(
            "CYBERAUDIT_DESKTOP_API_URL",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_the_exact_loopback_api_origin_and_prefix() {
        assert!(validate_loopback_api_url("http://127.0.0.1:18000/api/v1").is_ok());
        assert!(validate_loopback_api_url("http://localhost:18000/api/v1").is_err());
        assert!(validate_loopback_api_url("https://127.0.0.1:18000/api/v1").is_err());
        assert!(validate_loopback_api_url("http://127.0.0.1:80/api/v1").is_err());
        assert!(validate_loopback_api_url("http://127.0.0.1:18000/other").is_err());
    }
}
