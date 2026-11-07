use cyberaudit_runtime_host::{
    packaged_tool, replace_process, runtime_root, validated_directory, validated_port,
    validated_secret, HostError,
};
use os_pipe::pipe;
use std::io::Write;
use std::process::{Command, Stdio};

fn main() {
    if let Err(error) = run() {
        eprintln!("CyberAudit broker runtime error: {error}");
        std::process::exit(78);
    }
}

fn run() -> Result<(), HostError> {
    let root = runtime_root()?;
    let server = packaged_tool(&root, &["valkey", "bin", "valkey-server"])?;
    let data_directory = validated_directory("CYBERAUDIT_BROKER_DIRECTORY")?;
    let port = validated_port("CYBERAUDIT_BROKER_PORT")?;
    let password = validated_secret("CYBERAUDIT_BROKER_PASSWORD")?;
    let directory = quote_config_value(data_directory.to_str().ok_or(
        HostError::InvalidConfiguration("CYBERAUDIT_BROKER_DIRECTORY"),
    )?)?;
    let configuration = format!(
        "bind 127.0.0.1\n\
         protected-mode yes\n\
         port {port}\n\
         daemonize no\n\
         dir {directory}\n\
         dbfilename cyberaudit.rdb\n\
         appendonly yes\n\
         appenddirname cyberaudit-appendonly\n\
         appendfsync everysec\n\
         requirepass {password}\n\
         maxmemory 512mb\n\
         maxmemory-policy noeviction\n\
         enable-protected-configs no\n\
         enable-debug-command no\n\
         enable-module-command no\n\
         hide-user-data-from-log yes\n\
         always-show-logo no\n"
    );
    let (reader, mut writer) = pipe().map_err(HostError::Io)?;
    writer
        .write_all(configuration.as_bytes())
        .map_err(HostError::Io)?;
    drop(writer);

    let mut command = Command::new(server);
    command
        .arg("-")
        .env_clear()
        .stdin(Stdio::from(reader))
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    replace_process(command)
}

fn quote_config_value(value: &str) -> Result<String, HostError> {
    if value.contains(['\0', '\r', '\n']) {
        return Err(HostError::InvalidConfiguration(
            "CYBERAUDIT_BROKER_DIRECTORY",
        ));
    }
    Ok(format!(
        "\"{}\"",
        value.replace('\\', "\\\\").replace('"', "\\\"")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quotes_paths_without_allowing_config_injection() {
        assert_eq!(
            quote_config_value(r#"/Users/Test User/\"data\""#).expect("path should quote"),
            r#""/Users/Test User/\\\"data\\\"""#
        );
        assert!(quote_config_value("/tmp/data\nrequirepass attacker").is_err());
    }
}
