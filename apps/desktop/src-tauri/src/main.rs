use std::path::PathBuf;

use cyberaudit_desktop_lib::backup::{create_offline_backup, restore_offline_backup};
use cyberaudit_desktop_lib::runtime::RuntimeLayout;

fn maintenance_command(arguments: &[String]) -> Result<bool, String> {
    match arguments {
        [command, data_root, destination] if command == "offline-backup" => {
            let data_root = PathBuf::from(data_root);
            let destination = PathBuf::from(destination);
            if !data_root.is_absolute() || !destination.is_absolute() {
                return Err("maintenance paths must be absolute".to_owned());
            }
            let layout = RuntimeLayout::open_existing(&data_root)
                .map_err(|_| "the desktop data directory is unavailable".to_owned())?;
            create_offline_backup(&layout, &destination)
                .map_err(|error| error.to_string())?;
            println!("CyberAudit OS offline backup verified successfully.");
            Ok(true)
        }
        [command, backup, destination] if command == "offline-restore" => {
            let backup = PathBuf::from(backup);
            let destination = PathBuf::from(destination);
            if !backup.is_absolute() || !destination.is_absolute() {
                return Err("maintenance paths must be absolute".to_owned());
            }
            restore_offline_backup(&backup, &destination)
                .map_err(|error| error.to_string())?;
            println!("CyberAudit OS offline restore verified successfully.");
            Ok(true)
        }
        [] => Ok(false),
        [command, ..] if command == "offline-backup" || command == "offline-restore" => Err(
            "usage: cyberaudit-desktop offline-backup <data-root> <backup-destination> | offline-restore <backup> <new-data-root>"
                .to_owned(),
        ),
        _ => Ok(false),
    }
}

fn main() {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match maintenance_command(&arguments) {
        Ok(true) => {}
        Ok(false) => cyberaudit_desktop_lib::run(),
        Err(error) => {
            eprintln!("CyberAudit OS maintenance failed: {error}");
            std::process::exit(2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_gui_arguments_do_not_enter_maintenance_mode() {
        assert!(!maintenance_command(&["-psn_0_123".to_owned()]).expect("GUI argument"));
    }

    #[test]
    fn maintenance_commands_require_exact_absolute_paths() {
        let result = maintenance_command(&[
            "offline-backup".to_owned(),
            "relative-data".to_owned(),
            "relative-backup".to_owned(),
        ]);
        assert!(matches!(result, Err(message) if message.contains("absolute")));
    }
}
