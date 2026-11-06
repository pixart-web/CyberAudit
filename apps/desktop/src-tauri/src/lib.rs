mod runtime;

use runtime::{inspect_resources, provision_session_secret, RuntimeLayout, RuntimeStatus};
use tauri::Manager;

#[tauri::command]
fn desktop_runtime_status(app: tauri::AppHandle) -> RuntimeStatus {
    let resources = app
        .path()
        .resource_dir()
        .unwrap_or_else(|_| std::path::PathBuf::new());
    inspect_resources(&resources)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .setup(|app| {
            let data_root = app.path().app_local_data_dir()?;
            let layout = RuntimeLayout::initialize(&data_root)?;
            provision_session_secret(&layout.configuration)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![desktop_runtime_status])
        .run(tauri::generate_context!())
        .expect("CyberAudit desktop runtime failed");
}
