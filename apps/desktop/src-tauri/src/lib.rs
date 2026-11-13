pub mod runtime;
pub mod secrets;
pub mod supervisor;

use runtime::{inspect_resources, provision_session_secret, RuntimeLayout};
use secrets::{provision_installation_secrets, OsSecretStore};
use serde::Serialize;
use std::path::PathBuf;
#[cfg(unix)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;
use supervisor::RuntimeSupervisor;
use tauri::{Manager, State};

#[derive(Clone, Serialize)]
struct DesktopRuntimeStatus {
    ready: bool,
    state: String,
    missing_resources: Vec<String>,
    invalid_resources: Vec<String>,
    message: Option<String>,
    web_url: Option<String>,
}

impl DesktopRuntimeStatus {
    fn starting() -> Self {
        Self {
            ready: false,
            state: "verifying_resources".to_owned(),
            missing_resources: Vec::new(),
            invalid_resources: Vec::new(),
            message: None,
            web_url: None,
        }
    }

    fn failed(message: impl Into<String>) -> Self {
        Self {
            ready: false,
            state: "failed".to_owned(),
            missing_resources: Vec::new(),
            invalid_resources: Vec::new(),
            message: Some(message.into()),
            web_url: None,
        }
    }

    fn resources_verified() -> Self {
        Self {
            ready: false,
            state: "resources_verified".to_owned(),
            missing_resources: Vec::new(),
            invalid_resources: Vec::new(),
            message: None,
            web_url: None,
        }
    }
}

type SharedRuntimeStatus = Arc<Mutex<DesktopRuntimeStatus>>;

struct SupervisorControl {
    sender: Mutex<mpsc::Sender<SupervisorCommand>>,
}

enum SupervisorCommand {
    Stop(Option<mpsc::SyncSender<()>>),
}

impl SupervisorControl {
    fn stop(&self) {
        if let Ok(sender) = self.sender.lock() {
            let _ = sender.send(SupervisorCommand::Stop(None));
        }
    }
}

#[cfg(unix)]
static TERMINATION_REQUESTED: AtomicBool = AtomicBool::new(false);

#[cfg(unix)]
extern "C" fn request_termination(_signal: libc::c_int) {
    TERMINATION_REQUESTED.store(true, Ordering::Release);
}

#[cfg(unix)]
fn install_termination_handlers() -> Result<(), std::io::Error> {
    for signal in [libc::SIGTERM, libc::SIGINT] {
        let previous = unsafe { libc::signal(signal, request_termination as libc::sighandler_t) };
        if previous == libc::SIG_ERR {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(unix)]
fn spawn_termination_watcher(
    app: tauri::AppHandle,
    sender: mpsc::Sender<SupervisorCommand>,
) -> Result<(), std::io::Error> {
    thread::Builder::new()
        .name("cyberaudit-termination-watcher".to_owned())
        .spawn(move || loop {
            if TERMINATION_REQUESTED.swap(false, Ordering::AcqRel) {
                let (completion_sender, completion_receiver) = mpsc::sync_channel(1);
                if sender
                    .send(SupervisorCommand::Stop(Some(completion_sender)))
                    .is_ok()
                {
                    let _ = completion_receiver.recv_timeout(Duration::from_secs(30));
                }
                app.exit(0);
                break;
            }
            thread::sleep(Duration::from_millis(100));
        })?;
    Ok(())
}

#[tauri::command]
fn desktop_runtime_status(status: State<'_, SharedRuntimeStatus>) -> DesktopRuntimeStatus {
    status
        .lock()
        .map(|value| value.clone())
        .unwrap_or_else(|_| DesktopRuntimeStatus::failed("runtime status is unavailable"))
}

fn configured_resource_directory(app: &tauri::AppHandle) -> Result<PathBuf, String> {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os("CYBERAUDIT_DESKTOP_RESOURCE_DIR") {
        return Ok(PathBuf::from(path));
    }
    app.path()
        .resource_dir()
        .map_err(|_| "desktop resource directory is unavailable".to_owned())
}

fn update_status(status: &SharedRuntimeStatus, value: DesktopRuntimeStatus) {
    if let Ok(mut current) = status.lock() {
        *current = value;
    }
}

fn launch_runtime(
    app: tauri::AppHandle,
    resource_directory: PathBuf,
    layout: RuntimeLayout,
    session_file: PathBuf,
    status: SharedRuntimeStatus,
    receiver: mpsc::Receiver<SupervisorCommand>,
) {
    let resources = inspect_resources(&resource_directory);
    if !resources.ready {
        update_status(
            &status,
            DesktopRuntimeStatus {
                ready: false,
                state: resources.state.to_owned(),
                missing_resources: resources.missing_resources,
                invalid_resources: resources.invalid_resources,
                message: Some("runtime resources failed integrity verification".to_owned()),
                web_url: None,
            },
        );
        return;
    }
    update_status(&status, DesktopRuntimeStatus::resources_verified());
    let secrets = match provision_installation_secrets(&OsSecretStore) {
        Ok(value) => value,
        Err(_) => {
            update_status(
                &status,
                DesktopRuntimeStatus::failed("operating-system credential storage is unavailable"),
            );
            return;
        }
    };
    let mut supervisor =
        match RuntimeSupervisor::start(&resource_directory, &layout, &session_file, &secrets) {
            Ok(value) => value,
            Err(error) => {
                update_status(&status, DesktopRuntimeStatus::failed(error.to_string()));
                return;
            }
        };
    let url = format!("http://127.0.0.1:{}/setup", supervisor.ports().web);
    update_status(
        &status,
        DesktopRuntimeStatus {
            ready: true,
            state: "ready".to_owned(),
            missing_resources: Vec::new(),
            invalid_resources: Vec::new(),
            message: None,
            web_url: Some(url.clone()),
        },
    );
    if let Some(window) = app.get_webview_window("main") {
        if let Ok(parsed) = url.parse() {
            let _ = window.navigate(parsed);
        }
    }

    loop {
        match receiver.recv_timeout(Duration::from_millis(500)) {
            Ok(SupervisorCommand::Stop(completion)) => {
                let _ = supervisor.stop();
                if let Some(sender) = completion {
                    let _ = sender.send(());
                }
                break;
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                let _ = supervisor.stop();
                break;
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if let Err(error) = supervisor.monitor_once() {
                    update_status(&status, DesktopRuntimeStatus::failed(error.to_string()));
                    let _ = supervisor.stop();
                    break;
                }
            }
        }
    }
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    #[cfg(unix)]
    install_termination_handlers().expect("CyberAudit termination handlers failed to initialize");
    let status = Arc::new(Mutex::new(DesktopRuntimeStatus::starting()));
    let command_status = Arc::clone(&status);
    let (sender, receiver) = mpsc::channel();
    #[cfg(unix)]
    let termination_sender = sender.clone();
    let builder = tauri::Builder::default()
        .manage(command_status)
        .manage(SupervisorControl {
            sender: Mutex::new(sender),
        })
        .setup(move |app| {
            #[cfg(unix)]
            spawn_termination_watcher(app.handle().clone(), termination_sender)?;
            let data_root = app.path().app_local_data_dir()?;
            let layout = RuntimeLayout::initialize(&data_root)?;
            let session_file = provision_session_secret(&layout.configuration)?;
            let resource_directory =
                configured_resource_directory(app.handle()).map_err(std::io::Error::other)?;
            let app_handle = app.handle().clone();
            let runtime_status = Arc::clone(&status);
            thread::Builder::new()
                .name("cyberaudit-runtime-supervisor".to_owned())
                .spawn(move || {
                    launch_runtime(
                        app_handle,
                        resource_directory,
                        layout,
                        session_file,
                        runtime_status,
                        receiver,
                    );
                })?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![desktop_runtime_status]);
    let app = builder
        .build(tauri::generate_context!())
        .expect("CyberAudit desktop shell failed to initialize");
    app.run(|app, event| {
        if matches!(event, tauri::RunEvent::ExitRequested { .. }) {
            app.state::<SupervisorControl>().stop();
        }
    });
}
