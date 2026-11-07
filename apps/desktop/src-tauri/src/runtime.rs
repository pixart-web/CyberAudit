use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};

const REQUIRED_SIDECARS: [&str; 5] = [
    "cyberaudit-postgres",
    "cyberaudit-valkey",
    "cyberaudit-api",
    "cyberaudit-worker",
    "cyberaudit-web",
];
const MAX_RUNTIME_RESOURCES: usize = 100_000;

#[derive(Debug, Clone)]
pub struct RuntimeLayout {
    pub configuration: PathBuf,
    pub database: PathBuf,
    pub evidence: PathBuf,
    pub models: PathBuf,
    pub knowledge_packs: PathBuf,
    pub logs: PathBuf,
    pub backups: PathBuf,
    pub temporary: PathBuf,
}

impl RuntimeLayout {
    pub fn initialize(root: &Path) -> Result<Self, RuntimeError> {
        let layout = Self {
            configuration: root.join("configuration"),
            database: root.join("database"),
            evidence: root.join("evidence"),
            models: root.join("models"),
            knowledge_packs: root.join("knowledge-packs"),
            logs: root.join("logs"),
            backups: root.join("backups"),
            temporary: root.join("temporary"),
        };
        for directory in layout.directories() {
            fs::create_dir_all(directory)?;
            restrict_directory(directory)?;
        }
        Ok(layout)
    }

    fn directories(&self) -> [&Path; 8] {
        [
            &self.configuration,
            &self.database,
            &self.evidence,
            &self.models,
            &self.knowledge_packs,
            &self.logs,
            &self.backups,
            &self.temporary,
        ]
    }
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<(), RuntimeError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> Result<(), RuntimeError> {
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct RuntimeStatus {
    pub ready: bool,
    pub state: &'static str,
    pub missing_resources: Vec<String>,
    pub invalid_resources: Vec<String>,
}

pub fn inspect_resources(resource_root: &Path) -> RuntimeStatus {
    let runtime_root = resource_root.join("runtime");
    let binary_root = runtime_root.join("bin");
    let manifest_path = runtime_root.join("manifest.json");
    let mut missing_resources = REQUIRED_SIDECARS
        .iter()
        .filter(|name| !is_regular_nonsymlink(&binary_root.join(executable_name(name))))
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    let mut invalid_resources = Vec::new();

    if !manifest_path.is_file() {
        missing_resources.push("manifest.json".to_owned());
    } else {
        match load_manifest(&manifest_path) {
            Ok(manifest) => verify_manifest(&runtime_root, &manifest, &mut invalid_resources),
            Err(_) => invalid_resources.push("manifest.json".to_owned()),
        }
    }
    missing_resources.sort();
    invalid_resources.sort();
    let ready = missing_resources.is_empty() && invalid_resources.is_empty();
    RuntimeStatus {
        ready,
        state: if ready {
            "resources_verified"
        } else {
            "resources_invalid"
        },
        missing_resources,
        invalid_resources,
    }
}

fn is_regular_nonsymlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeManifest {
    version: u32,
    resources: Vec<ManifestResource>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestResource {
    path: String,
    sha256: String,
}

fn load_manifest(path: &Path) -> Result<RuntimeManifest, RuntimeError> {
    let file = File::open(path)?;
    let manifest: RuntimeManifest = serde_json::from_reader(BufReader::new(file))?;
    if manifest.version != 2 || manifest.resources.len() > MAX_RUNTIME_RESOURCES {
        return Err(RuntimeError::InvalidManifest);
    }
    Ok(manifest)
}

fn verify_manifest(
    runtime_root: &Path,
    manifest: &RuntimeManifest,
    invalid_resources: &mut Vec<String>,
) {
    let required = REQUIRED_SIDECARS
        .iter()
        .map(|name| (format!("bin/{}", executable_name(name)), *name))
        .collect::<HashMap<_, _>>();
    let mut seen = HashSet::new();
    for resource in &manifest.resources {
        if !safe_manifest_path(&resource.path)
            || !seen.insert(resource.path.clone())
            || !valid_sha256(&resource.sha256)
        {
            invalid_resources.push(display_resource(&resource.path, &required));
            continue;
        }
        let path = join_manifest_path(runtime_root, &resource.path);
        if !is_regular_nonsymlink(&path) {
            invalid_resources.push(display_resource(&resource.path, &required));
            continue;
        }
        match sha256_file(&path) {
            Ok(actual) if actual == resource.sha256.to_ascii_lowercase() => {}
            _ => invalid_resources.push(display_resource(&resource.path, &required)),
        }
    }
    for (path, display_name) in required {
        if !seen.contains(&path) {
            invalid_resources.push(display_name.to_owned());
        }
    }
    match collect_runtime_files(runtime_root) {
        Ok(actual) => {
            for unexpected in actual.difference(&seen) {
                invalid_resources.push((*unexpected).clone());
            }
        }
        Err(_) => invalid_resources.push("runtime-tree".to_owned()),
    }
    invalid_resources.sort();
    invalid_resources.dedup();
}

fn display_resource(path: &str, required: &HashMap<String, &str>) -> String {
    required
        .get(path)
        .map(|name| (*name).to_owned())
        .unwrap_or_else(|| path.to_owned())
}

fn safe_manifest_path(value: &str) -> bool {
    if value.is_empty() || value.contains('\\') || value == "manifest.json" {
        return false;
    }
    Path::new(value)
        .components()
        .all(|component| matches!(component, Component::Normal(_)))
}

fn join_manifest_path(root: &Path, value: &str) -> PathBuf {
    value
        .split('/')
        .fold(root.to_path_buf(), |path, component| path.join(component))
}

fn collect_runtime_files(runtime_root: &Path) -> Result<HashSet<String>, RuntimeError> {
    let mut files = HashSet::new();
    let mut pending = vec![runtime_root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory)? {
            let entry = entry?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path)?;
            if metadata.file_type().is_symlink() {
                return Err(RuntimeError::UnsafeResourceTree);
            }
            if metadata.is_dir() {
                pending.push(path);
                continue;
            }
            if !metadata.is_file() {
                return Err(RuntimeError::UnsafeResourceTree);
            }
            let relative = path
                .strip_prefix(runtime_root)
                .map_err(|_| RuntimeError::UnsafeResourceTree)?;
            let components = relative
                .components()
                .map(|component| match component {
                    Component::Normal(value) => value.to_str().map(str::to_owned),
                    _ => None,
                })
                .collect::<Option<Vec<_>>>()
                .ok_or(RuntimeError::UnsafeResourceTree)?;
            let manifest_path = components.join("/");
            if manifest_path == "manifest.json" || manifest_path == ".manifest.json.tmp" {
                continue;
            }
            if files.len() >= MAX_RUNTIME_RESOURCES || !files.insert(manifest_path) {
                return Err(RuntimeError::UnsafeResourceTree);
            }
        }
    }
    Ok(files)
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn sha256_file(path: &Path) -> Result<String, RuntimeError> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(format!("{:x}", digest.finalize()))
}

pub fn provision_session_secret(configuration: &Path) -> Result<PathBuf, RuntimeError> {
    let secret_path = configuration.join("desktop-session");
    let mut secret = [0_u8; 32];
    getrandom::fill(&mut secret).map_err(|error| RuntimeError::Random(error.to_string()))?;
    let encoded = secret
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let temporary_path = configuration.join(format!(".desktop-session-{}.tmp", &encoded[..16]));

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&temporary_path)?;
    file.write_all(encoded.as_bytes())?;
    file.sync_all()?;
    #[cfg(windows)]
    if secret_path.exists() {
        fs::remove_file(&secret_path)?;
    }
    fs::rename(&temporary_path, &secret_path)?;
    restrict_secret(&secret_path)?;
    Ok(secret_path)
}

#[cfg(unix)]
fn restrict_secret(path: &Path) -> Result<(), RuntimeError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_secret(_path: &Path) -> Result<(), RuntimeError> {
    Ok(())
}

fn executable_name(name: &str) -> String {
    if cfg!(windows) {
        format!("{name}.exe")
    } else {
        name.to_owned()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("unable to prepare the local runtime directory: {0}")]
    Io(#[from] std::io::Error),
    #[error("runtime manifest is invalid")]
    InvalidManifest,
    #[error("runtime manifest cannot be decoded: {0}")]
    Manifest(#[from] serde_json::Error),
    #[error("runtime resource tree contains an unsafe entry")]
    UnsafeResourceTree,
    #[error("secure random generation failed: {0}")]
    Random(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_root(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "cyberaudit-desktop-{label}-{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock must be after the Unix epoch")
                .as_nanos()
        ))
    }

    fn write_fixture_manifest(root: &Path) -> PathBuf {
        let binary_root = root.join("runtime/bin");
        fs::create_dir_all(&binary_root).expect("resource root should initialize");
        let mut resources = Vec::new();
        for name in REQUIRED_SIDECARS {
            let filename = executable_name(name);
            let path = binary_root.join(&filename);
            fs::write(&path, name.as_bytes()).expect("sidecar fixture should be written");
            resources.push(serde_json::json!({
                "path": format!("bin/{filename}"),
                "sha256": sha256_file(&path).expect("fixture should hash")
            }));
        }
        fs::write(
            root.join("runtime/manifest.json"),
            serde_json::to_vec(&serde_json::json!({
                "version": 2,
                "resources": resources
            }))
            .expect("manifest should encode"),
        )
        .expect("manifest should be written");
        binary_root
    }

    #[test]
    fn creates_separate_mutable_data_directories() {
        let root = temp_root("layout");
        let layout = RuntimeLayout::initialize(&root).expect("layout should initialize");
        for directory in layout.directories() {
            assert!(directory.is_dir());
            assert!(directory.starts_with(&root));
        }
        fs::remove_dir_all(root).expect("temporary layout should be removable");
    }

    #[test]
    fn fails_closed_when_sidecars_are_missing() {
        let root = temp_root("resources");
        fs::create_dir_all(root.join("runtime/bin")).expect("resource root should initialize");
        let status = inspect_resources(&root);
        assert!(!status.ready);
        assert_eq!(status.state, "resources_invalid");
        assert_eq!(status.missing_resources.len(), REQUIRED_SIDECARS.len() + 1);
        assert!(status.invalid_resources.is_empty());
        fs::remove_dir_all(root).expect("temporary resources should be removable");
    }

    #[test]
    fn rejects_a_tampered_sidecar() {
        let root = temp_root("tampered");
        let binary_root = write_fixture_manifest(&root);
        fs::write(
            binary_root.join(executable_name("cyberaudit-api")),
            b"tampered",
        )
        .expect("sidecar should be tampered");

        let status = inspect_resources(&root);
        assert!(!status.ready);
        assert_eq!(status.invalid_resources, vec!["cyberaudit-api"]);
        fs::remove_dir_all(root).expect("temporary resources should be removable");
    }

    #[test]
    fn rejects_an_unmanifested_runtime_dependency() {
        let root = temp_root("unexpected");
        write_fixture_manifest(&root);
        let library = root.join("runtime/tools/postgresql/lib/untrusted-library");
        fs::create_dir_all(library.parent().expect("library should have a parent"))
            .expect("library directory should initialize");
        fs::write(&library, b"not in the manifest").expect("library fixture should be written");

        let status = inspect_resources(&root);

        assert!(!status.ready);
        assert_eq!(
            status.invalid_resources,
            vec!["tools/postgresql/lib/untrusted-library"]
        );
        fs::remove_dir_all(root).expect("temporary resources should be removable");
    }

    #[test]
    fn rotates_the_session_capability() {
        let root = temp_root("session");
        fs::create_dir_all(&root).expect("configuration root should initialize");
        let first_path = provision_session_secret(&root).expect("secret should be provisioned");
        let first = fs::read_to_string(&first_path).expect("secret should be readable");
        let second_path = provision_session_secret(&root).expect("secret should rotate");
        let second = fs::read_to_string(&second_path).expect("secret should be readable");

        assert_eq!(first.len(), 64);
        assert_eq!(second.len(), 64);
        assert_ne!(first, second);
        assert_eq!(first_path, second_path);
        fs::remove_dir_all(root).expect("temporary root should be removable");
    }
}
