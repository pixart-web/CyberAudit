use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::runtime::RuntimeLayout;
use crate::supervisor::SingleInstanceGuard;

const BACKUP_FORMAT_VERSION: u32 = 1;
const MAX_BACKUP_FILES: usize = 250_000;
const COPY_BUFFER_SIZE: usize = 1024 * 1024;
const COMPONENTS: [&str; 5] = [
    "configuration",
    "database",
    "evidence",
    "models",
    "knowledge-packs",
];

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupManifest {
    pub format_version: u32,
    pub product_version: String,
    pub created_at_unix: u64,
    pub files: Vec<BackupFile>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackupFile {
    pub path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

pub fn create_offline_backup(
    layout: &RuntimeLayout,
    destination: &Path,
) -> Result<BackupManifest, BackupError> {
    require_absolute_destination(destination)?;
    if destination.exists() {
        return Err(BackupError::DestinationExists);
    }
    let _runtime_guard = SingleInstanceGuard::acquire(&layout.configuration)
        .map_err(|_| BackupError::RuntimeActive)?;
    if layout.database.join("postmaster.pid").exists() {
        return Err(BackupError::RuntimeActive);
    }
    let parent = destination.parent().ok_or(BackupError::UnsafePath)?;
    fs::create_dir_all(parent)?;
    let staging = unique_staging_path(parent, destination)?;
    fs::create_dir(&staging)?;
    restrict_directory(&staging)?;

    let result = (|| {
        let data_root = staging.join("data");
        fs::create_dir(&data_root)?;
        restrict_directory(&data_root)?;
        let mut files = Vec::new();
        for component in COMPONENTS {
            let source = component_path(layout, component);
            copy_component(source, component, &data_root, &mut files)?;
        }
        files.sort_by(|left, right| left.path.cmp(&right.path));
        let manifest = BackupManifest {
            format_version: BACKUP_FORMAT_VERSION,
            product_version: env!("CARGO_PKG_VERSION").to_owned(),
            created_at_unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| BackupError::Clock)?
                .as_secs(),
            files,
        };
        write_manifest(&staging.join("manifest.json"), &manifest)?;
        verify_backup(&staging)?;
        fs::rename(&staging, destination)?;
        Ok(manifest)
    })();

    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

pub fn restore_offline_backup(
    backup: &Path,
    destination: &Path,
) -> Result<BackupManifest, BackupError> {
    require_absolute_destination(destination)?;
    if destination.exists() {
        return Err(BackupError::DestinationExists);
    }
    let manifest = verify_backup(backup)?;
    if manifest.product_version != env!("CARGO_PKG_VERSION") {
        return Err(BackupError::IncompatibleVersion);
    }
    let parent = destination.parent().ok_or(BackupError::UnsafePath)?;
    fs::create_dir_all(parent)?;
    let staging = unique_staging_path(parent, destination)?;
    fs::create_dir(&staging)?;
    restrict_directory(&staging)?;

    let result = (|| {
        for file in &manifest.files {
            let relative = safe_relative_path(&file.path)?;
            let source = backup.join("data").join(&relative);
            let output = staging.join(&relative);
            if let Some(directory) = output.parent() {
                fs::create_dir_all(directory)?;
                restrict_directory(directory)?;
            }
            copy_regular_file(&source, &output)?;
            restrict_file(&output)?;
            if file_digest(&output)? != file.sha256 {
                return Err(BackupError::Integrity);
            }
        }
        fs::rename(&staging, destination)?;
        Ok(manifest.clone())
    })();

    if result.is_err() {
        let _ = fs::remove_dir_all(&staging);
    }
    result
}

pub fn verify_backup(root: &Path) -> Result<BackupManifest, BackupError> {
    let manifest_path = root.join("manifest.json");
    require_regular_nonsymlink(&manifest_path)?;
    let manifest: BackupManifest =
        serde_json::from_reader(BufReader::new(File::open(manifest_path)?))?;
    if manifest.format_version != BACKUP_FORMAT_VERSION || manifest.files.len() > MAX_BACKUP_FILES {
        return Err(BackupError::InvalidManifest);
    }
    let mut previous: Option<&str> = None;
    for file in &manifest.files {
        if previous.is_some_and(|value| value >= file.path.as_str()) || !valid_sha256(&file.sha256)
        {
            return Err(BackupError::InvalidManifest);
        }
        previous = Some(&file.path);
        let relative = safe_relative_path(&file.path)?;
        if !COMPONENTS.iter().any(|component| {
            relative
                .components()
                .next()
                .is_some_and(|part| part.as_os_str() == *component)
        }) {
            return Err(BackupError::InvalidManifest);
        }
        let path = root.join("data").join(relative);
        require_regular_nonsymlink(&path)?;
        let metadata = path.metadata()?;
        if metadata.len() != file.size_bytes || file_digest(&path)? != file.sha256 {
            return Err(BackupError::Integrity);
        }
    }
    let mut actual = Vec::new();
    collect_relative_files(&root.join("data"), &root.join("data"), &mut actual)?;
    actual.sort();
    if actual
        != manifest
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect::<Vec<_>>()
    {
        return Err(BackupError::Integrity);
    }
    Ok(manifest)
}

fn copy_component(
    source: &Path,
    component: &str,
    destination: &Path,
    files: &mut Vec<BackupFile>,
) -> Result<(), BackupError> {
    if !source.is_dir() {
        return Ok(());
    }
    copy_tree(source, source, component, destination, files)
}

fn copy_tree(
    root: &Path,
    directory: &Path,
    component: &str,
    destination: &Path,
    files: &mut Vec<BackupFile>,
) -> Result<(), BackupError> {
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let source = entry.path();
        let metadata = fs::symlink_metadata(&source)?;
        if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
            return Err(BackupError::UnsafeTree);
        }
        if metadata.is_dir() {
            copy_tree(root, &source, component, destination, files)?;
            continue;
        }
        let relative = source
            .strip_prefix(root)
            .map_err(|_| BackupError::UnsafePath)?;
        if component == "configuration"
            && matches!(relative.to_str(), Some("desktop-session" | "runtime.lock"))
        {
            continue;
        }
        if files.len() >= MAX_BACKUP_FILES {
            return Err(BackupError::TooManyFiles);
        }
        let backup_relative = Path::new(component).join(relative);
        let output = destination.join(&backup_relative);
        if let Some(parent) = output.parent() {
            fs::create_dir_all(parent)?;
            restrict_directory(parent)?;
        }
        copy_regular_file(&source, &output)?;
        restrict_file(&output)?;
        files.push(BackupFile {
            path: portable_path(&backup_relative)?,
            size_bytes: output.metadata()?.len(),
            sha256: file_digest(&output)?,
        });
    }
    Ok(())
}

fn collect_relative_files(
    root: &Path,
    directory: &Path,
    files: &mut Vec<String>,
) -> Result<(), BackupError> {
    if !directory.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
            return Err(BackupError::UnsafeTree);
        }
        if metadata.is_dir() {
            collect_relative_files(root, &path, files)?;
        } else {
            files.push(portable_path(
                path.strip_prefix(root)
                    .map_err(|_| BackupError::UnsafePath)?,
            )?);
        }
    }
    Ok(())
}

fn component_path<'a>(layout: &'a RuntimeLayout, component: &str) -> &'a Path {
    match component {
        "configuration" => &layout.configuration,
        "database" => &layout.database,
        "evidence" => &layout.evidence,
        "models" => &layout.models,
        "knowledge-packs" => &layout.knowledge_packs,
        _ => unreachable!("components are fixed at compile time"),
    }
}

fn write_manifest(path: &Path, manifest: &BackupManifest) -> Result<(), BackupError> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    serde_json::to_writer_pretty(&mut file, manifest)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    Ok(())
}

fn copy_regular_file(source: &Path, destination: &Path) -> Result<(), BackupError> {
    require_regular_nonsymlink(source)?;
    let mut input = File::open(source)?;
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options.open(destination)?;
    let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        output.write_all(&buffer[..read])?;
    }
    output.sync_all()?;
    Ok(())
}

fn file_digest(path: &Path) -> Result<String, BackupError> {
    let mut input = File::open(path)?;
    let mut hash = Sha256::new();
    let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];
    loop {
        let read = input.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hash.update(&buffer[..read]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

fn unique_staging_path(parent: &Path, destination: &Path) -> Result<PathBuf, BackupError> {
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|_| BackupError::Random)?;
    let suffix = random
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or(BackupError::UnsafePath)?;
    Ok(parent.join(format!(".{name}.staging-{suffix}")))
}

fn safe_relative_path(value: &str) -> Result<PathBuf, BackupError> {
    if value.is_empty() || value.contains('\\') {
        return Err(BackupError::UnsafePath);
    }
    let path = PathBuf::from(value);
    if path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(BackupError::UnsafePath);
    }
    Ok(path)
}

fn portable_path(path: &Path) -> Result<String, BackupError> {
    let components = path
        .components()
        .map(|part| match part {
            Component::Normal(value) => value.to_str().ok_or(BackupError::UnsafePath),
            _ => Err(BackupError::UnsafePath),
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(components.join("/"))
}

fn require_absolute_destination(path: &Path) -> Result<(), BackupError> {
    if !path.is_absolute() || path.parent().is_none() {
        return Err(BackupError::UnsafePath);
    }
    Ok(())
}

fn require_regular_nonsymlink(path: &Path) -> Result<(), BackupError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(BackupError::UnsafeTree);
    }
    Ok(())
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|value| value.is_ascii_hexdigit())
}

#[cfg(unix)]
fn restrict_directory(path: &Path) -> Result<(), BackupError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_directory(_path: &Path) -> Result<(), BackupError> {
    Ok(())
}

#[cfg(unix)]
fn restrict_file(path: &Path) -> Result<(), BackupError> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file(_path: &Path) -> Result<(), BackupError> {
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum BackupError {
    #[error("backup destination already exists")]
    DestinationExists,
    #[error("the desktop runtime must be stopped before backup")]
    RuntimeActive,
    #[error("backup format is not compatible with this application version")]
    IncompatibleVersion,
    #[error("backup contains an unsafe path")]
    UnsafePath,
    #[error("backup contains a symbolic link or special file")]
    UnsafeTree,
    #[error("backup manifest is invalid")]
    InvalidManifest,
    #[error("backup integrity verification failed")]
    Integrity,
    #[error("backup contains too many files")]
    TooManyFiles,
    #[error("secure random generation failed")]
    Random,
    #[error("system clock is unavailable")]
    Clock,
    #[error("backup I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("backup manifest could not be decoded: {0}")]
    Manifest(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).expect("fixture randomness should be available");
        std::env::temp_dir().join(format!(
            "cyberaudit-backup-{name}-{}",
            random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ))
    }

    #[test]
    fn backup_and_restore_preserve_data_and_exclude_session_capability() {
        let root = fixture("roundtrip");
        let source_root = root.join("source");
        let layout = RuntimeLayout::initialize(&source_root).expect("layout should initialize");
        fs::write(layout.database.join("PG_VERSION"), "16").expect("database fixture");
        fs::write(layout.evidence.join("evidence.pdf"), b"safe fixture").expect("evidence fixture");
        fs::write(
            layout.configuration.join("desktop-session"),
            "ephemeral-secret",
        )
        .expect("session fixture");
        fs::write(layout.configuration.join("preferences.json"), "{}")
            .expect("configuration fixture");
        let backup = root.join("backup");
        let restored = root.join("restored");

        let manifest = create_offline_backup(&layout, &backup).expect("backup should succeed");
        assert!(manifest.files.iter().all(|file| {
            !file.path.contains("desktop-session") && !file.path.contains("runtime.lock")
        }));
        restore_offline_backup(&backup, &restored).expect("restore should succeed");

        assert_eq!(
            fs::read_to_string(restored.join("database/PG_VERSION")).unwrap(),
            "16"
        );
        assert_eq!(
            fs::read(restored.join("evidence/evidence.pdf")).unwrap(),
            b"safe fixture"
        );
        assert!(!restored.join("configuration/desktop-session").exists());
        fs::remove_dir_all(root).expect("fixture cleanup");
    }

    #[test]
    fn corrupted_backup_never_creates_restore_destination() {
        let root = fixture("corrupt");
        let source_root = root.join("source");
        let layout = RuntimeLayout::initialize(&source_root).expect("layout should initialize");
        fs::write(layout.database.join("PG_VERSION"), "16").expect("database fixture");
        let backup = root.join("backup");
        create_offline_backup(&layout, &backup).expect("backup should succeed");
        fs::write(backup.join("data/database/PG_VERSION"), "corrupt").expect("corruption fixture");
        let restored = root.join("restored");

        let result = restore_offline_backup(&backup, &restored);

        assert!(matches!(result, Err(BackupError::Integrity)));
        assert!(!restored.exists());
        fs::remove_dir_all(root).expect("fixture cleanup");
    }

    #[test]
    fn restore_refuses_to_overwrite_existing_data() {
        let root = fixture("overwrite");
        let source_root = root.join("source");
        let layout = RuntimeLayout::initialize(&source_root).expect("layout should initialize");
        fs::write(layout.database.join("PG_VERSION"), "16").expect("database fixture");
        let backup = root.join("backup");
        create_offline_backup(&layout, &backup).expect("backup should succeed");
        let restored = root.join("restored");
        fs::create_dir_all(&restored).expect("destination fixture");
        fs::write(restored.join("customer-data"), "preserve").expect("customer fixture");

        let result = restore_offline_backup(&backup, &restored);

        assert!(matches!(result, Err(BackupError::DestinationExists)));
        assert_eq!(
            fs::read_to_string(restored.join("customer-data")).unwrap(),
            "preserve"
        );
        fs::remove_dir_all(root).expect("fixture cleanup");
    }

    #[test]
    fn active_postgresql_blocks_offline_backup() {
        let root = fixture("active");
        let source_root = root.join("source");
        let layout = RuntimeLayout::initialize(&source_root).expect("layout should initialize");
        fs::write(layout.database.join("postmaster.pid"), "123").expect("pid fixture");

        let result = create_offline_backup(&layout, &root.join("backup"));

        assert!(matches!(result, Err(BackupError::RuntimeActive)));
        fs::remove_dir_all(root).expect("fixture cleanup");
    }

    #[test]
    fn restore_rejects_an_incompatible_product_version() {
        let root = fixture("version");
        let source_root = root.join("source");
        let layout = RuntimeLayout::initialize(&source_root).expect("layout should initialize");
        fs::write(layout.database.join("PG_VERSION"), "16").expect("database fixture");
        let backup = root.join("backup");
        create_offline_backup(&layout, &backup).expect("backup should succeed");
        let manifest_path = backup.join("manifest.json");
        let mut manifest: BackupManifest = serde_json::from_reader(
            File::open(&manifest_path).expect("manifest should be readable"),
        )
        .expect("manifest should decode");
        manifest.product_version = "999.0.0".to_owned();
        fs::remove_file(&manifest_path).expect("manifest fixture should be replaceable");
        write_manifest(&manifest_path, &manifest).expect("manifest fixture should be written");
        let restored = root.join("restored");

        let result = restore_offline_backup(&backup, &restored);

        assert!(matches!(result, Err(BackupError::IncompatibleVersion)));
        assert!(!restored.exists());
        fs::remove_dir_all(root).expect("fixture cleanup");
    }
}
