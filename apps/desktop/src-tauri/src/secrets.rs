use keyring::{Entry, Error as KeyringError};

const LEGACY_KEYCHAIN_SERVICE: &str = "com.pixart.cyberaudit.desktop";
const DEVELOPMENT_KEYCHAIN_SERVICE: &str = "com.pixart.cyberaudit.desktop.development.v1";
const PRODUCTION_KEYCHAIN_SERVICE: &str = "com.pixart.cyberaudit.desktop.production.v1";
const SECRET_BYTES: usize = 32;
const SECRET_HEX_LENGTH: usize = SECRET_BYTES * 2;

const DATABASE_PASSWORD: &str = "database-password";
const DATABASE_RUNTIME_PASSWORD: &str = "database-runtime-password";
const BROKER_PASSWORD: &str = "broker-password";
const JWT_SECRET: &str = "jwt-secret";
const ENCRYPTION_KEY: &str = "encryption-key";
const BOOTSTRAP_TOKEN: &str = "bootstrap-token";

pub trait SecretStore {
    fn get(&self, account: &str) -> Result<Option<String>, SecretStoreError>;
    fn set(&self, account: &str, value: &str) -> Result<(), SecretStoreError>;
}

#[derive(Clone, Copy)]
pub struct OsSecretStore {
    service: &'static str,
}

impl OsSecretStore {
    pub fn current() -> Self {
        Self {
            service: if cfg!(debug_assertions) {
                DEVELOPMENT_KEYCHAIN_SERVICE
            } else {
                PRODUCTION_KEYCHAIN_SERVICE
            },
        }
    }

    pub fn legacy() -> Self {
        Self {
            service: LEGACY_KEYCHAIN_SERVICE,
        }
    }
}

impl SecretStore for OsSecretStore {
    fn get(&self, account: &str) -> Result<Option<String>, SecretStoreError> {
        let entry = Entry::new(self.service, account).map_err(map_keyring_error)?;
        match entry.get_password() {
            Ok(value) => Ok(Some(value)),
            Err(KeyringError::NoEntry) => Ok(None),
            Err(error) => Err(map_keyring_error(error)),
        }
    }

    fn set(&self, account: &str, value: &str) -> Result<(), SecretStoreError> {
        let entry = Entry::new(self.service, account).map_err(map_keyring_error)?;
        entry.set_password(value).map_err(map_keyring_error)
    }
}

fn map_keyring_error(error: KeyringError) -> SecretStoreError {
    match error {
        KeyringError::NoEntry => SecretStoreError::NotFound,
        _ => SecretStoreError::Unavailable,
    }
}

#[derive(Clone)]
pub struct InstallationSecrets {
    database_password: String,
    database_runtime_password: String,
    broker_password: String,
    jwt_secret: String,
    encryption_key: String,
    bootstrap_token: String,
}

impl InstallationSecrets {
    pub(crate) fn database_password(&self) -> &str {
        &self.database_password
    }

    pub(crate) fn database_runtime_password(&self) -> &str {
        &self.database_runtime_password
    }

    pub(crate) fn broker_password(&self) -> &str {
        &self.broker_password
    }

    pub(crate) fn jwt_secret(&self) -> &str {
        &self.jwt_secret
    }

    pub(crate) fn encryption_key(&self) -> &str {
        &self.encryption_key
    }

    pub(crate) fn bootstrap_token(&self) -> &str {
        &self.bootstrap_token
    }
}

pub fn provision_installation_secrets(
    store: &dyn SecretStore,
) -> Result<InstallationSecrets, SecretStoreError> {
    Ok(InstallationSecrets {
        database_password: get_or_create(store, DATABASE_PASSWORD)?,
        database_runtime_password: get_or_create(store, DATABASE_RUNTIME_PASSWORD)?,
        broker_password: get_or_create(store, BROKER_PASSWORD)?,
        jwt_secret: get_or_create(store, JWT_SECRET)?,
        encryption_key: get_or_create(store, ENCRYPTION_KEY)?,
        bootstrap_token: get_or_create(store, BOOTSTRAP_TOKEN)?,
    })
}

pub fn resolve_installation_secrets(
    store: &dyn SecretStore,
    persistent_data_exists: bool,
) -> Result<InstallationSecrets, SecretStoreError> {
    match load_installation_secrets(store)? {
        Some(secrets) => Ok(secrets),
        None if persistent_data_exists => Err(SecretStoreError::MigrationRequired),
        None => provision_installation_secrets(store),
    }
}

pub fn migrate_installation_secrets(
    source: &dyn SecretStore,
    destination: &dyn SecretStore,
) -> Result<(), SecretStoreError> {
    let source =
        load_installation_secrets(source)?.ok_or(SecretStoreError::MigrationSourceMissing)?;
    // Validate the complete destination before writing anything. Keychain does not
    // offer multi-item transactions, so this preflight prevents a known conflict
    // from leaving a partially migrated credential set behind.
    for (account, value) in source.entries() {
        match destination.get(account)? {
            Some(existing) if existing == value => {}
            Some(_) => return Err(SecretStoreError::MigrationConflict(account)),
            None => {}
        }
    }
    for (account, value) in source.entries() {
        if destination.get(account)?.is_none() {
            destination.set(account, value)?;
        }
    }
    Ok(())
}

fn load_installation_secrets(
    store: &dyn SecretStore,
) -> Result<Option<InstallationSecrets>, SecretStoreError> {
    let values = [
        (DATABASE_PASSWORD, store.get(DATABASE_PASSWORD)?),
        (
            DATABASE_RUNTIME_PASSWORD,
            store.get(DATABASE_RUNTIME_PASSWORD)?,
        ),
        (BROKER_PASSWORD, store.get(BROKER_PASSWORD)?),
        (JWT_SECRET, store.get(JWT_SECRET)?),
        (ENCRYPTION_KEY, store.get(ENCRYPTION_KEY)?),
        (BOOTSTRAP_TOKEN, store.get(BOOTSTRAP_TOKEN)?),
    ];
    let present = values.iter().filter(|(_, value)| value.is_some()).count();
    if present == 0 {
        return Ok(None);
    }
    if present != values.len() {
        return Err(SecretStoreError::IncompleteCredentialSet);
    }
    for (account, value) in &values {
        if !is_valid_secret(value.as_deref().unwrap_or_default()) {
            return Err(SecretStoreError::InvalidValue(account));
        }
    }
    Ok(Some(InstallationSecrets {
        database_password: values[0].1.clone().unwrap_or_default(),
        database_runtime_password: values[1].1.clone().unwrap_or_default(),
        broker_password: values[2].1.clone().unwrap_or_default(),
        jwt_secret: values[3].1.clone().unwrap_or_default(),
        encryption_key: values[4].1.clone().unwrap_or_default(),
        bootstrap_token: values[5].1.clone().unwrap_or_default(),
    }))
}

impl InstallationSecrets {
    fn entries(&self) -> [(&'static str, &str); 6] {
        [
            (DATABASE_PASSWORD, self.database_password()),
            (DATABASE_RUNTIME_PASSWORD, self.database_runtime_password()),
            (BROKER_PASSWORD, self.broker_password()),
            (JWT_SECRET, self.jwt_secret()),
            (ENCRYPTION_KEY, self.encryption_key()),
            (BOOTSTRAP_TOKEN, self.bootstrap_token()),
        ]
    }
}

fn get_or_create(
    store: &dyn SecretStore,
    account: &'static str,
) -> Result<String, SecretStoreError> {
    if let Some(existing) = store.get(account)? {
        if is_valid_secret(&existing) {
            return Ok(existing);
        }
        return Err(SecretStoreError::InvalidValue(account));
    }

    let value = random_secret()?;
    store.set(account, &value)?;
    Ok(value)
}

fn random_secret() -> Result<String, SecretStoreError> {
    let mut secret = [0_u8; SECRET_BYTES];
    getrandom::fill(&mut secret).map_err(|_| SecretStoreError::Random)?;
    Ok(secret
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>())
}

fn is_valid_secret(value: &str) -> bool {
    value.len() == SECRET_HEX_LENGTH && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SecretStoreError {
    #[error("the requested credential does not exist")]
    NotFound,
    #[error("the operating system credential store is unavailable")]
    Unavailable,
    #[error("credential {0} has an invalid format")]
    InvalidValue(&'static str),
    #[error("the operating-system credential set is incomplete")]
    IncompleteCredentialSet,
    #[error("existing installation data requires explicit credential migration")]
    MigrationRequired,
    #[error("the legacy credential set is unavailable or incomplete")]
    MigrationSourceMissing,
    #[error("credential migration would overwrite a different value for {0}")]
    MigrationConflict(&'static str),
    #[error("secure random generation failed")]
    Random,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    #[derive(Default)]
    struct MemorySecretStore {
        values: Mutex<HashMap<String, String>>,
    }

    impl SecretStore for MemorySecretStore {
        fn get(&self, account: &str) -> Result<Option<String>, SecretStoreError> {
            Ok(self
                .values
                .lock()
                .expect("memory secret store should not be poisoned")
                .get(account)
                .cloned())
        }

        fn set(&self, account: &str, value: &str) -> Result<(), SecretStoreError> {
            self.values
                .lock()
                .expect("memory secret store should not be poisoned")
                .insert(account.to_owned(), value.to_owned());
            Ok(())
        }
    }

    #[test]
    fn provisions_stable_distinct_installation_secrets() {
        let store = MemorySecretStore::default();
        let first = provision_installation_secrets(&store).expect("secrets should provision");
        let second = provision_installation_secrets(&store).expect("secrets should be reused");

        assert_eq!(first.database_password(), second.database_password());
        assert_eq!(
            first.database_runtime_password(),
            second.database_runtime_password()
        );
        assert_eq!(first.broker_password(), second.broker_password());
        assert_eq!(first.jwt_secret(), second.jwt_secret());
        assert_eq!(first.encryption_key(), second.encryption_key());
        assert_eq!(first.bootstrap_token(), second.bootstrap_token());
        assert_ne!(first.database_password(), first.broker_password());
        assert_ne!(first.database_password(), first.database_runtime_password());
        assert!(is_valid_secret(first.jwt_secret()));
    }

    #[test]
    fn refuses_to_rotate_a_malformed_existing_secret() {
        let store = MemorySecretStore::default();
        store
            .set(JWT_SECRET, "short")
            .expect("fixture should be stored");

        let result = provision_installation_secrets(&store);

        assert!(matches!(
            result,
            Err(SecretStoreError::InvalidValue(JWT_SECRET))
        ));
        assert_eq!(
            store.get(JWT_SECRET).expect("fixture should be readable"),
            Some("short".to_owned())
        );
    }

    #[test]
    fn existing_data_never_causes_silent_secret_creation() {
        let store = MemorySecretStore::default();

        let result = resolve_installation_secrets(&store, true);

        assert!(matches!(result, Err(SecretStoreError::MigrationRequired)));
        assert!(store.values.lock().expect("store lock").is_empty());
    }

    #[test]
    fn clean_installation_gets_a_complete_credential_set() {
        let store = MemorySecretStore::default();

        let secrets = resolve_installation_secrets(&store, false)
            .expect("clean installation secrets should provision");

        assert!(is_valid_secret(secrets.database_password()));
        assert_eq!(
            store.values.lock().expect("store lock").len(),
            secrets.entries().len()
        );
    }

    #[test]
    fn migration_copies_without_deleting_or_rotating_the_source() {
        let source = MemorySecretStore::default();
        let destination = MemorySecretStore::default();
        let expected = provision_installation_secrets(&source).expect("source should provision");

        migrate_installation_secrets(&source, &destination).expect("migration should succeed");
        migrate_installation_secrets(&source, &destination)
            .expect("repeated migration should be idempotent");

        let migrated = load_installation_secrets(&destination)
            .expect("destination should be readable")
            .expect("destination should be complete");
        assert_eq!(expected.database_password(), migrated.database_password());
        assert_eq!(expected.jwt_secret(), migrated.jwt_secret());
        assert_eq!(source.values.lock().expect("store lock").len(), 6);
    }

    #[test]
    fn migration_refuses_to_overwrite_a_destination_conflict() {
        let source = MemorySecretStore::default();
        let destination = MemorySecretStore::default();
        provision_installation_secrets(&source).expect("source should provision");
        destination
            .set(DATABASE_PASSWORD, &"f".repeat(SECRET_HEX_LENGTH))
            .expect("conflict fixture should be stored");

        let result = migrate_installation_secrets(&source, &destination);

        assert!(matches!(
            result,
            Err(SecretStoreError::MigrationConflict(DATABASE_PASSWORD))
        ));
        assert_eq!(destination.values.lock().expect("store lock").len(), 1);
    }

    #[test]
    fn incomplete_credential_set_fails_closed() {
        let store = MemorySecretStore::default();
        store
            .set(DATABASE_PASSWORD, &"a".repeat(SECRET_HEX_LENGTH))
            .expect("fixture should be stored");

        let result = resolve_installation_secrets(&store, false);

        assert!(matches!(
            result,
            Err(SecretStoreError::IncompleteCredentialSet)
        ));
        assert_eq!(store.values.lock().expect("store lock").len(), 1);
    }
}
