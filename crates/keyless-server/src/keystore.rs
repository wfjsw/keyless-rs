use std::collections::HashMap;
use std::future::Future;
use std::path::Path;
use std::sync::{Arc, RwLock};

use keyless_protocol::{ski_from_spki, Operation, Ski};

use crate::key::{KeyError, LocalKey, PrivateKey};

pub type KeystoreError = Box<dyn std::error::Error + Send + Sync>;

/// Resolves the private key a request refers to.
///
/// Returning `Ok(None)` yields `ErrKeyNotFound`; `Err` yields `ErrInternal`.
pub trait Keystore: Send + Sync + 'static {
    fn get(
        &self,
        op: &Operation,
    ) -> impl Future<Output = Result<Option<Arc<dyn PrivateKey>>, KeystoreError>> + Send;
}

/// Keys indexed by Subject Key Identifier, like gokeyless's `DefaultKeystore`.
#[derive(Default)]
pub struct SkiKeystore {
    keys: RwLock<HashMap<Ski, Arc<dyn PrivateKey>>>,
}

impl SkiKeystore {
    pub fn new() -> SkiKeystore {
        SkiKeystore::default()
    }

    /// Adds a key, returning its SKI.
    pub fn add(&self, key: Arc<dyn PrivateKey>) -> Result<Ski, KeyError> {
        let ski = ski_from_spki(key.spki())?;
        tracing::debug!(%ski, "added key");
        self.keys.write().unwrap().insert(ski, key);
        Ok(ski)
    }

    /// Loads a PEM or DER private key file.
    pub fn add_file(&self, path: &Path) -> Result<Ski, KeystoreError> {
        let bytes = std::fs::read(path)?;
        let key = LocalKey::from_pem_or_der(&bytes)
            .map_err(|e| format!("{}: {e}", path.display()))?;
        tracing::info!(path = %path.display(), kind = ?key.kind(), "loaded key");
        Ok(self.add(Arc::new(key))?)
    }

    /// Recursively loads every `*.key` file under `dir`, as gokeyless does.
    pub fn add_dir(&self, dir: &Path) -> Result<Vec<Ski>, KeystoreError> {
        let mut skis = Vec::new();
        for entry in std::fs::read_dir(dir)? {
            let path = entry?.path();
            if path.is_dir() {
                skis.extend(self.add_dir(&path)?);
            } else if path.extension().is_some_and(|ext| ext == "key")
                && path.file_stem().is_some_and(|s| !s.is_empty())
            {
                skis.push(self.add_file(&path)?);
            }
        }
        Ok(skis)
    }

    pub fn len(&self) -> usize {
        self.keys.read().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Keystore for SkiKeystore {
    async fn get(&self, op: &Operation) -> Result<Option<Arc<dyn PrivateKey>>, KeystoreError> {
        Ok(op.ski.and_then(|ski| self.keys.read().unwrap().get(&ski).cloned()))
    }
}

impl<K: Keystore> Keystore for Arc<K> {
    fn get(
        &self,
        op: &Operation,
    ) -> impl Future<Output = Result<Option<Arc<dyn PrivateKey>>, KeystoreError>> + Send {
        (**self).get(op)
    }
}
