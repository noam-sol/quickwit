// Copyright 2021-Present Datadog, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::sync::Arc;

use async_trait::async_trait;
use quickwit_common::uri::Uri;
use quickwit_config::{StorageBackend, StorageCredentials};

use crate::{Storage, StorageResolverError};

/// Usage for the storage
#[derive(Copy, Clone, Default)]
pub enum StorageUsage {
    /// Usage should not affect how the storage is created
    #[default]
    None,

    /// Storage is used to read data from source
    Data,

    /// Storage is used to read and write index split files
    Index,
}

/// A storage factory builds a [`Storage`] object for a target [`StorageBackend`] from a
/// [`Uri`].
#[cfg_attr(any(test, feature = "testsuite"), mockall::automock)]
#[async_trait]
pub trait StorageFactory: Send + Sync + 'static {
    /// Returns the storage backend targeted by the factory.
    fn backend(&self) -> StorageBackend;

    /// Returns the appropriate [`Storage`] object for the URI.
    async fn resolve(
        &self,
        uri: &Uri,
        storage_credentials: &StorageCredentials,
        storage_usage: StorageUsage,
    ) -> Result<Arc<dyn Storage>, StorageResolverError>;
}

/// A storage factory for handling unsupported or unavailable storage backends.
#[derive(Debug, Clone)]
pub struct UnsupportedStorage {
    backend: StorageBackend,
    message: &'static str,
}

impl UnsupportedStorage {
    /// Creates a new [`UnsupportedStorage`].
    pub fn new(backend: StorageBackend, message: &'static str) -> Self {
        Self { backend, message }
    }
}

#[async_trait]
impl StorageFactory for UnsupportedStorage {
    fn backend(&self) -> StorageBackend {
        self.backend
    }

    async fn resolve(
        &self,
        _uri: &Uri,
        _: &StorageCredentials,
        _: StorageUsage,
    ) -> Result<Arc<dyn Storage>, StorageResolverError> {
        Err(StorageResolverError::UnsupportedBackend(
            self.message.to_string(),
        ))
    }
}
