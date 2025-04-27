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
use quickwit_config::{S3StorageConfig, StorageBackend, StorageCredentials};

use super::s3_compatible_storage::create_s3_client;
use crate::{
    DebouncedStorage, S3CompatibleObjectStorage, Storage, StorageFactory, StorageResolverError,
};

/// S3 compatible object storage resolver.
pub struct S3CompatibleObjectStorageFactory {
    storage_config: S3StorageConfig,
}

impl S3CompatibleObjectStorageFactory {
    /// Creates a new S3-compatible storage factory.
    pub fn new(storage_config: S3StorageConfig) -> Self {
        Self { storage_config }
    }
}

#[async_trait]
impl StorageFactory for S3CompatibleObjectStorageFactory {
    fn backend(&self) -> StorageBackend {
        StorageBackend::S3
    }

    async fn resolve(&self, uri: &Uri) -> Result<Arc<dyn Storage>, StorageResolverError> {
        self.resolve_with_storage_credentials(uri, StorageCredentials::default())
            .await
    }

    async fn resolve_with_storage_credentials(
        &self,
        uri: &Uri,
        storage_credentials: StorageCredentials,
    ) -> Result<Arc<dyn Storage>, StorageResolverError> {
        let role_arn_opt = storage_credentials
            .s3
            .as_ref()
            .and_then(|s3_creds| s3_creds.role_arn.as_deref())
            .map(ToString::to_string);

        let external_id_opt = storage_credentials
            .s3
            .as_ref()
            .and_then(|s3_creds| s3_creds.external_id.as_deref().map(|s| s.to_string()));

        let s3_client = create_s3_client(&self.storage_config, role_arn_opt, external_id_opt).await;

        let storage =
            S3CompatibleObjectStorage::from_uri_and_client(&self.storage_config, uri, s3_client)
                .await?;

        Ok(Arc::new(DebouncedStorage::new(storage)))
    }
}
