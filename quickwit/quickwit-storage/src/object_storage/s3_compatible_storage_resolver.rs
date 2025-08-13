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

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use aws_sdk_s3::Client as S3Client;
use quickwit_common::uri::Uri;
use quickwit_config::{AssumeRoleCredentials, S3StorageConfig, StorageBackend, StorageCredentials};
use tracing::{debug, info};

use super::s3_compatible_storage::create_s3_client;
use crate::{
    DebouncedStorage, S3CompatibleObjectStorage, Storage, StorageFactory, StorageResolverError,
    StorageUsage,
};

/// Cache key for S3 clients, combining role ARN and external ID
#[derive(Clone, PartialEq, Eq, Hash)]
struct S3ClientCacheKey {
    role_arn: Option<String>,
    external_id: Option<String>,
}

/// S3 compatible object storage resolver.
pub struct S3CompatibleObjectStorageFactory {
    storage_config: S3StorageConfig,
    client_cache: Mutex<HashMap<S3ClientCacheKey, S3Client>>,
}

impl S3CompatibleObjectStorageFactory {
    /// Creates a new S3-compatible storage factory.
    pub fn new(storage_config: S3StorageConfig) -> Self {
        Self {
            storage_config,
            client_cache: Mutex::new(HashMap::new()),
        }
    }

    /// Get an S3 client from the cache or create a new one
    async fn get_or_create_client(
        &self,
        role_arn_opt: Option<String>,
        external_id_opt: Option<String>,
    ) -> Result<S3Client, StorageResolverError> {
        let cache_key = S3ClientCacheKey {
            role_arn: role_arn_opt.clone(),
            external_id: external_id_opt.clone(),
        };

        {
            let cache_guard = self.client_cache.lock().map_err(|_| {
                StorageResolverError::FailedToOpenStorage {
                    kind: crate::StorageErrorKind::Internal,
                    message: "Failed to acquire lock on S3 client cache.".to_string(),
                }
            })?;

            if let Some(client) = cache_guard.get(&cache_key) {
                debug!(
                    role_arn=?role_arn_opt,
                    external_id=?external_id_opt,
                    "Using cached S3 client for role ARN and external ID"
                );
                return Ok(client.clone());
            }
        }

        info!(
            role_arn=?role_arn_opt,
            external_id=?external_id_opt,
            "Creating new S3 client for role ARN"
        );
        let new_client =
            create_s3_client(&self.storage_config, role_arn_opt.clone(), external_id_opt).await;

        {
            let mut cache_guard = self.client_cache.lock().map_err(|_| {
                StorageResolverError::FailedToOpenStorage {
                    kind: crate::StorageErrorKind::Internal,
                    message: "Failed to acquire lock on S3 client cache for storing new client"
                        .to_string(),
                }
            })?;

            cache_guard.insert(cache_key, new_client.clone());
        }

        Ok(new_client)
    }
}

fn get_role(
    storage_credentials: &StorageCredentials,
    storage_usage: StorageUsage,
) -> Option<&AssumeRoleCredentials> {
    storage_credentials
        .s3
        .as_ref()
        .and_then(|s3| match storage_usage {
            StorageUsage::Data => s3.role.as_ref(),
            StorageUsage::Index => s3.index_role.as_ref().or(s3.role.as_ref()),
            _ => None,
        })
}

#[async_trait]
impl StorageFactory for S3CompatibleObjectStorageFactory {
    fn backend(&self) -> StorageBackend {
        StorageBackend::S3
    }

    async fn resolve(
        &self,
        uri: &Uri,
        storage_credentials: &StorageCredentials,
        storage_usage: StorageUsage,
    ) -> Result<Arc<dyn Storage>, StorageResolverError> {
        let selected_role_opt = get_role(storage_credentials, storage_usage);
        let role_arn_opt = selected_role_opt.map(|role| role.role_arn.clone());

        let external_id_opt = selected_role_opt.and_then(|role| role.external_id.clone());

        let s3_client = self
            .get_or_create_client(role_arn_opt, external_id_opt)
            .await?;

        let storage = S3CompatibleObjectStorage::from_uri_and_client(
            &self.storage_config,
            uri,
            s3_client,
            Some(storage_credentials),
        )
        .await?;

        Ok(Arc::new(DebouncedStorage::new(storage)))
    }
}

#[cfg(test)]
mod tests {
    use quickwit_config::{S3StorageConfig, S3StorageCredentials};

    use super::*;

    #[test]
    fn test_get_role() {
        let res = get_role(
            &StorageCredentials {
                s3: Some(S3StorageCredentials {
                    role: None,
                    index_role: None,
                    index_kms_key_id: None,
                }),
            },
            StorageUsage::Data,
        );
        assert_eq!(res, None);

        let storage_credentials = StorageCredentials {
            s3: Some(S3StorageCredentials {
                role: Some(AssumeRoleCredentials {
                    role_arn: "arn".to_string(),
                    external_id: None,
                }),
                index_role: None,
                index_kms_key_id: None,
            }),
        };
        let res = get_role(&storage_credentials, StorageUsage::Data);
        assert_ne!(res, None);
        assert_eq!(res.unwrap().role_arn, "arn");
        assert_eq!(res.unwrap().external_id, None);

        let storage_credentials = StorageCredentials {
            s3: Some(S3StorageCredentials {
                role: Some(AssumeRoleCredentials {
                    role_arn: "arn".to_string(),
                    external_id: Some("external-id".to_string()),
                }),
                index_role: None,
                index_kms_key_id: None,
            }),
        };
        let res = get_role(&storage_credentials, StorageUsage::Data);
        assert_ne!(res, None);
        assert_eq!(res.as_ref().unwrap().role_arn, "arn");
        assert_eq!(
            res.as_ref().unwrap().external_id.clone().unwrap(),
            "external-id"
        );

        // Test fallback to data, when Index is requested
        let storage_credentials = StorageCredentials {
            s3: Some(S3StorageCredentials {
                role: Some(AssumeRoleCredentials {
                    role_arn: "arn".to_string(),
                    external_id: Some("external-id".to_string()),
                }),
                index_role: None,
                index_kms_key_id: None,
            }),
        };
        let res = get_role(&storage_credentials, StorageUsage::Index);
        assert_ne!(res, None);
        assert_eq!(res.as_ref().unwrap().role_arn, "arn");
        assert_eq!(
            res.as_ref().unwrap().external_id.clone().unwrap(),
            "external-id"
        );

        // Test use of an index role when requested
        let storage_credentials = StorageCredentials {
            s3: Some(S3StorageCredentials {
                role: Some(AssumeRoleCredentials {
                    role_arn: "arn".to_string(),
                    external_id: Some("external-id".to_string()),
                }),
                index_role: Some(AssumeRoleCredentials {
                    role_arn: "index_arn".to_string(),
                    external_id: Some("external-id2".to_string()),
                }),
                index_kms_key_id: None,
            }),
        };
        let res = get_role(&storage_credentials, StorageUsage::Index);
        assert_ne!(res, None);
        assert_eq!(res.as_ref().unwrap().role_arn, "index_arn");
        assert_eq!(
            res.as_ref().unwrap().external_id.clone().unwrap(),
            "external-id2"
        );
    }

    #[tokio::test]
    async fn test_client_cache() {
        let storage_config = S3StorageConfig::default();
        let factory = S3CompatibleObjectStorageFactory::new(storage_config);

        // No clients in cache initially
        let cache_size = factory.client_cache.lock().map(|c| c.len()).unwrap_or(0);
        assert_eq!(cache_size, 0);

        // Create first client with no role
        factory
            .get_or_create_client(None, None)
            .await
            .expect("Failed to create client");
        let cache_size = factory.client_cache.lock().map(|c| c.len()).unwrap_or(0);
        assert_eq!(cache_size, 1);

        // Create client with a role
        let role1 = "arn:aws:iam::123456789012:role/TestRole1";
        factory
            .get_or_create_client(Some(role1.to_string()), None)
            .await
            .expect("Failed to create client");
        let cache_size = factory.client_cache.lock().map(|c| c.len()).unwrap_or(0);
        assert_eq!(cache_size, 2);

        // Request client with same role but different external ID
        // Should create a new client since we now cache by role+external ID
        factory
            .get_or_create_client(Some(role1.to_string()), Some("external-id".to_string()))
            .await
            .expect("Failed to create client");
        let cache_size = factory.client_cache.lock().map(|c| c.len()).unwrap_or(0);
        assert_eq!(cache_size, 3);

        // Create client with a different role
        let role2 = "arn:aws:iam::123456789012:role/TestRole2";
        factory
            .get_or_create_client(Some(role2.to_string()), None)
            .await
            .expect("Failed to create client");
        let cache_size = factory.client_cache.lock().map(|c| c.len()).unwrap_or(0);
        assert_eq!(cache_size, 4);
    }
}
