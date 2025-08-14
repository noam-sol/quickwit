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

// Based on https://github.com/aslamplr/warp_lambda under MIT license

use std::path::PathBuf;
use std::str::FromStr;

use anyhow::{Context, Result};
use quickwit_common::uri::Uri;
use quickwit_config::StorageCredentials;
use quickwit_storage::{StorageResolver, StorageUsage};

use crate::searcher::environment::BUCKET_PAYLOADS;

/*

Lambda response spec:
[content][footer]

footer: [content_type (1byte)][version (1byte)]
    content_type:    0 - embed, 1 - s3

content: content_type=0 - embedded body
         content_type=1 - s3://bucket/path, which contains body
*/

mod footer {
    pub const SIZE: usize = 2;
    pub mod version {
        pub const _FIELD_OFFSET: usize = 0;

        pub const V0: u8 = 0;
    }

    pub mod content_type {
        pub const _FIELD_OFFSET: usize = 1;

        pub const EMBED: u8 = 0;
        pub const S3: u8 = 1;
    }

    #[allow(dead_code)]
    pub fn get_version(lambda_response: &[u8]) -> anyhow::Result<u8> {
        check_valid(lambda_response)?;
        Ok(lambda_response[lambda_response.len() - version::_FIELD_OFFSET - 1])
    }

    pub fn get_content_type(lambda_response: &[u8]) -> anyhow::Result<u8> {
        check_valid(lambda_response)?;
        Ok(lambda_response[lambda_response.len() - content_type::_FIELD_OFFSET - 1])
    }

    fn check_valid(lambda_response: &[u8]) -> anyhow::Result<()> {
        if lambda_response.len() < SIZE {
            return Err(anyhow::anyhow!(
                "lambda response is too short. expected: {}, actual: {}",
                SIZE,
                lambda_response.len()
            ));
        }
        Ok(())
    }
}

// AWS claims for 6mb max payload, however this includes the base64 wrapping,
// so in practice we're limited to 4.7mb.
const AWS_PAYLOAD_MAX_SIZE: usize = 4_700_000;

pub async fn response_hook(
    body: Vec<u8>,
    storage_resolver: &StorageResolver,
    response_creator: ConstructLambdaResponse,
) -> anyhow::Result<Vec<u8>> {
    match response_creator.construct_lambda_response(body)? {
        ConstructResult::Embed(lambda_response) => Ok(lambda_response),
        ConstructResult::S3 {
            lambda_response,
            object_url,
            object,
        } => {
            let (bucket, prefix) = parse_s3_uri(&object_url).context("failed to parse s3 uri")?;
            let storage = storage_resolver
                .resolve(
                    &bucket,
                    &StorageCredentials::default(),
                    StorageUsage::default(),
                )
                .await
                .context("failed to resolve storage")?;
            storage
                .put(&prefix, Box::new(object))
                .await
                .context("failed to store lambda response in s3")?;
            Ok(lambda_response)
        }
    }
}

fn parse_s3_uri(object_url: &Uri) -> anyhow::Result<(Uri, PathBuf)> {
    let (bucket, prefix) = quickwit_storage::parse_s3_uri(object_url)
        .ok_or(anyhow::anyhow!("quickwit_storage::parse_s3_uri failed"))?;
    let bucket = Uri::from_str(&format!("s3://{}", bucket))?;
    Ok((bucket, prefix))
}

pub enum ConstructResult {
    Embed(Vec<u8>),
    S3 {
        lambda_response: Vec<u8>,
        object_url: Uri,
        object: Vec<u8>,
    },
}

pub struct ConstructLambdaResponse {
    get_s3_path: fn() -> String,
}

impl ConstructLambdaResponse {
    pub fn new() -> Self {
        Self {
            get_s3_path: gen_s3_path,
        }
    }

    pub fn construct_lambda_response(
        &self,
        mut content: Vec<u8>,
    ) -> anyhow::Result<ConstructResult> {
        if content.len() + footer::SIZE > AWS_PAYLOAD_MAX_SIZE {
            let object_url = (self.get_s3_path)();
            let mut lambda_response = object_url.as_bytes().to_vec();
            let object_url =
                Uri::from_str(&object_url).context("failed to parse generated s3 uri")?;
            lambda_response
                .extend_from_slice(vec![footer::content_type::S3, footer::version::V0].as_ref());
            return Ok(ConstructResult::S3 {
                lambda_response,
                object_url,
                object: content,
            });
        }
        content.extend_from_slice(vec![footer::content_type::EMBED, footer::version::V0].as_ref());
        Ok(ConstructResult::Embed(content))
    }
}

fn gen_s3_path() -> String {
    let now = chrono::Utc::now();
    let date_str = now.format("%Y%m%d").to_string();

    format!(
        "s3://{}/{}/{}",
        *BUCKET_PAYLOADS,
        date_str,
        uuid::Uuid::now_v7()
    )
}

pub async fn fetch_content(storage: StorageResolver, mut payload: Vec<u8>) -> Result<Vec<u8>> {
    let content_type = footer::get_content_type(&payload)?;
    let content_len = payload.len() - footer::SIZE;

    payload.truncate(content_len);
    let content = payload;

    match content_type {
        footer::content_type::EMBED => Ok(content),
        footer::content_type::S3 => {
            let content = String::from_utf8(content)?;
            let path: Uri = content.as_str().parse()?;
            let (bucket, prefix) = parse_s3_uri(&path).context("failed to parse s3 uri")?;
            let storage = storage
                .resolve(
                    &bucket,
                    &StorageCredentials::default(),
                    StorageUsage::default(),
                )
                .await?;

            let out_vec = storage
                .copy_to_vec(&prefix)
                .await
                .context("failed to download s3 file")?;
            Ok(out_vec)
        }
        _ => Err(anyhow::anyhow!(
            "Unknown footer content_type: {}",
            content_type
        )),
    }
}

#[cfg(test)]
pub mod test {
    use std::path::Path;
    use std::str::FromStr;
    use std::sync::Arc;

    use async_trait::async_trait;
    use quickwit_common::uri::Uri;
    use quickwit_config::{StorageBackend, StorageCredentials};
    use quickwit_storage::{
        RamStorageFactory, Storage, StorageFactory, StorageResolver, StorageResolverError,
        StorageUsage,
    };

    use crate::searcher::lambda_response::{fetch_content, response_hook, ConstructLambdaResponse};

    const S3_URL: &str = "s3://bucket/20250101/69771bf3-0e0f-4af3-a27c-4504be8526c7";
    const S3_URL_PREFIX: &str = "s3://";
    const RAM_URL_PREFIX: &str = "ram://";

    #[tokio::test]
    async fn construct_lambda_response_which_is_in_s3() {
        // Arrange
        let response_creator = ConstructLambdaResponse {
            get_s3_path: || -> String { S3_URL.to_string() },
        };
        let storage_resolver = create_storage_resolver(vec![]).await;
        let body = vec![b'A'; 7 * 1024 * 1024]; // 7mb

        // Act
        let actual = response_hook(body.clone(), &storage_resolver, response_creator)
            .await
            .unwrap();

        // Assert lambda response
        let mut expected = S3_URL.as_bytes().to_vec();
        expected.extend_from_slice(vec![1, 0].as_ref());
        assert_eq!(actual, expected);

        // Assert bucket content
        let storage = storage_resolver
            .resolve(
                &Uri::from_str(S3_URL).unwrap(),
                &StorageCredentials::default(),
                StorageUsage::default(),
            )
            .await
            .unwrap();
        let bucket_content = storage.copy_to_vec(Path::new("")).await.unwrap();
        assert_long_array_eq(bucket_content.as_ref(), body.as_ref());
    }

    #[tokio::test]
    async fn construct_lambda_response_which_is_embedded() {
        // Arrange
        let response_creator = ConstructLambdaResponse {
            get_s3_path: || -> String {
                panic!("get_s3_path() should not be called");
            },
        };
        let storage_resolver = create_storage_resolver(vec![]).await;
        let body = vec![b'A'; 1024 * 1024]; // 1mb

        // Act
        let actual = response_hook(body.clone(), &storage_resolver, response_creator)
            .await
            .unwrap();

        // Assert lambda response
        let mut expected = body.clone();
        expected.extend_from_slice(vec![0, 0].as_ref());
        assert_long_array_eq(actual.as_ref(), expected.as_ref());
    }

    fn assert_long_array_eq(actual: &[u8], expected: &[u8]) {
        // Don't use assert_eq to not print the long array
        assert!(actual == expected, "assert lambda response failed");
    }

    #[tokio::test]
    async fn fetch_content_which_is_embedded() {
        // lambda response-
        let mut lambda_response: Vec<u8> = "content".as_bytes().to_vec();
        lambda_response.extend_from_slice(vec![0, 0].as_ref());

        // Arrange - create storage resolver
        let storage_resolver = create_storage_resolver(vec![]).await;

        // Act - fetch content
        let content = fetch_content(storage_resolver, lambda_response)
            .await
            .unwrap();
        assert_eq!(content, b"content".to_vec());
    }

    #[tokio::test]
    async fn fetch_content_which_is_in_s3() {
        // lambda response-
        let mut lambda_response: Vec<u8> = S3_URL.as_bytes().to_vec();
        lambda_response.extend_from_slice(vec![1, 0].as_ref());

        // Arrange - create s3 object
        let storage_resolver = create_storage_resolver(vec![(S3_URL, b"content".to_vec())]).await;

        // Act - fetch content
        let content = fetch_content(storage_resolver, lambda_response)
            .await
            .unwrap();
        assert_eq!(content, b"content".to_vec());
    }

    async fn create_storage_resolver(s3_objects: Vec<(&str, Vec<u8>)>) -> StorageResolver {
        let factory = FakeS3StorageFactory {
            inner: RamStorageFactory::default(),
        };

        let storage = factory
            .resolve(
                &Uri::from_str(S3_URL_PREFIX).unwrap(),
                &StorageCredentials::default(),
                StorageUsage::default(),
            )
            .await
            .unwrap();
        for (s3_object_url, s3_object_payload) in s3_objects {
            let modified_path = s3_object_url.replace(S3_URL_PREFIX, "");
            storage
                .put(
                    Path::new(modified_path.as_str()),
                    Box::new(s3_object_payload),
                )
                .await
                .unwrap();
        }

        StorageResolver::builder()
            .register(factory)
            .build()
            .unwrap()
    }

    struct FakeS3StorageFactory {
        inner: RamStorageFactory,
    }

    #[async_trait]
    impl StorageFactory for FakeS3StorageFactory {
        fn backend(&self) -> StorageBackend {
            StorageBackend::S3
        }

        async fn resolve(
            &self,
            uri: &Uri,
            credentials: &StorageCredentials,
            storage_usage: StorageUsage,
        ) -> Result<Arc<dyn Storage>, StorageResolverError> {
            let uri = Uri::from_str(uri.as_str().replace(S3_URL_PREFIX, RAM_URL_PREFIX).as_ref())
                .unwrap();
            self.inner.resolve(&uri, credentials, storage_usage).await
        }
    }
}
