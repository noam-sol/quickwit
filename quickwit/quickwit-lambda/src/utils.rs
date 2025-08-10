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

use std::str::FromStr;
use std::sync::atomic::AtomicU32;
use std::sync::atomic::Ordering::SeqCst;

use anyhow::Context;
use quickwit_config::{ConfigFormat, NodeConfig};
use quickwit_metastore::{MetastoreResolver, MetastoreResolverError};
use quickwit_proto::metastore::MetastoreServiceClient;
use quickwit_storage::StorageResolver;
use tracing::info;

async fn dummy_metastore() -> anyhow::Result<MetastoreServiceClient, MetastoreResolverError> {
    let metastore_resolver = MetastoreResolver::unconfigured();
    // Use a local file URI that won't actually connect to any external service
    let dummy_uri = quickwit_common::uri::Uri::from_str("file:///tmp/dummy-metastore").unwrap();
    metastore_resolver.resolve(&dummy_uri).await
}

pub(crate) async fn load_node_config(
    config_template: &str,
    should_mock_metastore: bool,
) -> anyhow::Result<(NodeConfig, StorageResolver, MetastoreServiceClient)> {
    let config = NodeConfig::load(ConfigFormat::Yaml, config_template.as_bytes())
        .await
        .with_context(|| format!("Failed to parse node config `{config_template}`."))?;
    info!(config=?config, "loaded node config");
    let storage_resolver = StorageResolver::configured(&config.storage_configs);

    let metastore = if should_mock_metastore {
        dummy_metastore().await?
    } else {
        let metastore_resolver =
            MetastoreResolver::configured(storage_resolver.clone(), &config.metastore_configs);
        metastore_resolver.resolve(&config.metastore_uri).await?
    };

    Ok((config, storage_resolver, metastore))
}

static CONTAINER_ID: AtomicU32 = AtomicU32::new(0);

pub struct LambdaContainerContext {
    pub container_id: u32,
    pub cold: bool,
}

impl LambdaContainerContext {
    /// Configure and return the Lambda container context.
    ///
    /// The `cold` field returned will be `true` only the first time this
    /// function is called.
    pub fn load() -> Self {
        let mut container_id = CONTAINER_ID.load(SeqCst);
        let mut cold = false;
        if container_id == 0 {
            container_id = rand::random();
            CONTAINER_ID.store(container_id, SeqCst);
            cold = true;
        }
        Self { container_id, cold }
    }
}
