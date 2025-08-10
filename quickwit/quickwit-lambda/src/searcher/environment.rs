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

use std::env::var;

use once_cell::sync::Lazy;
use quickwit_config::NodeConfig;
use quickwit_proto::metastore::MetastoreServiceClient;
use quickwit_storage::StorageResolver;

use crate::utils::load_node_config;
pub(crate) const CONFIGURATION_TEMPLATE: &str = include_str!("lambda_node_config.yaml");

pub static BUCKET_PAYLOADS: Lazy<String> = Lazy::new(|| {
    var("QW_LAMBDA_BUCKET_PAYLOADS")
        .expect("environment variable QW_LAMBDA_BUCKET_PAYLOADS should be set")
});

pub static LEAF_FUNCTION_NAME: Lazy<String> = Lazy::new(|| {
    var("QW_LAMBDA_LEAF_FUNCTION_NAME")
        .expect("environment variable QW_LAMBDA_LEAF_FUNCTION_NAME should be set")
});

pub static NUM_LEAFS: Lazy<u16> = Lazy::new(|| {
    var("QW_LAMBDA_NUM_LEAFS")
        .expect("environment variable QW_LAMBDA_NUM_LEAFS should be set")
        .parse::<u16>()
        .expect("environment variable QW_LAMBDA_NUM_LEAFS must be int")
});

pub async fn load_lambda_leaf_node_config(
) -> anyhow::Result<(NodeConfig, StorageResolver, MetastoreServiceClient)> {
    load_node_config(CONFIGURATION_TEMPLATE, true).await
}

pub async fn load_lambda_root_node_config(
) -> anyhow::Result<(NodeConfig, StorageResolver, MetastoreServiceClient)> {
    load_node_config(CONFIGURATION_TEMPLATE, false).await
}

#[cfg(test)]
mod tests {

    use bytesize::ByteSize;
    use quickwit_config::{ConfigFormat, NodeConfig};

    use super::*;

    #[tokio::test]
    #[serial_test::file_serial(with_env)]
    async fn test_load_config() {
        let bucket = "mock-test-bucket";
        std::env::set_var("QW_LAMBDA_METASTORE_BUCKET", bucket);
        std::env::set_var("QW_LAMBDA_INDEX_BUCKET", bucket);
        std::env::set_var(
            "QW_LAMBDA_INDEX_CONFIG_URI",
            "s3://mock-index-config-bucket",
        );
        std::env::set_var("QW_LAMBDA_INDEX_ID", "lambda-test");

        let node_config = NodeConfig::load(ConfigFormat::Yaml, CONFIGURATION_TEMPLATE.as_bytes())
            .await
            .unwrap();
        assert_eq!(
            node_config.data_dir_path.to_string_lossy(),
            "/tmp",
            "only `/tmp` is writeable in AWS Lambda"
        );
        assert_eq!(
            node_config.default_index_root_uri,
            "s3://mock-test-bucket/index"
        );
        assert_eq!(
            node_config.metastore_uri.to_string(),
            "s3://mock-test-bucket/index#polling_interval=60s"
        );
        assert_eq!(
            node_config.searcher_config.partial_request_cache_capacity,
            ByteSize::mb(64)
        );

        std::env::remove_var("QW_LAMBDA_METASTORE_BUCKET");
        std::env::remove_var("QW_LAMBDA_INDEX_BUCKET");
        std::env::remove_var("QW_LAMBDA_INDEX_CONFIG_URI");
        std::env::remove_var("QW_LAMBDA_INDEX_ID");
    }
}
