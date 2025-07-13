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

use quickwit_lambda::logger;
use quickwit_lambda::searcher::environment::load_lambda_node_config;
use quickwit_lambda::searcher::{setup_searcher_api, warp_lambda};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    logger::setup_lambda_tracer(tracing::Level::INFO)?;
    let (node_config, storage_resolver, metastore) = load_lambda_node_config().await?;
    let (routes, _) = setup_searcher_api(node_config, storage_resolver.clone(), metastore); // ignore abort() as lambda dies anyway.
    let warp_service = warp::service(routes);
    warp_lambda::run(warp_service, storage_resolver)
        .await
        .map_err(|e| anyhow::anyhow!(e))
}
