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

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bytesize::ByteSize;
use http::Method;
use quickwit_common::tower::Pool;
use quickwit_config::service::QuickwitService;
use quickwit_config::{NodeConfig, SearcherConfig};
use quickwit_proto::metastore::MetastoreServiceClient;
use quickwit_proto::search::search_service_server::SearchServiceServer;
use quickwit_proto::tonic::transport::Server;
use quickwit_search::{
    create_search_client, ClusterClient, SearchClientConfig, SearchJobPlacer, SearchService,
    SearchServiceClient, SearchServiceImpl, SearcherContext, SearcherPool,
};
use quickwit_serve::lambda_search_api::*;
use quickwit_serve::search_api::grpc_adapter::GrpcSearchAdapter;
use quickwit_storage::StorageResolver;
use quickwit_telemetry::payload::{QuickwitFeature, QuickwitTelemetryInfo, TelemetryEvent};
use tracing::{error, info};
use warp::filters::path::FullPath;
use warp::reject::Rejection;
use warp::{Filter, Reply};

use super::aws::create_grpc_interceptor;
use crate::searcher::environment::NUM_LEAFS;
use crate::searcher::reverse_proxy::reverse_proxy_filter;

static GRPC_SERVER_PORT: u16 = 5000;

fn spawn_grpc_server_task(
    address: SocketAddr,
    search_service: Arc<dyn SearchService>,
) -> tokio::task::JoinHandle<Result<(), anyhow::Error>> {
    let search_grpc_adapter = GrpcSearchAdapter::from(search_service);
    tokio::spawn(async move {
        Server::builder()
            .trace_fn(|val| {
                let content_type = val
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok());
                info!(path=%val.uri(), content_type=?content_type, "grpc server - new request");
                tracing::Span::current()
            })
            .add_service(SearchServiceServer::new(search_grpc_adapter))
            .serve(address)
            .await
            .context("grpc server task exit")
    })
}

fn spawn_grpc_interceptor_task(
    port: u16,
    storage_resolver: StorageResolver,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let hello = warp::any().and(create_grpc_interceptor(storage_resolver));

        warp::serve(hello).run(([127, 0, 0, 1], port)).await;
    })
}

fn spawn_leaf_search_service(
    searcher_config: SearcherConfig,
    metastore: MetastoreServiceClient,
    storage_resolver: StorageResolver,
) -> tokio::task::JoinHandle<Result<(), anyhow::Error>> {
    let searcher_context = Arc::new(SearcherContext::new(searcher_config, None));
    let cluster_client = ClusterClient::new(SearchJobPlacer::new(SearcherPool::default()));
    let search_service = SearchServiceImpl::new(
        metastore.clone(),
        storage_resolver.clone(),
        cluster_client.clone(),
        searcher_context.clone(),
    );
    let grpc_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), GRPC_SERVER_PORT);
    spawn_grpc_server_task(grpc_addr, Arc::new(search_service.clone()))
}

fn spawn_node_pool(
    storage_resolver: StorageResolver,
) -> (
    Pool<SocketAddr, SearchServiceClient>,
    Vec<tokio::task::JoinHandle<()>>,
) {
    let mut handles = Vec::new();
    let searcher_pool = SearcherPool::default();
    let start_port = 6001;
    let end_port = start_port + *NUM_LEAFS;
    for port in start_port..end_port {
        handles.push(spawn_grpc_interceptor_task(port, storage_resolver.clone()));
        let socket_addr = SocketAddr::new(Ipv4Addr::LOCALHOST.into(), port);
        searcher_pool.insert(
            socket_addr,
            create_search_client(&SearchClientConfig {
                grpc_addr: socket_addr,
                max_message_size: ByteSize::mib(30),
                timeout: Some(Duration::from_secs(500)),
            }),
        );
    }
    (searcher_pool, handles)
}

fn create_search_service_for_root_lambda(
    searcher_pool: Pool<SocketAddr, SearchServiceClient>,
    searcher_config: SearcherConfig,
    metastore: MetastoreServiceClient,
    storage_resolver: StorageResolver,
) -> Arc<dyn SearchService> {
    let searcher_context = Arc::new(SearcherContext::new(searcher_config, None));
    let search_job_placer = SearchJobPlacer::new(searcher_pool.clone());
    let cluster_client = ClusterClient::new(search_job_placer);
    // TODO configure split cache
    Arc::new(SearchServiceImpl::new(
        metastore,
        storage_resolver,
        cluster_client,
        searcher_context,
    ))
}

fn native_api(
    search_service: Arc<dyn SearchService>,
) -> impl Filter<Extract = (impl warp::Reply,), Error = Rejection> + Clone {
    search_get_handler(search_service.clone()).or(search_post_handler(search_service))
}

fn es_compat_api(
    search_service: Arc<dyn SearchService>,
    metastore: MetastoreServiceClient,
) -> impl Filter<Extract = (impl warp::Reply,), Error = Rejection> + Clone {
    es_compat_search_handler(search_service.clone())
        .or(es_compat_index_search_handler(search_service.clone()))
        .or(es_compat_index_count_handler(search_service.clone()))
        .or(es_compat_scroll_handler(search_service.clone()))
        .or(es_compat_index_multi_search_handler(search_service.clone()))
        .or(es_compat_index_field_capabilities_handler(
            search_service.clone(),
        ))
        .or(es_compat_index_stats_handler(metastore.clone()))
        .or(es_compat_stats_handler(metastore.clone()))
        .or(es_compat_index_cat_indices_handler(metastore.clone()))
        .or(es_compat_cat_indices_handler(metastore.clone()))
        .or(es_compat_resolve_index_handler(metastore.clone()))
}

fn index_api(
    metastore: MetastoreServiceClient,
) -> impl Filter<Extract = (impl warp::Reply,), Error = Rejection> + Clone {
    get_index_metadata_handler(metastore)
}

fn searcher_api(
    search_service: Arc<dyn SearchService>,
    metastore: MetastoreServiceClient,
) -> impl Filter<Extract = (impl warp::Reply,), Error = Rejection> + Clone {
    es_compat_api(search_service.clone(), metastore.clone())
        .or(index_api(metastore))
        .or(warp::path!("api" / "v1" / ..).and(native_api(search_service)))
        .recover(|rejection| {
            error!(?rejection, "request rejected");
            recover_fn(rejection)
        })
}

fn grpc_api() -> impl Filter<Extract = (impl warp::Reply,), Error = Rejection> + Clone {
    let before_hook = warp::path::full()
        .and(warp::method())
        .and_then(|route: FullPath, method: Method| async move {
            info!(
                method = method.as_str(),
                route = route.as_str(),
                "going into path"
            );
            quickwit_telemetry::send_telemetry_event(TelemetryEvent::RunCommand).await;
            Ok::<_, std::convert::Infallible>(())
        })
        .untuple_one();

    warp::path!("quickwit.search.SearchService" / ..)
        .and(before_hook)
        .and(reverse_proxy_filter(
            "".to_string(),
            format!("http://127.0.0.1:{GRPC_SERVER_PORT}"),
        ))
        .recover(log_and_forward_rejection)
}

async fn log_and_forward_rejection(rejection: Rejection) -> Result<Box<dyn Reply>, Rejection> {
    error!(?rejection, "grpc reverse proxy caught error");
    Err(rejection)
}

/// Sets up the searcher API for root lambdas
///
/// Includes:
/// - REST API endpoints for external requests
/// - gRPC server for internal communication
/// - Node pool and interceptors for spawning leaf lambdas
/// - Metastore connection for index/split discovery
pub fn setup_root_searcher_api(
    node_config: NodeConfig,
    storage_resolver: StorageResolver,
    metastore: MetastoreServiceClient,
) -> (
    impl Filter<Extract = (impl warp::Reply,), Error = Rejection> + Clone,
    impl FnOnce(),
) {
    let telemetry_info = QuickwitTelemetryInfo::new(
        HashSet::from_iter([QuickwitService::Searcher.as_str().to_string()]),
        HashSet::from_iter([QuickwitFeature::AwsLambda]),
    );
    let _telemetry_handle_opt = quickwit_telemetry::start_telemetry_loop(telemetry_info);

    let leaf_grpc_server_handle = spawn_leaf_search_service(
        node_config.searcher_config.clone(),
        metastore.clone(),
        storage_resolver.clone(),
    );

    let (searcher_pool, grpc_interceptor_handles) = spawn_node_pool(storage_resolver.clone());
    let abort = move || {
        // NOTE: not actually called by the lambda main().
        // TODO: if used, consider to await() as well.
        leaf_grpc_server_handle.abort();
        for handle in grpc_interceptor_handles {
            handle.abort();
        }
    };

    let root_lambda_search_service = create_search_service_for_root_lambda(
        searcher_pool,
        node_config.searcher_config,
        metastore.clone(),
        storage_resolver,
    );

    let api = create_api_with_hooks(
        searcher_api(root_lambda_search_service, metastore).or(grpc_api()),
        "root lambda",
    );

    (api, abort)
}

/// Sets up the API for leaf lambdas
///
/// Includes:
/// - Only gRPC server for leaf search requests
pub async fn setup_leaf_searcher_api(
    node_config: NodeConfig,
    storage_resolver: StorageResolver,
    mock_metastore: MetastoreServiceClient,
) -> (
    impl Filter<Extract = (impl warp::Reply,), Error = Rejection> + Clone,
    impl FnOnce(),
) {
    let telemetry_info: QuickwitTelemetryInfo = QuickwitTelemetryInfo::new(
        HashSet::from_iter([QuickwitService::Searcher.as_str().to_string()]),
        HashSet::from_iter([QuickwitFeature::AwsLambda]),
    );
    let _telemetry_handle_opt = quickwit_telemetry::start_telemetry_loop(telemetry_info);

    info!("Setting up leaf lambda without node pool and interceptors");

    // Spawn the leaf search service (gRPC server)
    let leaf_grpc_server_handle = spawn_leaf_search_service(
        node_config.searcher_config.clone(),
        mock_metastore,
        storage_resolver.clone(),
    );

    let abort = move || {
        leaf_grpc_server_handle.abort();
    };

    let api = create_api_with_hooks(grpc_api(), "leaf lambda");

    (api, abort)
}

/// Creates a warp API with common hooks (before/after request logging).
fn create_api_with_hooks(
    api_routes: impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone + Send + Sync + 'static,
    lambda_type: &'static str,
) -> impl Filter<Extract = (impl Reply,), Error = Rejection> + Clone {
    let before_hook = warp::path::full()
        .and(warp::method())
        .and_then(move |route: FullPath, method: Method| {
            let lambda_type = lambda_type;
            async move {
                info!(
                    method = method.as_str(),
                    route = route.as_str(),
                    lambda_type = lambda_type,
                    "new request"
                );
                quickwit_telemetry::send_telemetry_event(TelemetryEvent::RunCommand).await;
                Ok::<_, std::convert::Infallible>(())
            }
        })
        .untuple_one();

    let after_hook = warp::log::custom(move |info| {
        info!(
            status = info.status().as_str(),
            lambda_type = lambda_type,
            "request completed"
        );
    });

    warp::any()
        .and(before_hook)
        .and(api_routes)
        .with(after_hook)
}
