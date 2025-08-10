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

use core::future::Future;
use std::marker::PhantomData;
use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};

use anyhow::{anyhow, Context as AnyhowContext};
use http::header::Entry;
use lambda_http::{
    lambda_runtime, Adapter, Body as LambdaBody, Error as LambdaError, Request, RequestExt,
    Response, Service,
};
use tracing::{info, info_span, Instrument};
use warp::hyper::Body as WarpBody;
pub use {lambda_http, warp};

use crate::searcher::aws::lambda_header;
use crate::searcher::environment::{load_lambda_leaf_node_config, load_lambda_root_node_config};
use crate::searcher::lambda_response::{response_hook, ConstructLambdaResponse};
use crate::searcher::{setup_leaf_searcher_api, setup_root_searcher_api};

pub type WarpRequest = warp::http::Request<warp::hyper::Body>;
pub type WarpResponse = warp::http::Response<warp::hyper::Body>;

pub async fn run() -> Result<(), LambdaError> {
    lambda_runtime::run(Adapter::from(WarpAdapter::default())).await
}

#[derive(Clone, Default)]
pub struct WarpAdapter<'a> {
    _phantom_data: PhantomData<&'a WarpResponse>,
}

impl<'a> Service<Request> for WarpAdapter<'a> {
    type Response = Response<LambdaBody>;
    type Error = LambdaError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send + 'a>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        let query_params = req.query_string_parameters();
        let request_id = req.lambda_context().request_id.clone();
        let (mut parts, body) = req.into_parts();
        let (content_len, body) = match body {
            LambdaBody::Empty => (0, WarpBody::empty()),
            LambdaBody::Text(t) => (t.len(), WarpBody::from(t.into_bytes())),
            LambdaBody::Binary(b) => (b.len(), WarpBody::from(b)),
        };

        let mut uri = format!("http://{}{}", "127.0.0.1", parts.uri.path());
        if !query_params.is_empty() {
            let url_res = reqwest::Url::parse_with_params(&uri, query_params.iter());
            if let Ok(url) = url_res {
                uri = url.into();
            } else {
                return Box::pin(async { Err(anyhow!("Invalid url").into()) });
            }
        }

        // REST API Gateways swallow the content-length header which is required
        // by many Quickwit routes (`warp::body::content_length_limit(xxx)`)
        if let Entry::Vacant(v) = parts.headers.entry("Content-Length") {
            v.insert(content_len.into());
        }

        parts.uri = warp::hyper::Uri::from_str(uri.as_str()).unwrap();
        let warp_request = WarpRequest::from_parts(parts, body);

        // Create lambda future
        let fut = async move {
            let is_leaf = match warp_request.headers().get(lambda_header::IS_LEAF) {
                Some(v) => v
                    .to_str()
                    .context(format!("header {} is not a string", lambda_header::IS_LEAF))?
                    .parse::<bool>()
                    .context(format!("{} is not a boolean", lambda_header::IS_LEAF))?,
                None => false,
            };

            let (storage_resolver, warp_response) = if is_leaf {
                info!("Starting leaf lambda");
                let (node_config, storage_resolver, metastore) =
                    load_lambda_leaf_node_config().await?;
                let (routes, _) =
                    setup_leaf_searcher_api(node_config, storage_resolver.clone(), metastore).await;
                let warp_response = warp::service(routes).call(warp_request).await?;
                (storage_resolver, warp_response)
            } else {
                info!("Starting root lambda");
                let (node_config, storage_resolver, metastore) =
                    load_lambda_root_node_config().await?;
                let (routes, _) =
                    setup_root_searcher_api(node_config, storage_resolver.clone(), metastore);
                let warp_response = warp::service(routes).call(warp_request).await?;
                (storage_resolver, warp_response)
            };
            let (parts, res_body): (_, _) = warp_response.into_parts();
            let body = warp::hyper::body::to_bytes(res_body).await?.to_vec();

            let response_creator = ConstructLambdaResponse::new();
            info!("entering response_hook");
            let modified_body = response_hook(body, &storage_resolver, response_creator)
                .await
                .context("response_hook failed")?;
            info!(
                "exited response_hook; modified_body len: {}",
                modified_body.len()
            );

            let lambda_response = Response::from_parts(parts, LambdaBody::Binary(modified_body));
            Ok::<Self::Response, Self::Error>(lambda_response)
        }
        .instrument(info_span!("searcher request", request_id));
        Box::pin(fut)
    }
}
