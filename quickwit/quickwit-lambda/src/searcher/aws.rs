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

use std::fmt::Debug;

use anyhow::Context;
use aws_config::{self, BehaviorVersion};
use aws_sdk_lambda as lambda;
use aws_sdk_lambda::primitives::Blob;
use base64::prelude::*;
use http::{HeaderMap, Uri};
use lambda_http::aws_lambda_events::apigw::ApiGatewayProxyResponse;
use lambda_runtime::tracing::log::{error, info};
use quickwit_storage::StorageResolver;
use warp::filters::path::FullPath;
use warp::http::Method as RequestMethod;
use warp::hyper::body::Bytes;
use warp::hyper::Body;
use warp::reject::{Reject, Rejection};
use warp::Filter;

use crate::searcher::environment::LEAF_FUNCTION_NAME;
use crate::searcher::lambda_response::fetch_content;
use crate::searcher::reverse_proxy::extract_request_data_filter;

/// Alias of query parameters.
///
/// This is the type that holds the request query parameters.
pub type QueryParameters = Option<String>;

/// Alias of warp `Method`
pub type Method = RequestMethod;

pub mod lambda_header {
    pub const IS_LEAF: &str = "lambda-is-leaf";
    pub const NUM_LEAFS: &str = "lambda-num-leafs";
}

pub fn create_grpc_interceptor(
    storage_resolver: StorageResolver,
) -> impl Filter<Extract = (http::Response<Body>,), Error = Rejection> + Clone {
    let data_filter = extract_request_data_filter();

    let with_state = warp::any().map(move || storage_resolver.clone());

    data_filter
        .and(with_state)
        .and_then(invoke_lambda_and_forward_response)
        .boxed()
}

#[derive(Debug)]
struct RejectReason {
    #[allow(unused)] // derived debug impl uses this field
    pub err: anyhow::Error,
}
impl Reject for RejectReason {}

pub async fn invoke_lambda_and_forward_response(
    uri: FullPath,
    _: QueryParameters,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
    storage_resolver: StorageResolver,
) -> Result<http::Response<Body>, Rejection> {
    invoke_lambda_and_forward_response_inner(uri, method, headers, body, storage_resolver)
        .await
        .map_err(|err| warp::reject::custom(RejectReason { err }))
}

pub async fn invoke_lambda_and_forward_response_inner(
    uri: FullPath,
    method: Method,
    mut headers: HeaderMap,
    body: Bytes,
    storage_resolver: StorageResolver,
) -> Result<http::Response<Body>, anyhow::Error> {
    headers.insert(lambda_header::IS_LEAF, "true".parse().unwrap());
    let request_json = create_request_json(uri, method, headers, body)?.to_string();
    let aws_response = invoke_lambda(request_json.as_bytes())
        .await
        .context("failed to invoke lambda")?;
    let lambda_response =
        parse_lambda_response(&aws_response).context("failed to parse lambda response")?;

    let lambda_body_protocol = decode_lambda_body_field(&lambda_response)?;
    let content = fetch_content(storage_resolver, lambda_body_protocol)
        .await
        .context("failed to fetch content")?;

    let http_response = http::Response::builder().status(lambda_response.status_code as u16);
    let http_response = lambda_response
        .headers
        .iter()
        .fold(http_response, |http_response, (key, value)| {
            http_response.header(key, value)
        });
    http_response
        .body(content.into())
        .context("failed to build response")
}

fn create_request_json(
    uri: FullPath,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> anyhow::Result<serde_json::Value> {
    let uri = uri.as_str().parse::<Uri>().context("failed to parse uri")?;
    let mut parts = uri.into_parts();
    parts.authority = None;
    parts.scheme = None;
    let new_uri = http::Uri::from_parts(parts).context("failed to create new uri")?;

    let base64_body = BASE64_STANDARD.encode(body);
    let mut header_map = serde_json::Map::new();
    for (key, value) in headers.iter() {
        let value = value
            .to_str()
            .context("failed to convert header value to string")?;
        header_map.insert(key.to_string(), value.to_string().into());
    }

    Ok(serde_json::json!({
        "resource": new_uri.to_string(),
        "path": new_uri.to_string(),
        "httpMethod": method.as_str(),
        "headers": header_map,
        "requestContext": {
            "httpMethod": method.as_str()
        },
        "body": base64_body,
        "isBase64Encoded": true
    }))
}

async fn invoke_lambda(
    payload: &[u8],
) -> anyhow::Result<aws_sdk_lambda::operation::invoke::InvokeOutput> {
    let config = aws_config::load_defaults(BehaviorVersion::latest()).await;
    let client = aws_sdk_lambda::Client::new(&config);

    info!("Invoking lambda");
    client
        .invoke()
        .function_name(LEAF_FUNCTION_NAME.as_str())
        .payload(Blob::new(payload))
        .invocation_type(lambda::types::InvocationType::RequestResponse)
        .send()
        .await
        .map_err(anyhow::Error::new)
}

fn parse_lambda_response(
    aws_response: &aws_sdk_lambda::operation::invoke::InvokeOutput,
) -> anyhow::Result<ApiGatewayProxyResponse> {
    info!("status code from lambda: {:?}", aws_response.status_code);
    let payload = aws_response
        .payload()
        .ok_or_else(|| anyhow::anyhow!("empty payload from aws response"))?
        .as_ref();
    info!("raw lambda payload length: {:?}", payload.len());

    let lambda_response: anyhow::Result<ApiGatewayProxyResponse> =
        serde_json::from_slice(payload).context("failed to parse payload as json");
    if let Err(err) = lambda_response {
        error!(
            "failed to parse lambda payload as json. payload: {}",
            String::from_utf8_lossy(payload)
        );
        return Err(err);
    }
    Ok(lambda_response.unwrap())
}

fn decode_lambda_body_field(response: &ApiGatewayProxyResponse) -> anyhow::Result<Vec<u8>> {
    let body = response
        .body
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("empty body from lambda response"))?;
    BASE64_STANDARD
        .decode(body)
        .context("failed to decode body field as base64")
}
