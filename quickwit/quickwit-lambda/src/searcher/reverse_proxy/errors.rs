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

use thiserror::Error;
use warp::reject::Reject;

/// Lib errors wrapper
/// Encapsulates the different errors that can occur during forwarding requests
#[derive(Error, Debug)]
pub enum Error {
    /// Errors produced by reading or building requests
    #[error("Request error: {0}")]
    Request(#[from] reqwest::Error),

    /// Errors when connecting to the target service
    #[error("Http error: {0}")]
    Http(#[from] warp::http::Error),
}

impl Reject for Error {}