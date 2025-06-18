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

use serde::Deserialize;

use crate::elastic_query_dsl::{
    ConvertibleToQueryAst, ElasticQueryDslInner, StringOrStructForSerialization,
};
use crate::query_ast::{QueryAst, WildcardQuery};
use crate::OneFieldMap;

#[derive(Deserialize, Clone, Eq, PartialEq, Debug)]
#[serde(from = "OneFieldMap<StringOrStructForSerialization<WildcardPhraseParams>>")]
pub(crate) struct WildcardPhraseQuery {
    pub(crate) field: String,
    pub(crate) params: WildcardPhraseParams,
}

#[derive(Clone, Deserialize, PartialEq, Eq, Debug)]
#[serde(deny_unknown_fields)]
pub struct WildcardPhraseParams {
    pub(crate) query: String,
    #[serde(default)]
    pub(crate) analyzer: Option<String>,
    #[serde(default)]
    pub(crate) slop: u32,
    #[serde(default)]
    pub(crate) case_insensitive: bool,
    #[serde(default)]
    pub(crate) must_start: bool,
}

impl ConvertibleToQueryAst for WildcardPhraseQuery {
    fn convert_to_query_ast(self) -> anyhow::Result<QueryAst> {
        Ok(QueryAst::Wildcard(WildcardQuery {
            field: self.field,
            value: self.params.query,
            lenient: false,
            slop: self.params.slop,
            tokenizer: self.params.analyzer,
            case_insensitive: self.params.case_insensitive,
            must_start: self.params.must_start,
            must_end: false,
        }))
    }
}

impl From<WildcardPhraseQuery> for ElasticQueryDslInner {
    fn from(wildcard_phrase_query: WildcardPhraseQuery) -> Self {
        ElasticQueryDslInner::WildcardPhrase(wildcard_phrase_query)
    }
}

impl From<OneFieldMap<StringOrStructForSerialization<WildcardPhraseParams>>>
    for WildcardPhraseQuery
{
    fn from(
        match_query_params: OneFieldMap<StringOrStructForSerialization<WildcardPhraseParams>>,
    ) -> Self {
        let OneFieldMap { field, value } = match_query_params;
        WildcardPhraseQuery {
            field,
            params: value.inner,
        }
    }
}

impl From<String> for WildcardPhraseParams {
    fn from(query: String) -> WildcardPhraseParams {
        WildcardPhraseParams {
            query,
            analyzer: None,
            slop: 0,
            case_insensitive: false,
            must_start: false,
        }
    }
}
