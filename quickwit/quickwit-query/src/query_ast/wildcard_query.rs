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

use std::sync::Arc;

use anyhow::Context;
use serde::{Deserialize, Serialize};
use tantivy::query::RegexPhraseQuery;
use tantivy::schema::{Field, FieldType, Schema as TantivySchema};
use tantivy::Term;

use super::{BuildTantivyAst, QueryAst};
use crate::query_ast::{AutomatonQuery, JsonPathPrefix, TantivyQueryAst};
use crate::tokenizers::TokenizerManager;
use crate::{find_field_or_hit_dynamic, InvalidQuery};

/// A Wildcard query allows to match 'bond' with a query like 'b*d'.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct WildcardQuery {
    pub field: String,
    pub value: String,
    /// Support missing fields
    pub lenient: bool,

    #[serde(default)]
    pub slop: u32,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tokenizer: Option<String>,

    #[serde(default)]
    pub case_insensitive: bool,

    #[serde(default)]
    pub must_start: bool,
}

impl From<WildcardQuery> for QueryAst {
    fn from(wildcard_query: WildcardQuery) -> Self {
        Self::Wildcard(wildcard_query)
    }
}

fn parse_wildcard_query(mut query: &str) -> Vec<SubQuery> {
    let mut res = Vec::new();
    while let Some(pos) = query.find(['*', '?', '\\']) {
        if pos > 0 {
            res.push(SubQuery::Text(query[..pos].to_string()));
        }
        let chr = &query[pos..pos + 1];
        query = &query[pos + 1..];
        match chr {
            "*" => res.push(SubQuery::Wildcard),
            "?" => res.push(SubQuery::QuestionMark),
            "\\" => {
                if let Some(chr) = query.chars().next() {
                    res.push(SubQuery::Text(chr.to_string()));
                    query = &query[chr.len_utf8()..];
                } else {
                    // escaping at the end is invalid, handle it as if that escape sequence wasn't
                    // present
                    break;
                }
            }
            _ => unreachable!("find shouldn't return non-matching position"),
        }
    }
    if !query.is_empty() {
        res.push(SubQuery::Text(query.to_string()));
    }
    res
}

enum SubQuery {
    Text(String),
    Wildcard,
    QuestionMark,
}

enum LastToken {
    None,
    Text,
    Regex,
}

fn sub_query_parts_to_regex_tokens(
    sub_query_parts: Vec<SubQuery>,
    tokenizer_name: &str,
    tokenizer_manager: &TokenizerManager,
    case_insensitive: bool,
) -> anyhow::Result<Vec<String>> {
    let mut tokenizer = tokenizer_manager
        .get_tokenizer(tokenizer_name)
        .with_context(|| format!("no tokenizer named `{tokenizer_name}` is registered"))?;
    let lowercaser = tokenizer_manager.is_lowercaser(tokenizer_name);

    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut last = LastToken::None;

    for part in sub_query_parts {
        match part {
            SubQuery::Text(text) => {
                let text_to_match = if lowercaser {
                    text.to_ascii_lowercase()
                } else {
                    text.clone()
                };

                let mut token_stream = tokenizer.token_stream(&text);
                token_stream.process(&mut |token| {
                    if (!text.starts_with(&token.text) && matches!(last, LastToken::Regex))
                        || matches!(last, LastToken::Text)
                    {
                        tokens.push(std::mem::take(&mut current));
                    }

                    last = if text_to_match.ends_with(&token.text) {
                        LastToken::None
                    } else {
                        LastToken::Text
                    };

                    let mut escaped = regex::escape(&token.text);

                    if case_insensitive {
                        let mut s = String::new();
                        for chr in escaped.chars() {
                            let lower = chr.to_ascii_lowercase();
                            let upper = chr.to_ascii_uppercase();
                            if lower == upper {
                                s.push(chr);
                            } else {
                                s.push('[');
                                s.push(lower);
                                s.push(upper);
                                s.push(']');
                            }
                        }
                        escaped = s;
                    }

                    current.push_str(&escaped);
                });
            }
            SubQuery::Wildcard | SubQuery::QuestionMark => {
                if !matches!(last, LastToken::None) {
                    tokens.push(std::mem::take(&mut current));
                }
                last = LastToken::Regex;
                current.push_str(if matches!(part, SubQuery::Wildcard) {
                    ".*"
                } else {
                    "."
                });
            }
        }
    }

    if !current.is_empty() {
        tokens.push(current);
    }

    Ok(tokens)
}

#[derive(Debug)]
pub enum RegexTerms {
    One(Option<Vec<u8>>, String),
    Many(Vec<(usize, Term)>),
}

impl WildcardQuery {
    pub fn new(field: String, value: String, lenient: bool) -> Self {
        Self {
            field,
            value,
            lenient,
            slop: 0,
            tokenizer: None,
            case_insensitive: false,
            must_start: false,
        }
    }

    pub fn to_regex_terms(
        &self,
        schema: &TantivySchema,
        tokenizer_manager: &TokenizerManager,
    ) -> Result<(Field, RegexTerms), InvalidQuery> {
        let Some((field, field_entry, json_path)) = find_field_or_hit_dynamic(&self.field, schema)
        else {
            return Err(InvalidQuery::FieldDoesNotExist {
                full_path: self.field.clone(),
            });
        };
        let field_type = field_entry.field_type();

        let sub_query_parts = parse_wildcard_query(&self.value);

        match field_type {
            FieldType::Str(ref text_options) => {
                let text_field_indexing = text_options.get_indexing_options().ok_or_else(|| {
                    InvalidQuery::SchemaError(format!(
                        "field {} is not full-text searchable",
                        field_entry.name()
                    ))
                })?;
                let tokenizer_name: &str = self
                    .tokenizer
                    .as_deref()
                    .unwrap_or(text_field_indexing.tokenizer());
                let tokens = sub_query_parts_to_regex_tokens(
                    sub_query_parts,
                    tokenizer_name,
                    tokenizer_manager,
                    self.case_insensitive,
                )?;

                let regex_terms = if tokens.len() == 1 {
                    RegexTerms::One(None, tokens.into_iter().next().unwrap())
                } else {
                    RegexTerms::Many(
                        tokens
                            .into_iter()
                            .enumerate()
                            .map(|(offset, term)| (offset, Term::from_field_text(field, &term)))
                            .collect(),
                    )
                };

                Ok((field, regex_terms))
            }
            FieldType::JsonObject(json_options) => {
                let text_field_indexing =
                    json_options.get_text_indexing_options().ok_or_else(|| {
                        InvalidQuery::SchemaError(format!(
                            "field {} is not full-text searchable",
                            field_entry.name()
                        ))
                    })?;
                let tokenizer_name: &str = self
                    .tokenizer
                    .as_deref()
                    .unwrap_or(text_field_indexing.tokenizer());
                let tokens = sub_query_parts_to_regex_tokens(
                    sub_query_parts,
                    tokenizer_name,
                    tokenizer_manager,
                    self.case_insensitive,
                )?;

                let regex_terms = if tokens.len() == 1 {
                    let mut term_for_path = Term::from_field_json_path(
                        field,
                        json_path,
                        json_options.is_expand_dots_enabled(),
                    );
                    term_for_path.append_type_and_str("");

                    let value = term_for_path.value();
                    // We skip the 1st byte which is a marker to tell this is json. This isn't
                    // present in the dictionary
                    let byte_path_prefix = value.as_serialized()[1..].to_owned();

                    RegexTerms::One(Some(byte_path_prefix), tokens.into_iter().next().unwrap())
                } else {
                    RegexTerms::Many(
                        tokens
                            .into_iter()
                            .enumerate()
                            .map(|(offset, token)| {
                                let mut term = Term::from_field_json_path(
                                    field,
                                    json_path,
                                    json_options.is_expand_dots_enabled(),
                                );
                                term.append_type_and_str(&token);
                                (offset, term)
                            })
                            .collect(),
                    )
                };

                Ok((field, regex_terms))
            }
            _ => Err(InvalidQuery::SchemaError(
                "trying to run a Wildcard query on a non-text field".to_string(),
            )),
        }
    }
}

impl BuildTantivyAst for WildcardQuery {
    fn build_tantivy_ast_impl(
        &self,
        schema: &TantivySchema,
        tokenizer_manager: &TokenizerManager,
        _search_fields: &[String],
        _with_validation: bool,
    ) -> Result<TantivyQueryAst, InvalidQuery> {
        let (field, regex_terms) = match self.to_regex_terms(schema, tokenizer_manager) {
            Ok(res) => res,
            Err(InvalidQuery::FieldDoesNotExist { .. }) if self.lenient => {
                return Ok(TantivyQueryAst::match_none())
            }
            Err(e) => return Err(e),
        };

        match regex_terms {
            RegexTerms::One(json_path, term_text) => {
                let regex = tantivy_fst::Regex::new(&term_text)
                    .context("failed to parse regex built from wildcard")?;
                let regex_automaton_with_path = JsonPathPrefix {
                    prefix: json_path.unwrap_or_default(),
                    automaton: regex.into(),
                };
                let regex_query_with_path = AutomatonQuery {
                    field,
                    automaton: Arc::new(regex_automaton_with_path),
                };
                Ok(regex_query_with_path.into())
            }
            RegexTerms::Many(terms) => {
                if terms.is_empty() {
                    return Err(InvalidQuery::SchemaError(
                        "wildcard term is empty".to_string(),
                    ));
                }
                let mut regex_query_with_path =
                    RegexPhraseQuery::new_with_term_offset_and_slop(field, terms, self.slop);
                regex_query_with_path.set_must_start(self.must_start);
                Ok(regex_query_with_path.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use tantivy::schema::{TextFieldIndexing, TextOptions};

    use super::*;
    use crate::create_default_quickwit_tokenizer_manager;

    fn single_text_field_schema(field_name: &str, tokenizer: &str) -> TantivySchema {
        let mut schema_builder = TantivySchema::builder();
        let text_options = TextOptions::default()
            .set_indexing_options(TextFieldIndexing::default().set_tokenizer(tokenizer));
        schema_builder.add_text_field(field_name, text_options);
        schema_builder.build()
    }

    fn assert_term_eq_str(terms: Vec<(usize, Term)>, expected: Vec<&str>) {
        assert_eq!(terms.len(), expected.len());

        for (i, ex) in expected.into_iter().enumerate() {
            assert_eq!(terms[i].0, i);
            assert_eq!(terms[i].1.value().as_str(), Some(ex));
        }
    }

    fn assert_term_eq_json(terms: Vec<(usize, Term)>, expected: Vec<&str>) {
        assert_eq!(terms.len(), expected.len());

        for (i, ((offset, term), ex)) in terms.into_iter().zip(expected).enumerate() {
            assert_eq!(offset, i);

            let text = std::str::from_utf8(term.serialized_value_bytes())
                .expect("failed to get json text");
            assert!(text.ends_with(ex));
        }
    }

    #[test]
    fn test_wildcard_query_to_regex_on_text() {
        let query = WildcardQuery::new(
            "text_field".to_string(),
            "MyString Wh1ch?a.nOrMal Tokenizer would*cut".to_string(),
            false,
        );

        let tokenizer_manager = create_default_quickwit_tokenizer_manager();
        let mut schema_builder = TantivySchema::builder();
        let text_options = TextOptions::default()
            .set_indexing_options(TextFieldIndexing::default().set_tokenizer("whitespace"));
        schema_builder.add_text_field("text_field", text_options);
        let schema = schema_builder.build();

        let (_field, regex_terms) = query.to_regex_terms(&schema, &tokenizer_manager).unwrap();
        let RegexTerms::Many(terms) = regex_terms else {
            panic!("expected mutiple terms");
        };
        assert_term_eq_str(
            terms,
            vec!["MyString", "Wh1ch.a\\.nOrMal", "Tokenizer", "would.*cut"],
        );
    }

    #[test]
    fn test_wildcard_query_to_regex_on_json() {
        let query = WildcardQuery::new(
            // this volontarily contains uppercase and regex-unsafe char to make sure we properly
            // keep the case, but sanitize special chars
            "json_field.Inner.Fie*ld".to_string(),
            "MyString Wh1ch?a.nOrMal Tokenizer would*cut".to_string(),
            false,
        );

        let tokenizer_manager = create_default_quickwit_tokenizer_manager();
        let mut schema_builder = TantivySchema::builder();
        let text_options = TextOptions::default()
            .set_indexing_options(TextFieldIndexing::default().set_tokenizer("whitespace"));
        schema_builder.add_json_field("json_field", text_options);
        let schema = schema_builder.build();

        let (_field, regex_terms) = query.to_regex_terms(&schema, &tokenizer_manager).unwrap();
        let RegexTerms::Many(terms) = regex_terms else {
            panic!("expected mutiple terms");
        };
        assert_term_eq_json(
            terms,
            vec!["MyString", "Wh1ch.a\\.nOrMal", "Tokenizer", "would.*cut"],
        );
    }

    #[test]
    fn test_extract_regex_wildcard_missing_field() {
        let query = WildcardQuery::new(
            "my_missing_field".to_string(),
            "My query value*".to_string(),
            false,
        );
        let tokenizer_manager = create_default_quickwit_tokenizer_manager();
        let schema = single_text_field_schema("my_field", "whitespace");
        let err = query
            .to_regex_terms(&schema, &tokenizer_manager)
            .unwrap_err();
        let InvalidQuery::FieldDoesNotExist {
            full_path: missing_field_full_path,
        } = err
        else {
            panic!("unexpected error: {:?}", err);
        };
        assert_eq!(missing_field_full_path, "my_missing_field");
    }

    #[test]
    fn test_parse_complex_wildcard() -> anyhow::Result<()> {
        let tokenizer_manager = create_default_quickwit_tokenizer_manager();
        let parts = parse_wildcard_query("ha* t* *o ?it*");
        let tokens =
            sub_query_parts_to_regex_tokens(parts, "whitespace", &tokenizer_manager, false)?;
        assert_eq!(
            tokens,
            vec![
                "ha.*".to_string(),
                "t.*".to_string(),
                ".*o".to_string(),
                ".it.*".to_string()
            ]
        );
        Ok(())
    }

    #[test]
    fn test_parse_complex_wildcard_case_insensitive() -> anyhow::Result<()> {
        let tokenizer_manager = create_default_quickwit_tokenizer_manager();
        let parts = parse_wildcard_query("ha* t* *o ?it*");
        let tokens =
            sub_query_parts_to_regex_tokens(parts, "whitespace", &tokenizer_manager, true)?;
        assert_eq!(
            tokens,
            vec![
                "[hH][aA].*".to_string(),
                "[tT].*".to_string(),
                ".*[oO]".to_string(),
                ".[iI][tT].*".to_string()
            ]
        );
        Ok(())
    }

    #[test]
    fn test_parse_complex_wildcard_case_insensitive_lowercaser() -> anyhow::Result<()> {
        let tokenizer_manager = create_default_quickwit_tokenizer_manager();
        let parts = parse_wildcard_query("ha* t* *o ?it*");
        let tokens = sub_query_parts_to_regex_tokens(parts, "default", &tokenizer_manager, true)?;
        assert_eq!(
            tokens,
            vec![
                "[hH][aA].*".to_string(),
                "[tT].*".to_string(),
                ".*[oO]".to_string(),
                ".[iI][tT].*".to_string()
            ]
        );
        Ok(())
    }
}
