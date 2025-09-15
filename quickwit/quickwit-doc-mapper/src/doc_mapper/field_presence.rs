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

use fnv::FnvHashSet;
use quickwit_common::PathHasher;
use tantivy::schema::document::{ReferenceValue, ReferenceValueLeaf};
use tantivy::schema::{FieldEntry, FieldType, Schema, Value};
use tantivy::Document;

pub struct PresenceFields {
    // data which goes into _field_presence
    pub hashes: FnvHashSet<u64>,
    // data which goes into _field_presence_json
    pub json_hashes: FnvHashSet<u64>,
}

/// Populates the field presence for a document.
///
/// The field presence is a set of hashes that represent the fields that are present in the
/// document. Each hash is computed from the field path.
///
/// It is only added if the field is indexed and not fast.
pub(crate) fn populate_field_presence<D: Document>(
    document: &D,
    schema: &Schema,
    populate_object_fields: bool,
) -> PresenceFields {
    let mut presence_fields: PresenceFields = PresenceFields {
        hashes: FnvHashSet::with_capacity_and_hasher(schema.num_fields(), Default::default()),
        json_hashes: FnvHashSet::with_hasher(Default::default()),
    };
    for (field, value) in document.iter_fields_and_values() {
        let field_entry = schema.get_field_entry(field);
        if !should_populate(field_entry) {
            // Use tantivy's ExistsQuery
            continue;
        }

        let mut path_hasher: PathHasher = PathHasher::default();
        path_hasher.append(&field.field_id().to_le_bytes()[..]);
        if let Some(json_obj) = value.as_object() {
            let is_expand_dots_enabled: bool =
                if let FieldType::JsonObject(json_options) = field_entry.field_type() {
                    json_options.is_expand_dots_enabled()
                } else {
                    false
                };
            let mut subfields_populator = SubfieldsPopulator {
                populate_object_fields,
                is_expand_dots_enabled,
                is_fast_field: field_entry.is_fast(),
                presence_fields: &mut presence_fields,
            };
            subfields_populator.populate_field_presence_for_json_obj(path_hasher, json_obj);
        } else {
            presence_fields.hashes.insert(path_hasher.finish_leaf());
        }
    }
    presence_fields
}

fn should_populate(field_entry: &FieldEntry) -> bool {
    if !field_entry.is_indexed() {
        return false;
    }
    // exclude most fast fields, except json objects (to populate _field_presence_json).
    if field_entry.field_type().is_json() {
        return true;
    }
    !field_entry.is_fast()
}

/// A struct to help populate field presence hashes for nested JSON field.
struct SubfieldsPopulator<'a> {
    populate_object_fields: bool,
    is_expand_dots_enabled: bool,
    // whether the parent field is a fast field (for _field_presence_json).
    is_fast_field: bool,
    presence_fields: &'a mut PresenceFields,
}

impl SubfieldsPopulator<'_> {
    #[inline]
    fn populate_field_presence_for_json_value<'a>(
        &mut self,
        path_hasher: PathHasher,
        json_value: impl Value<'a>,
    ) {
        match json_value.as_value() {
            ReferenceValue::Leaf(ReferenceValueLeaf::Null) => {}
            ReferenceValue::Leaf(_) => {
                if !self.is_fast_field {
                    self.presence_fields
                        .hashes
                        .insert(path_hasher.finish_leaf());
                }
                // intentionally don't populate leafs in self.presence_fields.json_hashes.
            }
            ReferenceValue::Array(items) => {
                for item in items {
                    self.populate_field_presence_for_json_value(path_hasher.clone(), item);
                }
            }
            ReferenceValue::Object(json_obj) => {
                self.populate_field_presence_for_json_obj(path_hasher, json_obj);
            }
        }
    }

    fn populate_field_presence_for_json_obj<'a, I, V>(
        &mut self,
        path_hasher: PathHasher,
        json_obj: I,
    ) where
        I: Iterator<Item = (&'a str, V)>,
        V: Value<'a>,
    {
        if self.populate_object_fields {
            self.choose_set().insert(path_hasher.finish_intermediate());
        }
        for (field_key, field_value) in json_obj {
            let mut child_path_hasher = path_hasher.clone();
            if self.is_expand_dots_enabled {
                let mut expanded_key = field_key.split('.').peekable();
                while let Some(segment) = expanded_key.next() {
                    child_path_hasher.append(segment.as_bytes());
                    if self.populate_object_fields && expanded_key.peek().is_some() {
                        self.choose_set()
                            .insert(child_path_hasher.finish_intermediate());
                    }
                }
            } else {
                child_path_hasher.append(field_key.as_bytes());
            };
            self.populate_field_presence_for_json_value(child_path_hasher, field_value);
        }
    }

    fn choose_set(&mut self) -> &mut FnvHashSet<u64> {
        if self.is_fast_field {
            &mut self.presence_fields.json_hashes
        } else {
            &mut self.presence_fields.hashes
        }
    }
}

#[cfg(test)]
mod tests {
    use tantivy::schema::*;
    use tantivy::TantivyDocument;

    use super::*;

    #[test]
    fn test_populate_field_presence_basic() {
        let mut schema_builder = Schema::builder();
        schema_builder.add_text_field("indexed_text", TEXT);
        schema_builder.add_text_field("text_not_indexed", STORED);
        let schema = schema_builder.build();
        let json_doc = r#"{"indexed_text": "hello", "text_not_indexed": "world"}"#;
        let document = TantivyDocument::parse_json(&schema, json_doc).unwrap();

        let field_presence = populate_field_presence(&document, &schema, true);
        assert_eq!(field_presence.hashes.len(), 1);
    }

    #[test]
    fn test_populate_field_presence_with_array() {
        let mut schema_builder = Schema::builder();
        schema_builder.add_text_field("list", TEXT);
        let schema = schema_builder.build();
        let json_doc = r#"{"list": ["value1", "value2"]}"#;
        let document = TantivyDocument::parse_json(&schema, json_doc).unwrap();

        let field_presence = populate_field_presence(&document, &schema, true);
        assert_eq!(field_presence.hashes.len(), 1);
    }

    #[test]
    fn test_populate_field_presence_with_json() {
        let mut schema_builder = Schema::builder();
        schema_builder.add_json_field("json", TEXT);
        let schema = schema_builder.build();
        let json_doc = r#"{"json": {"subfield": "a"}}"#;
        let document = TantivyDocument::parse_json(&schema, json_doc).unwrap();

        let field_presence = populate_field_presence(&document, &schema, false);
        assert_eq!(field_presence.hashes.len(), 1);
        let field_presence = populate_field_presence(&document, &schema, true);
        assert_eq!(field_presence.hashes.len(), 2);
    }

    #[test]
    fn test_populate_field_presence_with_nested_jsons() {
        let mut schema_builder = Schema::builder();
        schema_builder.add_json_field("json", TEXT);
        let schema = schema_builder.build();
        let json_doc = r#"{"json": {"subfield": {"subsubfield": "a"}}}"#;
        let document = TantivyDocument::parse_json(&schema, json_doc).unwrap();

        let field_presence = populate_field_presence(&document, &schema, false);
        assert_eq!(field_presence.hashes.len(), 1);
        let field_presence = populate_field_presence(&document, &schema, true);
        assert_eq!(field_presence.hashes.len(), 3);
    }

    #[test]
    fn test_populate_field_presence_with_array_of_objects() {
        let mut schema_builder = Schema::builder();
        schema_builder.add_json_field("json", TEXT);
        let schema = schema_builder.build();
        let json_doc = r#"{"json": {"list": [{"key1":"value1"}, {"key2":"value2"}]}}"#;
        let document = TantivyDocument::parse_json(&schema, json_doc).unwrap();

        let field_presence = populate_field_presence(&document, &schema, false);
        assert_eq!(field_presence.hashes.len(), 2);
        let field_presence = populate_field_presence(&document, &schema, true);
        assert_eq!(field_presence.hashes.len(), 4);
    }

    #[test]
    fn test_populate_field_presence_with_expand_dots() {
        let mut schema_builder = Schema::builder();
        schema_builder.add_json_field(
            "json",
            Into::<JsonObjectOptions>::into(TEXT).set_expand_dots_enabled(),
        );
        let schema = schema_builder.build();
        let json_doc = r#"{"json": {"key.with.dots": "value"}}"#;
        let document = TantivyDocument::parse_json(&schema, json_doc).unwrap();

        let field_presence = populate_field_presence(&document, &schema, false);
        assert_eq!(field_presence.hashes.len(), 1);
        let field_presence = populate_field_presence(&document, &schema, true);
        assert_eq!(field_presence.hashes.len(), 4);
    }
}
