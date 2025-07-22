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

use std::str::CharIndices;

use tantivy::tokenizer::{Token, TokenStream, Tokenizer};

const UUID_LEN: usize = 36;

/// Same as SimpleTokenizer, but doesn't tokenizes the values between hyphens in UUIDs.
#[derive(Clone, Default)]
pub struct SimpleIgnoreUUIDTokenizer {
    token: Token,
}

/// TokenStream produced by the `SimpleIgnoreUUIDTokenizer`.
pub struct SimpleIgnoreUUIDTokenStream<'a> {
    text: &'a str,
    chars: CharIndices<'a>,
    token: &'a mut Token,
}

impl Tokenizer for SimpleIgnoreUUIDTokenizer {
    type TokenStream<'a> = SimpleIgnoreUUIDTokenStream<'a>;
    fn token_stream<'a>(&'a mut self, text: &'a str) -> SimpleIgnoreUUIDTokenStream<'a> {
        self.token.reset();
        SimpleIgnoreUUIDTokenStream {
            text,
            chars: text.char_indices(),
            token: &mut self.token,
        }
    }
}

impl SimpleIgnoreUUIDTokenStream<'_> {
    // search for the end of the current token.
    fn search_token_end(&mut self) -> usize {
        (&mut self.chars)
            .filter(|(_, c)| !c.is_alphanumeric())
            .map(|(offset, _)| offset)
            .next()
            .unwrap_or(self.text.len())
    }

    fn try_find_uuid_offset_to(&mut self, offset_from: usize) -> Option<usize> {
        let last_index = offset_from + UUID_LEN - 1;
        if last_index >= self.text.len() {
            return None;
        }

        if !self.text.is_char_boundary(last_index + 1) {
            return None;
        }

        let maybe_uuid_chars = &self.text[offset_from..(last_index + 1)];
        if !is_likely_uuid(maybe_uuid_chars) {
            return None;
        }
        let mut offset_to = 0;
        // -1 to accommodate the already read first char by calling next() in the caller func.
        for _ in 0..UUID_LEN - 1 {
            let (offset, _) = self.chars.next().unwrap();
            offset_to = offset;
        }
        Some(offset_to + 1)
    }
}

fn is_likely_uuid(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
        return false;
    }

    for (i, &b) in bytes.iter().enumerate() {
        if !matches!(i, 8 | 13 | 18 | 23) && !b.is_ascii_hexdigit() {
            return false;
        }
    }

    true
}

impl TokenStream for SimpleIgnoreUUIDTokenStream<'_> {
    fn advance(&mut self) -> bool {
        self.token.text.clear();
        self.token.position = self.token.position.wrapping_add(1);
        while let Some((offset_from, c)) = self.chars.next() {
            if c.is_alphanumeric() {
                let offset_to = self
                    .try_find_uuid_offset_to(offset_from)
                    .unwrap_or_else(|| self.search_token_end());
                self.token.offset_from = offset_from;
                self.token.offset_to = offset_to;
                self.token.text.push_str(&self.text[offset_from..offset_to]);
                return true;
            }
        }
        false
    }

    fn token(&self) -> &Token {
        self.token
    }

    fn token_mut(&mut self) -> &mut Token {
        self.token
    }
}

#[cfg(test)]
mod tests {
    use tantivy::tokenizer::{TextAnalyzer, Token};

    use super::SimpleIgnoreUUIDTokenizer;

    /// This is a function that can be used in tests and doc tests
    /// to assert a token's correctness.
    fn assert_token(token: &Token, position: usize, text: &str, from: usize, to: usize) {
        assert_eq!(
            token.position, position,
            "expected position {position} but {token:?}"
        );
        assert_eq!(token.text, text, "expected text {text} but {token:?}");
        assert_eq!(
            token.offset_from, from,
            "expected offset_from {from} but {token:?}"
        );
        assert_eq!(token.offset_to, to, "expected offset_to {to} but {token:?}");
    }

    fn token_stream_helper(text: &str) -> Vec<Token> {
        let mut a = TextAnalyzer::from(SimpleIgnoreUUIDTokenizer::default());
        let mut token_stream = a.token_stream(text);
        let mut tokens: Vec<Token> = vec![];
        let mut add_token = |token: &Token| {
            tokens.push(token.clone());
        };
        token_stream.process(&mut add_token);
        tokens
    }

    #[test]
    fn test_simple_tokenizer() {
        let tokens = token_stream_helper("Hello, happy tax payer!");
        assert_eq!(tokens.len(), 4);
        assert_token(&tokens[0], 0, "Hello", 0, 5);
        assert_token(&tokens[1], 1, "happy", 7, 12);
        assert_token(&tokens[2], 2, "tax", 13, 16);
        assert_token(&tokens[3], 3, "payer", 17, 22);
    }

    #[test]
    fn test_uuid_tokenizer() {
        let tokens = token_stream_helper("123e4567-e89b-12d3-a456-426614174000");
        assert_eq!(tokens.len(), 1);
        assert_token(&tokens[0], 0, "123e4567-e89b-12d3-a456-426614174000", 0, 36);
    }

    #[test]
    fn test_simple_with_uuid_tokenizer() {
        let tokens = token_stream_helper("Hello, 123e4567-e89b-12d3-a456-426614174000 Hi");
        assert_eq!(tokens.len(), 3);
        assert_token(&tokens[0], 0, "Hello", 0, 5);
        assert_token(&tokens[1], 1, "123e4567-e89b-12d3-a456-426614174000", 7, 43);
        assert_token(&tokens[2], 2, "Hi", 44, 46);
    }

    #[test]
    fn test_unicode_should_not_be_accessed_within_the_char_boundary() {
        // A UUID is 36 chars long.
        // In this test, the 36th char is unicode with size of 3 bytes.
        // If we try to slice the string in 0..37 it will panic - as byte index 36 is not a char
        // boundary.
        let tokens = token_stream_helper("35/chars/then/unicode/AAAAAAAAAAAA/发");
        assert_eq!(tokens.len(), 6);
        assert_token(&tokens[0], 0, "35", 0, 2);
        assert_token(&tokens[1], 1, "chars", 3, 8);
        assert_token(&tokens[2], 2, "then", 9, 13);
        assert_token(&tokens[3], 3, "unicode", 14, 21);
        assert_token(&tokens[4], 4, "AAAAAAAAAAAA", 22, 34);
        assert_token(&tokens[5], 5, "发", 35, 38);
    }
}
