use http::{HeaderMap, HeaderName, HeaderValue, StatusCode, Version, header};
use httparse::ParserConfig;

use super::{Error, Result};

/// A structure for the response headers, without any support for a body
/// Simplified from `http`
pub struct ResponseHeaders {
    /// The response's status
    pub status: StatusCode,

    /// The response's version
    pub version: Version,

    /// The response's headers
    pub headers: HeaderMap<HeaderValue>,
}

/// The context and result store for `httparser`
pub struct ResponseCtx<const CAP: usize> {
    prev_len: usize,
    parse_size: usize,
}

impl<const CAP: usize> ResponseCtx<CAP> {
    pub fn new() -> Self {
        Self {
            prev_len: 0,
            parse_size: 0,
        }
    }

    /// Extract response headers from a buffer
    pub fn parse(&mut self, buf: &[u8]) -> Result<Option<ResponseHeaders>> {
        let prev_len = self.prev_len;
        self.prev_len = buf.len();
        if prev_len > 0 && !is_complete_fast(buf, prev_len) {
            return Ok(None);
        }
        let mut headers = [httparse::EMPTY_HEADER; CAP];
        let mut response = httparse::Response::new(&mut headers);
        let res = ParserConfig::default()
            .allow_obsolete_multiline_headers_in_responses(true)
            .ignore_invalid_headers_in_responses(true)
            .parse_response(&mut response, buf)?;
        match res {
            httparse::Status::Complete(s) => {
                self.parse_size = s;
                let r = response.try_into()?;
                Ok(Some(r))
            }
            httparse::Status::Partial => Ok(None),
        }
    }

    pub fn size(&self) -> usize {
        self.parse_size
    }
}

impl ResponseHeaders {
    pub fn keep_alive(&self) -> bool {
        if self.version == Version::HTTP_11 {
            if let Some(v) = self.headers.get(header::CONNECTION) {
                if !v.as_bytes().eq_ignore_ascii_case(b"close") {
                    return true;
                }
            }
        }
        false
    }
}

impl<'a, 'b> TryFrom<httparse::Response<'a, 'b>> for ResponseHeaders {
    type Error = Error;

    fn try_from(value: httparse::Response<'a, 'b>) -> std::result::Result<Self, Self::Error> {
        let status = value.code.ok_or(Error::MissingStatus)?;
        let status = StatusCode::from_u16(status)?;
        let version = match value.version {
            Some(1) => Version::HTTP_11,
            _ => Version::HTTP_10,
        };

        let mut headers = HeaderMap::with_capacity(value.headers.len());
        for header in value.headers {
            let name = HeaderName::from_bytes(header.name.as_bytes())?;
            let value = HeaderValue::from_bytes(header.value)?;
            headers.insert(name, value);
        }
        let resp = ResponseHeaders {
            status,
            version,
            headers,
        };

        Ok(resp)
    }
}

// From Hyper MIT - Copyright (c) 2014-2025 Sean McArthur
/// Find the header terminator before attempting to parse
fn is_complete_fast(bytes: &[u8], prev_len: usize) -> bool {
    let start = if prev_len < 3 { 0 } else { prev_len - 3 };
    let bytes = &bytes[start..];

    for (i, b) in bytes.iter().copied().enumerate() {
        if b == b'\r' {
            if bytes[i + 1..].chunks(3).next() == Some(&b"\n\r\n"[..]) {
                return true;
            }
        } else if b == b'\n' && bytes.get(i + 1) == Some(&b'\n') {
            return true;
        }
    }

    false
}
