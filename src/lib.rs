mod client;
mod io;
mod request;
mod response;

pub use http::Uri;
use thiserror::Error;

pub use http;

pub use client::*;
pub use response::ResponseHeaders;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Url has no host")]
    NoHost,
    #[error("No address")]
    NoAddress,
    #[error("No status in response")]
    MissingStatus,
    #[error("Not connected")]
    NotConnected,
    #[error("Conversion error: {0}")]
    Conversion(&'static str),
    #[error("Http error: {0}")]
    Http(#[from] http::Error),
    #[error("httparse error: {0}")]
    Httparse(#[from] httparse::Error),
    #[error("io error")]
    TokioIo(#[from] tokio::io::Error),
    #[error("Invalid header name")]
    InvalidHeaderName(#[from] http::header::InvalidHeaderName),
    #[error("Invalid header value")]
    InvalidHeaderValue(#[from] http::header::InvalidHeaderValue),
    #[error("Invalid status code")]
    InvalidStatus(#[from] http::status::InvalidStatusCode),
    #[error("Max headers size reached")]
    MaxHeadersSize(#[from] http::header::MaxSizeReached),
    #[error("Header value conversion error")]
    HeaderStr(#[from] http::header::ToStrError),
    #[error("Failed parsing integer")]
    ParseInt(#[from] std::num::ParseIntError),
    #[cfg(feature = "rustls")]
    #[error("Invalid DNS name")]
    InvalidDNSName(#[from] rustls::pki_types::InvalidDnsNameError),
}

pub type Result<T> = std::result::Result<T, Error>;

pub fn path_query(url: &http::Uri) -> &str {
    match url.path_and_query() {
        Some(pq) => pq.as_str(),
        None => "/",
    }
}

pub fn credentials_from_url(url: &http::Uri) -> Option<(&str, &str)> {
    let authority = url.authority().unwrap().as_str();
    if let Some((creds, _)) = authority.split_once('@') {
        creds.split_once(":")
    } else {
        None
    }
}
