mod client;
mod io;
mod request;
mod response;

pub use http::Uri;
use thiserror::Error;

pub use http;

pub use client::*;

#[derive(Error, Debug)]
pub enum Error {
    #[error("Url has no host")]
    NoHost,
    #[error("No address")]
    NoAddress,
    #[error("No credentials")]
    NoCredentials(Response),
    #[error("Not authorized")]
    NotAuthorized(Response),
    #[error("Too many redirects")]
    TooManyRedirects(Response),
    #[error("Invalid response")]
    InvalidResponse(Response),
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
    #[error("timeout")]
    TokioTimeout,
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
    InvalidDnsName(#[from] rustls::pki_types::InvalidDnsNameError),
}

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Clone)]
pub struct Credentials {
    username: String,
    password: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        const REDACT: &str = "****";
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &REDACT)
            .finish()
    }
}

impl Credentials {
    pub fn new<S: Into<String>, T: Into<String>>(username: S, password: T) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }

    pub fn from_url(url: &http::Uri) -> Option<Self> {
        let authority = url.authority().unwrap().as_str();
        if let Some((creds, _)) = authority.split_once('@') {
            creds
                .split_once(":")
                .map(|(username, password)| Self::new(username, password))
        } else {
            None
        }
    }

    pub fn username(&self) -> &str {
        self.username.as_str()
    }

    pub fn password(&self) -> &str {
        self.password.as_str()
    }

    pub fn set_username<S: Into<String>>(&mut self, username: S) -> &mut Self {
        self.username = username.into();
        self
    }

    pub fn set_password<S: Into<String>>(&mut self, password: S) -> &mut Self {
        self.password = password.into();
        self
    }
}

#[inline]
pub fn path_query(url: &http::Uri) -> &str {
    match url.path_and_query() {
        Some(pq) => pq.as_str(),
        None => "/",
    }
}
