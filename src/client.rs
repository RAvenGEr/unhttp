use bytes::{Buf, Bytes, BytesMut};
use http::{HeaderMap, HeaderValue, Request, StatusCode, Version, header};
use http_body::Body;
use http_body_util::Empty;
use log::{debug, info, warn};
use memchr::{memchr, memmem};

use super::*;

/// An async HTTP client
/// Supports HTTP 1.1 or 1.0, no HTTPS
pub struct Client {
    conn: io::Connection,
    rx_buf: io::ReadBuffer,
    credentials: Option<Credentials>,
    max_redirects: u32,
    keep_alive: bool,
    allow_basic_auth: bool,
}

impl Client {
    pub fn new() -> Self {
        Self {
            conn: io::Connection::default(),
            rx_buf: io::ReadBuffer::new(),
            credentials: None,
            max_redirects: 1,
            keep_alive: true,
            allow_basic_auth: false,
        }
    }

    /// Set credentials for Digest Authentication
    /// TODO: Consider supporting Basic Authentication
    pub fn credentials<S: Into<String>, T: Into<String>>(
        &mut self,
        username: S,
        password: T,
    ) -> &mut Self {
        self.credentials = Some(Credentials::new(username.into(), password.into()));
        self
    }

    /// Set the minimum bytes available for read operations
    pub fn read_buffer_reservation(&mut self, size: usize) -> &mut Self {
        self.rx_buf.set_min_read(size);
        self
    }

    pub fn keep_alive(&mut self, keep_alive: bool) -> &mut Self {
        self.keep_alive = keep_alive;
        self
    }

    pub fn allow_basic_auth(&mut self, allow_basic: bool) -> &mut Self {
        self.allow_basic_auth = allow_basic;
        self
    }

    /// Send a request to the remote and read any response
    pub async fn send_request<B: http_body::Body>(mut self, req: Request<B>) -> Result<Response> {
        request::write_request(&mut self.conn, &req).await?;
        // Read Response
        let mut ctx: response::ResponseCtx<64> = response::ResponseCtx::new();
        let resp = loop {
            self.read().await?;
            let buf = self.rx_buf.as_ref();
            if let Some(res) = ctx.parse(buf)? {
                // Remove header data from read buffer
                self.rx_buf.advance(ctx.size());
                break Response::from_response_headers(res, self);
            }
        };
        // Attempt authentication if we have credentials and the server requires it
        if resp.must_authenticate() && resp.can_authenticate() {
            Box::pin(resp.authenticate_request(req)).await
        } else {
            // TODO: Handle redirect
            Ok(resp)
        }
    }

    /// Perform a GET request
    pub async fn get(mut self, url: http::Uri) -> Result<Response> {
        let (url, creds) = strip_credentials(url);

        let host = url.host().ok_or(Error::NoHost)?;
        let port = port_from(&url);

        // Don't clear any credentials previously set, only change if url has credentials
        if creds.is_some() {
            self.credentials = creds;
        }

        let req = Request::builder()
            .uri(&url)
            .header(header::USER_AGENT, "Unhttp")
            .header(header::CONNECTION, "keep-alive")
            .header(header::HOST, host)
            .body(Empty::<Bytes>::new())?;
        #[cfg(feature = "rustls")]
        self.conn.connect_to(host, port, use_tls(req.uri())).await?;
        #[cfg(not(feature = "rustls"))]
        self.conn.connect_to(host, port).await?;

        self.send_request(req).await
    }

    /// Read some bytes from the server
    pub async fn read_some(&mut self) -> Result<BytesMut> {
        self.read_while(|s| s.rx_buf.is_empty()).await?;
        let buf = self.rx_buf.split();
        Ok(buf)
    }

    /// Read until the read buffer contains `needle`
    pub async fn read_until(&mut self, needle: &[u8]) -> Result<BytesMut> {
        let mut last_end = 0;
        let mut end = None;
        self.read_while(|s| {
            let start = if last_end > needle.len() {
                last_end - needle.len()
            } else {
                0
            };
            let slice = &s.rx_buf.as_ref()[start..];
            last_end = s.rx_buf.len();
            end = memmem::find(slice, needle).map(|p| p + start + needle.len());
            end.is_none()
        })
        .await?;
        let buf = if let Some(e) = end {
            self.rx_buf.split_to(e)
        } else {
            warn!("read_until without end");
            self.rx_buf.split()
        };
        Ok(buf)
    }

    async fn read_while<F: FnMut(&Self) -> bool>(&mut self, mut check: F) -> Result<()> {
        while check(self) {
            self.read().await?;
        }
        Ok(())
    }

    #[inline]
    async fn read(&mut self) -> Result<()> {
        self.rx_buf.read_from(&mut self.conn).await
    }
}

impl Default for Client {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for Client {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Client")
            .field("conn", &self.conn)
            .field("credentials", &self.credentials)
            .field("max_redirects", &self.max_redirects)
            .field("keep_alive", &self.keep_alive)
            .field("allow_basic_auth", &self.allow_basic_auth)
            .finish()
    }
}

#[derive(Debug)]
pub struct Response {
    headers: ResponseHeaders,
    client: Client,
    content_length: Option<usize>,
}

impl Response {
    pub fn from_response_headers(headers: ResponseHeaders, client: Client) -> Self {
        let content_length = headers.content_length();
        let must_close = !client.keep_alive || !headers.keep_alive();
        let mut client = client;
        client.conn.must_close = must_close;
        Self {
            headers,
            client,
            content_length,
        }
    }

    pub fn into_inner(self) -> Client {
        self.client
    }

    pub fn status(&self) -> StatusCode {
        self.headers.status
    }

    pub fn version(&self) -> Version {
        self.headers.version
    }

    pub fn headers(&self) -> &HeaderMap {
        &self.headers.headers
    }

    pub fn must_authenticate(&self) -> bool {
        self.headers().get(header::WWW_AUTHENTICATE).is_some()
    }

    pub fn can_authenticate(&self) -> bool {
        self.client.credentials.is_some()
    }

    pub async fn authenticate_request<T: Body>(mut self, mut req: Request<T>) -> Result<Self> {
        if let Some(creds) = self.client.credentials.as_ref() {
            let authorization =
                if let Ok(mut auth) = digest_access::DigestAccess::try_from(self.headers()) {
                    let path = path_query(req.uri());
                    auth.set_username(creds.username.as_str());
                    auth.set_password(creds.password.as_str());

                    let body = self.body().await?;
                    // Unwrap `generate_authorization` only fails if set_username and set_password are not called
                    auth.generate_authorization("GET", path, body.as_deref(), None)
                        .unwrap()
                } else if self.client.allow_basic_auth && self.require_basic_auth() {
                    use base64::prelude::*;
                    let auth = format!("{}:{}", creds.username, creds.password);
                    BASE64_STANDARD.encode(auth)
                } else {
                    // Unable to authenticate return self??
                    return Ok(self);
                };

            let val = HeaderValue::from_bytes(authorization.as_bytes())?;
            // Repeat the original request with the AUTHORIZATION header
            req.headers_mut().insert(header::AUTHORIZATION, val);
            let host = req.uri().host().ok_or(Error::NoHost)?;
            let port = port_from(req.uri());

            info!("Resending with Digest Authentication...");
            #[cfg(feature = "rustls")]
            self.client
                .conn
                .connect_to(host, port, use_tls(req.uri()))
                .await?;
            #[cfg(not(feature = "rustls"))]
            self.client.conn.connect_to(host, port).await?;
            self.client.send_request(req).await
        } else {
            Err(Error::NoCredentials(self))
        }
    }

    /// Read the response body, if there is a content-length
    pub async fn body(&mut self) -> Result<Option<BytesMut>> {
        match self.content_length {
            Some(0) | None => Ok(None),
            Some(l) => {
                self.client.read_while(|s| s.rx_buf.len() < l).await?;
                self.content_length = None;
                if self.client.conn.must_close {
                    self.client.conn.disconnect();
                }
                Ok(Some(self.client.rx_buf.split_to(l)))
            }
        }
    }

    pub fn require_basic_auth(&self) -> bool {
        // Test if basic authentication is required
        const BASIC: &[u8] = b"basic";
        let auth_headers = self.headers().get_all(header::WWW_AUTHENTICATE);
        for a in auth_headers.iter() {
            if a.len() > BASIC.len() && a.as_bytes()[..BASIC.len() - 1].eq_ignore_ascii_case(BASIC)
            {
                return true;
            }
        }
        false
    }
}

pub struct ResponseConversionError {
    response: Response,
    error: Error,
}

impl ResponseConversionError {
    fn new(response: Response, error: Error) -> Self {
        Self { response, error }
    }

    fn with_message(response: Response, message: &'static str) -> Self {
        Self::new(response, Error::Conversion(message))
    }

    pub fn into_parts(self) -> (Response, Error) {
        (self.response, self.error)
    }
}

/// A Client wrapper that can extract multipart streaming data
pub struct MultipartReplaceClient {
    inner: Client,
    content_type: Bytes,
    boundary: Bytes,
}

impl MultipartReplaceClient {
    /// Create a multipart client from a connected client server's response
    /// On failure, the client is returned in `ResponseConversionError` for re-use
    pub fn from_response(response: Response) -> std::result::Result<Self, ResponseConversionError> {
        if let Some(content) = response.headers().get(header::CONTENT_TYPE) {
            if let Some(boundary) = multipart_replace(content.as_bytes()) {
                let content_type = Bytes::copy_from_slice(content.as_bytes());
                debug!(
                    "Have multipart with type: `{}` boundary: `{}`",
                    String::from_utf8_lossy(&content_type),
                    String::from_utf8_lossy(&boundary)
                );
                let c = Self {
                    inner: response.client,
                    content_type,
                    boundary,
                };
                return Ok(c);
            }
        }
        Err(ResponseConversionError::with_message(
            response,
            "Invalid headers",
        ))
    }

    /// Take the client to reuse
    pub fn into_inner(self) -> Client {
        self.inner
    }

    /// The content-type reported by the server response
    pub fn content_type(&self) -> Bytes {
        self.content_type.clone()
    }

    /// Read the next boundary delimited part
    pub async fn next_part(&mut self) -> Result<BytesMut> {
        let mut extended = self.inner.read_until(&self.boundary).await?;
        let chunk = if extended.ends_with(&self.boundary) {
            let new_end = extended.len() - self.boundary.len();
            extended.split_to(new_end)
        } else {
            // This is a paranoia check.
            // Execution of this code should NOT should be possible due to the implementation of
            // `Client::read_until`
            warn!("Unexpected chunk without boundary");
            extended
        };
        Ok(chunk)
    }

    /// Read a content-length prefixed part
    /// Useful for alternative multipart implementation on the server where --boundary precedes the
    /// data and the data part has a Content-Length header
    /// NOTE: Only returns the content if a header is present
    pub async fn next_part_sized(&mut self) -> Result<BytesMut> {
        loop {
            let ext = ContentExtents::from_buffer(self.inner.rx_buf.as_ref(), &self.boundary);
            if let Some(pos) = ext.content_end() {
                self.inner.read_while(|s| s.rx_buf.len() < pos).await?;
                let mut used = self.inner.rx_buf.split_to(pos);
                // Checked in ContentExtents::content_end()
                let start = ext.header_end.unwrap();
                // Consume headers
                // TODO: Expose part headers
                used.advance(start);
                return Ok(used);
            } else if let Some(bound) = ext.boundary {
                // Fallback if no content length found
                if bound > 0 && !is_only_ascii_whitespace(&self.inner.rx_buf.as_ref()[..bound]) {
                    return Ok(self.inner.rx_buf.split_to(bound));
                }
            }
            self.inner.read().await?;
        }
    }
}

/// Find a multipart replace boundary, if it exists in the content-type header
fn multipart_replace(content_type: &[u8]) -> Option<Bytes> {
    // Content-Type: multipart/x-mixed-replace; boundary=myboundary
    const MULTIPART_TYPE: &[u8] = b"multipart/x-mixed-replace";
    const BOUNDARY_KEY: &[u8] = b"boundary=";
    const BOUNDARY_PREFIX: &[u8] = b"--";

    let sep = memchr(b';', content_type)?;
    let (first, ext) = content_type.split_at_checked(sep)?;

    if first.eq_ignore_ascii_case(MULTIPART_TYPE) {
        let pos = memmem::find(ext, BOUNDARY_KEY)?;
        let (_, bound) = ext.split_at_checked(pos + BOUNDARY_KEY.len())?;
        let mut boundary = BytesMut::from(BOUNDARY_PREFIX);
        boundary.extend_from_slice(bound);
        Some(boundary.into())
    } else {
        None
    }
}

/// Representation of the segments within a multipart part
#[derive(Debug, Default, PartialEq, Eq)]
struct ContentExtents {
    boundary: Option<usize>,
    header_end: Option<usize>,
    content_length: Option<usize>,
}

impl ContentExtents {
    fn content_end(&self) -> Option<usize> {
        match (self.header_end, self.content_length) {
            (Some(start), Some(len)) => Some(start + len),
            _ => None,
        }
    }

    #[cfg(test)]
    fn content<'buf>(&self, buf: &'buf [u8]) -> Option<&'buf [u8]> {
        match (self.header_end, self.content_length) {
            (Some(start), Some(len)) => {
                if start + len <= buf.len() {
                    let cont = &buf[start..start + len];
                    Some(cont)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn from_buffer(buf: &[u8], boundary: &[u8]) -> ContentExtents {
        let mut ext = ContentExtents::default();
        if let Some(pos) = memmem::find(buf, boundary) {
            ext.boundary = Some(pos);
            // Ensure only empty lines precede boundary marker
            if let Some((pre, chunk)) = buf.split_at_checked(pos) {
                if is_only_ascii_whitespace(pre) {
                    let mut start = boundary.len();
                    // Skip whitespace
                    while chunk[start].is_ascii_whitespace() && start < chunk.len() {
                        start += 1;
                    }
                    if let Some((l, b)) = read_length_header(&chunk[start..]) {
                        ext.header_end = Some(pos + start + b);
                        ext.content_length = Some(l);
                    }
                }
            }
        }
        ext
    }
}

#[inline]
fn is_only_ascii_whitespace(data: &[u8]) -> bool {
    for c in data {
        if !c.is_ascii_whitespace() {
            return false;
        }
    }
    true
}

fn read_length_header(chunk: &[u8]) -> Option<(usize, usize)> {
    let mut headers = [httparse::EMPTY_HEADER; 8];
    if let Ok(parsed) = httparse::parse_headers(chunk, &mut headers) {
        match parsed {
            httparse::Status::Complete((bytes, head)) => {
                let mut length: Option<usize> = None;
                // TODO: Consider how to return these headers
                for h in head {
                    if h.name.eq_ignore_ascii_case(header::CONTENT_LENGTH.as_str()) {
                        if let Ok(l) = String::from_utf8_lossy(h.value).parse() {
                            if length.is_some_and(|n| n == l) {
                                warn!("Have multiple content length headers");
                                return None;
                            }
                            length = Some(l);
                        }
                    }
                }
                return length.map(|l| (l, bytes));
            }
            httparse::Status::Partial => (),
        }
    }
    None
}

#[cfg(not(feature = "rustls"))]
#[inline]
fn port_from(url: &Uri) -> u16 {
    url.port_u16().unwrap_or(80)
}

#[cfg(feature = "rustls")]
#[inline]
fn port_from(url: &Uri) -> u16 {
    url.port_u16().unwrap_or_else(|| {
        if url.scheme_str() == Some("https") {
            443
        } else {
            80
        }
    })
}

#[cfg(feature = "rustls")]
#[inline]
fn use_tls(url: &Uri) -> bool {
    url.scheme_str() == Some("https")
}

/// Strip any credentials from a url, returning to the caller any extracted credentials
fn strip_credentials(url: Uri) -> (Uri, Option<Credentials>) {
    let mut credentials = None;
    let mut parts = url.into_parts();
    if let Some(aut) = parts.authority.as_ref() {
        if let Some((creds, rest)) = aut.as_str().split_once('@') {
            if let Some((username, password)) = creds.split_once(':') {
                credentials = Some(Credentials::new(username, password));
            }
            parts.authority = Some(rest.parse().expect("Had invalid url"));
        }
    }
    (
        Uri::from_parts(parts).expect("Had invalid url"),
        credentials,
    )
}

#[cfg(test)]
mod test {
    use super::*;

    const FIRST_PACKET: [u8; 73] = [
        0x0d, 0x0a, 0x2d, 0x2d, 0x6d, 0x79, 0x62, 0x6f, 0x75, 0x6e, 0x64, 0x61, 0x72, 0x79, 0x0d,
        0x0a, 0x43, 0x6f, 0x6e, 0x74, 0x65, 0x6e, 0x74, 0x2d, 0x54, 0x79, 0x70, 0x65, 0x3a, 0x20,
        0x74, 0x65, 0x78, 0x74, 0x2f, 0x70, 0x6c, 0x61, 0x69, 0x6e, 0x0d, 0x0a, 0x43, 0x6f, 0x6e,
        0x74, 0x65, 0x6e, 0x74, 0x2d, 0x4c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3a, 0x39, 0x0d, 0x0a,
        0x0d, 0x0a, 0x48, 0x65, 0x61, 0x72, 0x74, 0x62, 0x65, 0x61, 0x74, 0x0d, 0x0a,
    ];
    const BOUNDARY: &[u8] = b"--myboundary";

    const EXPECTED: ContentExtents = ContentExtents {
        boundary: Some(2),
        header_end: Some(62),
        content_length: Some(9),
    };

    const FIRST_CONTENT: &[u8] = b"Heartbeat";

    #[test]
    fn first_chunk() {
        let ext = ContentExtents::from_buffer(&FIRST_PACKET, BOUNDARY);
        assert_eq!(EXPECTED, ext);
        let content = ext.content(&FIRST_PACKET);
        assert_eq!(Some(FIRST_CONTENT), content);
    }
}
