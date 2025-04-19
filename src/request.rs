use http::{HeaderMap, Request, Version};
use http_body::Body;
use log::debug;
use tokio::io::AsyncWriteExt;

use super::*;

const INITIAL_ENCODE_CAPACITY: usize = 2048;

/// Take a Request, encode its headers and write them
pub(super) async fn write_request<T: AsyncWriteExt + Unpin, B: http_body::Body>(
    write: &mut T,
    req: &Request<B>,
) -> Result<()> {
    let mut dst = Vec::with_capacity(INITIAL_ENCODE_CAPACITY);

    encode(req, &mut dst)?;

    write.write_all(&dst).await?;
    // TODO: Handle a body
    Ok(())
}

// Below encoding is somewhat based on Hyper Client::encode, heavily simplified

fn encode<B: Body>(req: &Request<B>, dst: &mut Vec<u8>) -> Result<()> {
    dst.extend_from_slice(req.method().as_str().as_bytes());
    dst.extend_from_slice(b" ");
    dst.extend_from_slice(path_query(req.uri()).as_bytes());

    let ver = match req.version() {
        Version::HTTP_10 => b" HTTP/1.0",
        Version::HTTP_11 => b" HTTP/1.1",
        Version::HTTP_2 => {
            debug!("request with HTTP2 version coerced to HTTP/1.1");
            b" HTTP/1.1"
        }
        other => panic!("unexpected request version: {:?}", other),
    };

    dst.extend_from_slice(ver);
    dst.extend_from_slice(b"\r\n");

    write_headers(req.headers(), dst);

    dst.extend_from_slice(b"\r\n");

    Ok(())
}

fn write_headers(headers: &HeaderMap, dst: &mut Vec<u8>) {
    for (name, value) in headers {
        dst.extend_from_slice(name.as_str().as_bytes());
        dst.extend_from_slice(b": ");
        dst.extend_from_slice(value.as_bytes());
        dst.extend_from_slice(b"\r\n");
    }
}
