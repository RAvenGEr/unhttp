use std::pin::Pin;

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt};

#[cfg(feature = "rustls")]
mod tls;
#[cfg(feature = "rustls")]
pub use tls::Connection;

#[cfg(not(feature = "rustls"))]
mod tcp;
#[cfg(not(feature = "rustls"))]
pub use tcp::Connection;

use super::*;

const DEFAULT_MIN_READ: usize = 2048;

/// A buffer suitable for read operations
/// A thin wrapper around `BytesMut` that ensures a minimum free space for read operations
pub struct ReadBuffer {
    buf: BytesMut,
    min_read: usize,
}

impl ReadBuffer {
    pub(crate) fn new() -> Self {
        Self {
            buf: BytesMut::with_capacity(0),
            min_read: DEFAULT_MIN_READ,
        }
    }

    pub(crate) fn set_min_read(&mut self, min: usize) -> &mut Self {
        self.min_read = min;
        self
    }

    #[inline]
    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.buf.len()
    }

    #[inline]
    pub(crate) fn as_ref(&self) -> &[u8] {
        self.buf.as_ref()
    }

    #[inline]
    pub(crate) fn clear(&mut self) {
        self.buf.clear();
    }

    #[inline]
    pub(crate) fn split(&mut self) -> BytesMut {
        self.buf.split()
    }

    #[inline]
    pub(crate) fn split_to(&mut self, cnt: usize) -> BytesMut {
        self.buf.split_to(cnt)
    }

    #[inline]
    pub(crate) fn advance(&mut self, cnt: usize) {
        self.buf.advance(cnt);
    }

    /// Read some data into this buffer
    pub(crate) async fn read_from<T: AsyncRead + Unpin>(&mut self, read: &mut T) -> Result<()> {
        if self.buf.remaining_mut() < self.min_read {
            self.buf.reserve(self.min_read);
        }
        read.read_buf(&mut self.buf).await?;
        Ok(())
    }
}
