use bytes::{Buf, BufMut, BytesMut};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::{
        TcpStream,
        tcp::{ReadHalf, WriteHalf},
    },
};

use super::*;

const DEFAULT_MIN_READ: usize = 2048;

/// A connection to a remote peer
#[derive(Debug, Default)]
pub struct Connection {
    stream: Option<TcpStream>,
    addr: Option<(String, u16)>,
    must_close: bool,
}

impl Connection {
    pub(super) async fn connect_to(&mut self, host: &str, port: u16) -> Result<()> {
        if !self.connected_to(host, port) || self.must_close {
            self.set_addr(host, port).connect().await?;
        }
        Ok(())
    }

    pub(super) async fn connect(&mut self) -> Result<()> {
        self.disconnect();
        let addr = self.addr.as_ref().ok_or(Error::NoAddress)?;
        self.stream = Some(TcpStream::connect(addr).await?);
        Ok(())
    }

    #[inline]
    pub(super) fn disconnect(&mut self) {
        self.stream = None;
    }

    pub(super) fn read(&mut self) -> Result<ReadHalf<'_>> {
        if let Some(sock) = self.stream.as_mut() {
            let (read, _w) = sock.split();
            Ok(read)
        } else {
            Err(Error::NotConnected)
        }
    }

    pub(super) fn write(&mut self) -> Result<WriteHalf<'_>> {
        if let Some(sock) = self.stream.as_mut() {
            let (_r, write) = sock.split();
            Ok(write)
        } else {
            Err(Error::NotConnected)
        }
    }

    pub(super) fn set_addr(&mut self, host: impl Into<String>, port: u16) -> &mut Self {
        self.addr = Some((host.into(), port));
        self
    }

    pub(super) fn connected_to(&self, host: &str, port: u16) -> bool {
        if let Some((h, p)) = self.addr.as_ref() {
            if host == h && port == *p {
                return self.stream.is_some();
                // TODO: Check the port??
            }
        }
        false
    }
}

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
