use std::{task::Poll, time::Duration};

use tokio::{io::AsyncWrite, net::TcpStream};

use super::*;

/// A TCP connection to a remote peer
#[derive(Debug, Default)]
pub struct Connection {
    stream: Option<TcpStream>,
    addr: Option<(String, u16)>,
    pub(crate) must_close: bool,
    pub(crate) connect_timeout: Option<Duration>,
}

impl Connection {
    pub async fn connect_to(&mut self, host: &str, port: u16) -> Result<()> {
        if !self.connected_to(host, port) || self.must_close {
            self.set_addr(host, port).connect().await?;
        }
        Ok(())
    }

    pub async fn connect(&mut self) -> Result<()> {
        use tokio::time::timeout;
        self.disconnect();
        let addr = self.addr.as_ref().ok_or(Error::NoAddress)?;
        let f = TcpStream::connect(addr);
        let stream = match self.connect_timeout {
            Some(time) => timeout(time, f).await?,
            None => f.await,
        };
        self.stream = Some(stream?);
        Ok(())
    }

    #[inline]
    pub fn disconnect(&mut self) {
        self.stream = None;
    }

    pub fn set_addr(&mut self, host: impl Into<String>, port: u16) -> &mut Self {
        self.addr = Some((host.into(), port));
        self
    }

    pub fn connected_to(&self, host: &str, port: u16) -> bool {
        if let Some((h, p)) = self.addr.as_ref() {
            if host == h && port == *p {
                return self.stream.is_some();
                // TODO: Check the port??
            }
        }
        false
    }
}

impl AsyncRead for Connection {
    #[inline]
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        match self.stream.as_mut() {
            Some(s) => Pin::new(s).poll_read(cx, buf),
            None => Poll::Ready(Err(tokio::io::ErrorKind::NotConnected.into())),
        }
    }
}

impl AsyncWrite for Connection {
    #[inline]
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::result::Result<usize, std::io::Error>> {
        match self.stream.as_mut() {
            Some(s) => Pin::new(s).poll_write(cx, buf),
            None => Poll::Ready(Err(tokio::io::ErrorKind::NotConnected.into())),
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        match self.stream.as_mut() {
            Some(s) => Pin::new(s).poll_write_vectored(cx, bufs),
            None => Poll::Ready(Err(tokio::io::ErrorKind::NotConnected.into())),
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    #[inline]
    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        match self.stream.as_mut() {
            Some(s) => Pin::new(s).poll_flush(cx),
            None => Poll::Ready(Err(tokio::io::ErrorKind::NotConnected.into())),
        }
    }

    #[inline]
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        match self.stream.as_mut() {
            Some(s) => Pin::new(s).poll_shutdown(cx),
            None => Poll::Ready(Err(tokio::io::ErrorKind::NotConnected.into())),
        }
    }
}
