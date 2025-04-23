use std::{sync::Arc, task::Poll};

use rustls::{ClientConfig, pki_types::ServerName};
use rustls_platform_verifier::ConfigVerifierExt;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::{TlsConnector, client::TlsStream};

use super::*;

#[derive(Debug, Default)]
enum AnyStream {
    Tls(TlsStream<TcpStream>),
    Tcp(TcpStream),
    #[default]
    None,
}

impl AnyStream {
    pub fn is_some(&self) -> bool {
        !matches!(self, AnyStream::None)
    }
}

/// A TLS or TCP connection to a remote peer
#[derive(Debug, Default)]
pub struct Connection {
    stream: AnyStream,
    addr: Option<(String, u16)>,
    tls: bool,
    pub(crate) must_close: bool,
}

impl Connection {
    pub async fn connect_to(&mut self, host: &str, port: u16, tls: bool) -> Result<()> {
        let same_stream = tls == self.tls;
        self.tls = tls;
        if !same_stream || !self.connected_to(host, port) || self.must_close {
            self.set_addr(host, port).connect().await?;
        }
        Ok(())
    }

    pub async fn connect(&mut self) -> Result<()> {
        self.disconnect();
        let addr = self.addr.as_ref().ok_or(Error::NoAddress)?;
        if self.tls {
            let config = ClientConfig::with_platform_verifier();
            let connector = TlsConnector::from(Arc::new(config));
            let name = addr.0.clone();
            let dnsname = ServerName::try_from(name)?;
            let stream = TcpStream::connect(&addr).await?;
            let stream = connector.connect(dnsname, stream).await?;
            self.stream = AnyStream::Tls(stream);
        } else {
            self.stream = AnyStream::Tcp(TcpStream::connect(addr).await?);
        }
        Ok(())
    }

    #[inline]
    pub fn disconnect(&mut self) {
        self.stream = AnyStream::None;
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
        match self.stream {
            AnyStream::Tls(ref mut s) => Pin::new(s).poll_read(cx, buf),
            AnyStream::Tcp(ref mut s) => Pin::new(s).poll_read(cx, buf),
            AnyStream::None => Poll::Ready(Err(tokio::io::ErrorKind::NotConnected.into())),
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
        match self.stream {
            AnyStream::Tls(ref mut s) => Pin::new(s).poll_write(cx, buf),
            AnyStream::Tcp(ref mut s) => Pin::new(s).poll_write(cx, buf),
            AnyStream::None => Poll::Ready(Err(tokio::io::ErrorKind::NotConnected.into())),
        }
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        match self.stream {
            AnyStream::Tls(ref mut s) => Pin::new(s).poll_write_vectored(cx, bufs),
            AnyStream::Tcp(ref mut s) => Pin::new(s).poll_write_vectored(cx, bufs),
            AnyStream::None => Poll::Ready(Err(tokio::io::ErrorKind::NotConnected.into())),
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
        match self.stream {
            AnyStream::Tls(ref mut s) => Pin::new(s).poll_flush(cx),
            AnyStream::Tcp(ref mut s) => Pin::new(s).poll_flush(cx),
            AnyStream::None => Poll::Ready(Err(tokio::io::ErrorKind::NotConnected.into())),
        }
    }

    #[inline]
    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::result::Result<(), std::io::Error>> {
        match self.stream {
            AnyStream::Tls(ref mut s) => Pin::new(s).poll_shutdown(cx),
            AnyStream::Tcp(ref mut s) => Pin::new(s).poll_shutdown(cx),
            AnyStream::None => Poll::Ready(Err(tokio::io::ErrorKind::NotConnected.into())),
        }
    }
}
