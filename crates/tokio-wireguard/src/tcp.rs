use std::{
    any::type_name,
    fmt,
    future::{poll_fn, Future},
    iter,
    mem::replace,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
};

use bytes::BufMut;
use smoltcp::{
    socket::tcp::{RecvError, SendError, Socket, SocketBuffer},
    wire::IpEndpoint,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, Error, ErrorKind, Interest, ReadBuf, Ready, Result},
    net::{lookup_host, ToSocketAddrs},
    time,
};

use crate::{
    interface::{Allocation, Interface, ToInterface},
    io::{Evented, IO},
};

/// A WireGuard TCP stream
///
/// This type mostly behaves like and shares the same API as [`tokio::net::TcpStream`].
pub struct TcpStream {
    socket: IO<Socket<'static>>,
}

/// A WireGuard TCP listener
///
/// This type mostly behaves like and shares the same API as [`tokio::net::TcpListener`].
pub struct TcpListener {
    interface: Interface,
    allocation: Allocation,
    backlog: Box<[TcpStream]>,
}

impl TcpStream {
    /// Like [`tokio::net::TcpStream::connect`], but on a WireGuard [`Interface`]
    pub async fn connect<A: ToSocketAddrs, I: ToInterface>(addr: A, iface: I) -> Result<TcpStream> {
        let interface = iface.to_interface().await?;
        let targets = lookup_host(addr)
            .await?
            .filter(|addr| interface.address().is_compatible(*addr));

        let mut err: Option<Error> = None;
        for target in targets {
            let Some(allocation) = interface.allocate_tcp(match target {
                SocketAddr::V4(..) => SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)),
                SocketAddr::V6(..) => {
                    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, 0, 0, 0))
                }
            }) else {
                continue;
            };

            let socket = IO::new(
                interface.clone(),
                Socket::new(
                    SocketBuffer::new(vec![0; interface.options().tcp.recv_buffer_size]),
                    SocketBuffer::new(vec![0; interface.options().tcp.send_buffer_size]),
                ),
                Some(allocation),
            );

            if socket
                .interface()
                .connect_tcp(Arc::clone(&socket), allocation, target)
                .await?
                .is_err()
            {
                continue;
            }

            let ready = async {
                loop {
                    let ready = socket.ready(Interest::WRITABLE).await?;
                    if ready & Ready::WRITABLE == Ready::WRITABLE {
                        break Ok(());
                    }
                }
            };
            let timeout = time::timeout(interface.options().tcp.connect_timeout, ready).await;

            match timeout {
                Ok(Ok(..)) => return Ok(TcpStream { socket }),
                Ok(Err(e)) => err = Some(e),
                Err(..) => continue,
            }
        }

        Err(err.unwrap_or_else(|| Error::from(ErrorKind::TimedOut)))
    }

    fn endpoint<F>(&self, f: F) -> Result<SocketAddr>
    where
        F: FnOnce(&mut Socket<'static>) -> Option<IpEndpoint>,
    {
        let endpoint = self
            .socket
            .with(f)?
            .ok_or_else(|| Error::from(ErrorKind::NotConnected))?;
        let address: IpAddr = endpoint.addr.into();
        let port = endpoint.port;

        Ok(SocketAddr::new(address, port))
    }
    /// [`tokio::net::TcpStream::local_addr`]
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint(|s| s.local_endpoint())
    }
    /// [`tokio::net::TcpStream::peer_addr`]
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        self.endpoint(|s| s.remote_endpoint())
    }

    fn peek_io<B: BufMut>(socket: &mut Socket<'static>, mut buf: B) -> Poll<Result<usize>> {
        match socket.peek(buf.remaining_mut()) {
            Ok(data) if data.len() > 0 => {
                buf.put_slice(data);
                Poll::Ready(Ok(data.len()))
            }
            Ok(..) => Poll::Pending,
            Err(RecvError::Finished) => Poll::Ready(Ok(0)),
            Err(RecvError::InvalidState) => {
                Poll::Ready(Err(Error::from(ErrorKind::ConnectionAborted)))
            }
        }
    }
    /// [`tokio::net::TcpStream::peek`]
    pub async fn peek<B: BufMut>(&self, mut buf: B) -> Result<usize> {
        self.socket
            .io(Interest::READABLE, |s| Self::peek_io(s, &mut buf))
            .await
    }
    /// [`tokio::net::TcpStream::poll_peek`]
    pub fn poll_peek<B: BufMut>(&self, cx: &mut Context<'_>, buf: B) -> Poll<Result<usize>> {
        self.socket
            .poll_io(Interest::READABLE, cx, |s| Self::peek_io(s, buf))
    }

    /// [`tokio::net::TcpStream::ready`]
    pub async fn ready(&self, interest: Interest) -> Result<Ready> {
        self.socket.ready(interest).await
    }

    /// [`tokio::net::TcpStream::readable`]
    pub async fn readable(&self) -> Result<()> {
        self.socket.ready(Interest::READABLE).await.map(drop)
    }
    /// [`tokio::net::TcpStream::poll_read_ready`]
    pub fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.socket.poll_ready(Interest::READABLE, cx)
    }

    fn read_io<B: BufMut>(socket: &mut Socket<'static>, mut buf: B) -> Poll<Result<usize>> {
        match socket.recv(|data| {
            let len = usize::min(buf.remaining_mut(), data.len());
            buf.put_slice(&data[..len]);
            (len, len)
        }) {
            Ok(len) if len > 0 => Poll::Ready(Ok(len)),
            Ok(..) => Poll::Pending,
            Err(RecvError::Finished) => Poll::Ready(Ok(0)),
            Err(RecvError::InvalidState) => {
                Poll::Ready(Err(Error::from(ErrorKind::ConnectionAborted)))
            }
        }
    }
    /// [`tokio::net::TcpStream::try_read`]
    pub fn try_read<B: BufMut>(&self, buf: B) -> Result<usize> {
        self.socket.try_io(|s| Self::read_io(s, buf))
    }

    /// [`tokio::net::TcpStream::writable`]
    pub async fn writable(&self) -> Result<()> {
        self.socket.ready(Interest::WRITABLE).await.map(drop)
    }
    /// [`tokio::net::TcpStream::poll_write_ready`]
    pub fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.socket.poll_ready(Interest::WRITABLE, cx)
    }

    fn write_io(socket: &mut Socket<'static>, buf: &[u8]) -> Poll<Result<usize>> {
        match socket.send_slice(buf) {
            Ok(len) if len > 0 => Poll::Ready(Ok(len)),
            Ok(..) => Poll::Pending,
            Err(SendError::InvalidState) => {
                Poll::Ready(Err(Error::from(ErrorKind::ConnectionAborted)))
            }
        }
    }
    /// [`tokio::net::TcpStream::try_write`]
    pub fn try_write(&self, buf: &[u8]) -> Result<usize> {
        self.socket.try_io(|s| Self::write_io(s, buf))
    }

    fn shutdown_io(socket: &mut Socket<'static>) -> Poll<Result<()>> {
        if !socket.may_send() {
            Poll::Ready(Ok(()))
        } else {
            socket.close();
            Poll::Pending
        }
    }

    /// [`tokio::net::TcpStream::split`]
    pub fn split(&self) -> (ReadHalf<'_>, WriteHalf<'_>) {
        (ReadHalf(self), WriteHalf(self))
    }
    /// [`tokio::net::TcpStream::into_split`]
    pub fn into_split(self) -> (OwnedReadHalf, OwnedWriteHalf) {
        let read = OwnedReadHalf(self);
        let write = OwnedWriteHalf(TcpStream {
            socket: read.0.socket.clone(),
        });
        (read, write)
    }

    /// [`tokio::net::TcpStream::nodelay`]
    pub fn nodelay(&self) -> Result<bool> {
        self.socket.with(|s| !s.nagle_enabled())
    }
    /// [`tokio::net::TcpStream::set_nodelay`]
    pub fn set_nodelay(&mut self, nodelay: bool) -> Result<()> {
        self.socket.with(|s| s.set_nagle_enabled(!nodelay))
    }

    /// [`tokio::net::TcpStream::ttl`]
    pub fn ttl(&self) -> Result<u32> {
        self.socket.with(|s| s.hop_limit().unwrap_or(64).into())
    }
    /// [`tokio::net::TcpStream::set_ttl`]
    pub fn set_ttl(&mut self, ttl: u32) -> Result<()> {
        self.socket.with(|s| s.set_hop_limit(ttl.try_into().ok()))
    }

    /// Interface to which this stream is bound
    pub fn interface(&self) -> &Interface {
        self.socket.interface()
    }
}

impl AsyncRead for TcpStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        self.socket
            .poll_io(Interest::READABLE, cx, |s| Self::read_io(s, buf))
            .map_ok(drop)
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        self.socket
            .poll_io(Interest::WRITABLE, cx, |s| Self::write_io(s, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.socket
            .poll_io(Interest::WRITABLE, cx, Self::shutdown_io)
    }
}

impl fmt::Debug for TcpStream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct(type_name::<Self>());
        if let Ok(local_addr) = self.local_addr() {
            f.field("local_addr", &local_addr);
        }
        if let Ok(peer_addr) = self.peer_addr() {
            f.field("peer_addr", &peer_addr);
        }
        f.field("interface", &self.interface()).finish()
    }
}

impl TcpListener {
    fn socket(interface: &Interface, allocation: Allocation) -> Socket<'static> {
        let mut socket = Socket::new(
            SocketBuffer::new(vec![0; interface.options().tcp.recv_buffer_size]),
            SocketBuffer::new(vec![0; interface.options().tcp.send_buffer_size]),
        );
        socket.listen(allocation.address()).unwrap();
        socket
    }

    /// Like [`tokio::net::TcpListener::bind`], but on a WireGuard [`Interface`]
    pub async fn bind<A: ToSocketAddrs, I: ToInterface>(addr: A, iface: I) -> Result<Self> {
        let interface = iface.to_interface().await?;
        let allocation = lookup_host(addr)
            .await?
            .find_map(|addr| interface.allocate_tcp(addr))
            .ok_or_else(|| {
                Error::new(ErrorKind::AddrNotAvailable, "not a suitable bind address")
            })?;

        let backlog: Result<Box<[TcpStream]>> = iter::repeat_with(|| {
            let stream = TcpStream {
                socket: IO::new(
                    interface.clone(),
                    Self::socket(&interface, allocation.clone()),
                    None,
                ),
            };
            interface
                .register_tcp(Arc::clone(&stream.socket))
                .map(|()| stream)
        })
        .take(interface.options().tcp.backlog)
        .collect();

        Ok(Self {
            interface,
            allocation,
            backlog: backlog?,
        })
    }

    fn accept_io(
        socket: &mut Socket<'static>,
        interface: &Interface,
        allocation: Allocation,
    ) -> Poll<Result<(Socket<'static>, SocketAddr)>> {
        socket.state();
        if socket.may_send() {
            let next = Self::socket(&interface, allocation);
            let socket = replace(socket, next);

            let endpoint = match socket.remote_endpoint() {
                Some(endpoint) => endpoint,
                None => return Poll::Pending,
            };
            let address: IpAddr = endpoint.addr.into();
            let port = endpoint.port;

            Poll::Ready(Ok((socket, SocketAddr::new(address, port))))
        } else {
            Poll::Pending
        }
    }

    /// [`tokio::net::TcpListener::accept`]
    pub async fn accept(&self) -> Result<(TcpStream, SocketAddr)> {
        let mut waiters: Box<[_]> = self
            .backlog
            .iter()
            .map(|s| {
                s.socket.io(Interest::WRITABLE, |s| {
                    Self::accept_io(s, &self.interface, self.allocation)
                })
            })
            .collect();

        let (socket, addr) = poll_fn(|cx| {
            // Safety: The waiters are never used unpinned
            waiters
                .iter_mut()
                .map(|w| unsafe { Pin::new_unchecked(w) }.poll(cx))
                .find(Poll::is_ready)
                .unwrap_or(Poll::Pending)
        })
        .await?;

        let stream = TcpStream {
            socket: IO::new(self.interface.clone(), socket, None),
        };
        self.interface.register_tcp(Arc::clone(&stream.socket))?;

        Ok((stream, addr))
    }

    /// [`tokio::net::TcpListener::poll_accept`]
    pub fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<Result<(TcpStream, SocketAddr)>> {
        let socket = self
            .backlog
            .iter()
            .map(|s| {
                s.socket.poll_io(Interest::WRITABLE, cx, |s| {
                    Self::accept_io(s, &self.interface, self.allocation)
                })
            })
            .find(Poll::is_ready)
            .unwrap_or(Poll::Pending)?;

        match socket {
            Poll::Ready((socket, addr)) => {
                let stream = TcpStream {
                    socket: IO::new(self.interface.clone(), socket, None),
                };
                self.interface.register_tcp(Arc::clone(&stream.socket))?;

                Poll::Ready(Ok((stream, addr)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// [`tokio::net::TcpListener::local_addr`]
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.allocation.address())
    }

    /// Interface to which the listener is bound
    pub fn interface(&self) -> &Interface {
        &self.interface
    }
}

impl fmt::Debug for TcpListener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut f = f.debug_struct(type_name::<Self>());
        if let Ok(local_addr) = self.local_addr() {
            f.field("local_addr", &local_addr);
        }
        f.field("interface", &self.interface()).finish()
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        self.interface.deallocate(self.allocation);
    }
}

/// Like [`tokio::net::tcp::ReadHalf`], but on a WireGuard [`Interface`]
#[derive(Debug)]
pub struct ReadHalf<'a>(&'a TcpStream);

impl<'a> ReadHalf<'a> {
    /// [`tokio::net::tcp::ReadHalf::local_addr`]
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.0.local_addr()
    }
    /// [`tokio::net::tcp::ReadHalf::peer_addr`]
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        self.0.peer_addr()
    }

    /// [`tokio::net::tcp::ReadHalf::peek`]
    pub async fn peek<B: BufMut>(&self, buf: B) -> Result<usize> {
        self.0.peek(buf).await
    }
    /// [`tokio::net::tcp::ReadHalf::poll_peek`]
    pub fn poll_peek(&self, cx: &mut Context<'_>, buf: impl BufMut) -> Poll<Result<usize>> {
        self.0.poll_peek(cx, buf)
    }

    /// [`tokio::net::tcp::ReadHalf::ready`]
    pub async fn ready(&self, interest: Interest) -> Result<Ready> {
        self.0.ready(interest).await
    }

    /// [`tokio::net::tcp::ReadHalf::readable`]
    pub async fn readable(&self) -> Result<()> {
        self.0.readable().await
    }
    /// [`tokio::net::TcpStream::poll_read_ready`]
    pub fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.0.poll_read_ready(cx)
    }

    /// [`tokio::net::tcp::ReadHalf::try_read`]
    pub fn try_read<B: BufMut>(&self, buf: B) -> Result<usize> {
        self.0.try_read(buf)
    }

    /// Interface to which this stream is bound
    pub fn interface(&self) -> &Interface {
        self.0.interface()
    }
}

impl AsyncRead for ReadHalf<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        self.0
            .socket
            .poll_io(Interest::READABLE, cx, |s| TcpStream::read_io(s, buf))
            .map_ok(drop)
    }
}

impl AsRef<TcpStream> for ReadHalf<'_> {
    fn as_ref(&self) -> &TcpStream {
        self.0
    }
}

/// Like [`tokio::net::tcp::WriteHalf`], but on a WireGuard [`Interface`]
#[derive(Debug)]
pub struct WriteHalf<'a>(&'a TcpStream);

impl<'a> WriteHalf<'a> {
    /// [`tokio::net::tcp::WriteHalf::local_addr`]
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.0.local_addr()
    }
    /// [`tokio::net::tcp::WriteHalf::peer_addr`]
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        self.0.peer_addr()
    }

    /// [`tokio::net::tcp::WriteHalf::ready`]
    pub async fn ready(&self, interest: Interest) -> Result<Ready> {
        self.0.ready(interest).await
    }

    /// [`tokio::net::tcp::WriteHalf::writable`]
    pub async fn writable(&self) -> Result<()> {
        self.0.writable().await
    }
    /// [`tokio::net::TcpStream::poll_write_ready`]
    pub fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.0.poll_write_ready(cx)
    }

    /// [`tokio::net::tcp::WriteHalf::try_write`]
    pub fn try_write(&self, buf: &[u8]) -> Result<usize> {
        self.0.try_write(buf)
    }

    /// Interface to which this stream is bound
    pub fn interface(&self) -> &Interface {
        self.0.interface()
    }
}

impl AsyncWrite for WriteHalf<'_> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        self.0
            .socket
            .poll_io(Interest::WRITABLE, cx, |s| TcpStream::write_io(s, buf))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.0
            .socket
            .poll_io(Interest::WRITABLE, cx, TcpStream::shutdown_io)
    }
}

impl AsRef<TcpStream> for WriteHalf<'_> {
    fn as_ref(&self) -> &TcpStream {
        self.0
    }
}

/// Like [`tokio::net::tcp::OwnedReadHalf`], but on a WireGuard [`Interface`]
#[derive(Debug)]
pub struct OwnedReadHalf(TcpStream);

impl OwnedReadHalf {
    /// [`tokio::net::tcp::OwnedReadHalf::local_addr`]
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.0.local_addr()
    }
    /// [`tokio::net::tcp::OwnedReadHalf::peer_addr`]
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        self.0.peer_addr()
    }

    /// [`tokio::net::tcp::OwnedReadHalf::peek`]
    pub async fn peek<B: BufMut>(&self, buf: B) -> Result<usize> {
        self.0.peek(buf).await
    }
    /// [`tokio::net::tcp::OwnedReadHalf::poll_peek`]
    pub fn poll_peek(&self, cx: &mut Context<'_>, buf: impl BufMut) -> Poll<Result<usize>> {
        self.0.poll_peek(cx, buf)
    }

    /// [`tokio::net::tcp::OwnedReadHalf::ready`]
    pub async fn ready(&self, interest: Interest) -> Result<Ready> {
        self.0.ready(interest).await
    }

    /// [`tokio::net::tcp::OwnedReadHalf::readable`]
    pub async fn readable(&self) -> Result<()> {
        self.0.readable().await
    }
    /// [`tokio::net::TcpStream::poll_read_ready`]
    pub fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.0.poll_read_ready(cx)
    }

    /// [`tokio::net::tcp::OwnedReadHalf::try_read`]
    pub fn try_read<B: BufMut>(&self, buf: B) -> Result<usize> {
        self.0.try_read(buf)
    }

    /// Interface to which this stream is bound
    pub fn interface(&self) -> &Interface {
        self.0.interface()
    }

    /// [`tokio::net::tcp::OwnedReadHalf::reunite`]
    pub fn reunite(self, other: OwnedWriteHalf) -> std::result::Result<TcpStream, ReuniteError> {
        if self.0.socket.is(&other.0.socket) {
            Ok(TcpStream {
                socket: self.0.socket,
            })
        } else {
            Err(ReuniteError(self, other))
        }
    }
}

impl AsyncRead for OwnedReadHalf {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsRef<TcpStream> for OwnedReadHalf {
    fn as_ref(&self) -> &TcpStream {
        &self.0
    }
}

/// Like [`tokio::net::tcp::OwnedWriteHalf`], but on a WireGuard [`Interface`]
#[derive(Debug)]
pub struct OwnedWriteHalf(TcpStream);

impl OwnedWriteHalf {
    /// [`tokio::net::tcp::OwnedWriteHalf::local_addr`]
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.0.local_addr()
    }
    /// [`tokio::net::tcp::OwnedWriteHalf::peer_addr`]
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        self.0.peer_addr()
    }

    /// [`tokio::net::tcp::OwnedWriteHalf::ready`]
    pub async fn ready(&self, interest: Interest) -> Result<Ready> {
        self.0.ready(interest).await
    }

    /// [`tokio::net::tcp::OwnedWriteHalf::writable`]
    pub async fn writable(&self) -> Result<()> {
        self.0.writable().await
    }
    /// [`tokio::net::TcpStream::poll_write_ready`]
    pub fn poll_write_ready(&self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.0.poll_write_ready(cx)
    }

    /// [`tokio::net::tcp::OwnedWriteHalf::try_write`]
    pub fn try_write(&self, buf: &[u8]) -> Result<usize> {
        self.0.try_write(buf)
    }

    /// Interface to which this stream is bound
    pub fn interface(&self) -> &Interface {
        self.0.interface()
    }

    /// [`tokio::net::tcp::OwnedWriteHalf::reunite`]
    pub fn reunite(self, other: OwnedReadHalf) -> std::result::Result<TcpStream, ReuniteError> {
        if self.0.socket.is(&other.0.socket) {
            Ok(TcpStream {
                socket: other.0.socket,
            })
        } else {
            Err(ReuniteError(other, self))
        }
    }
}

impl AsyncWrite for OwnedWriteHalf {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl AsRef<TcpStream> for OwnedWriteHalf {
    fn as_ref(&self) -> &TcpStream {
        &self.0
    }
}

/// Error indicating that two halves were not from the same socket, and thus could not be reunited
#[derive(Debug)]
pub struct ReuniteError(pub OwnedReadHalf, pub OwnedWriteHalf);

impl fmt::Display for ReuniteError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("tried to reunite halves that are not from the same socket")
    }
}

impl std::error::Error for ReuniteError {}

impl Evented for Socket<'static> {
    fn readiness(&self) -> Ready {
        let mut readiness = Ready::EMPTY;
        if self.can_recv() {
            readiness |= Ready::READABLE;
        } else if !self.may_recv() {
            readiness |= Ready::READ_CLOSED;
        }
        if self.can_send() {
            readiness |= Ready::WRITABLE;
        } else if !self.may_send() {
            readiness |= Ready::WRITE_CLOSED;
        }
        readiness
    }

    fn register_read_waker(&mut self, waker: &Waker) {
        self.register_recv_waker(waker)
    }

    fn register_write_waker(&mut self, waker: &Waker) {
        self.register_send_waker(waker)
    }
}
