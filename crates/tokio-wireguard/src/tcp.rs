use std::{
    future::{poll_fn, Future},
    iter,
    mem::replace,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    pin::Pin,
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

pub struct TcpStream {
    socket: IO<Socket<'static>>,
}

pub struct TcpListener {
    interface: Interface,
    allocation: Allocation,
    backlog: Box<[TcpStream]>,
}

impl TcpStream {
    pub async fn connect<A: ToSocketAddrs, I: ToInterface>(addr: A, iface: I) -> Result<TcpStream> {
        let interface = iface.to_interface().await?;
        let targets = lookup_host(addr)
            .await?
            .filter(|addr| interface.address().is_compatible(*addr));

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
                .connect_tcp(socket.clone(), allocation, target)
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
                Ok(Err(e)) => return Err(e),
                Err(..) => continue,
            }
        }

        Err(Error::from(ErrorKind::TimedOut))
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
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint(|s| s.local_endpoint())
    }
    pub fn peer_addr(&self) -> Result<SocketAddr> {
        self.endpoint(|s| s.remote_endpoint())
    }

    fn peek_io<B: BufMut>(socket: &mut Socket<'static>, buf: &mut B) -> Poll<Result<usize>> {
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
    pub async fn peek<B: BufMut>(&self, buf: &mut B) -> Result<usize> {
        self.socket
            .io(Interest::READABLE, |s| Self::peek_io(s, buf))
            .await
    }
    pub fn poll_peek<B: BufMut>(&self, cx: &mut Context<'_>, buf: &mut B) -> Poll<Result<usize>> {
        self.socket
            .poll_io(Interest::READABLE, cx, |s| Self::peek_io(s, buf))
    }

    pub async fn ready(&self, interest: Interest) -> Result<Ready> {
        self.socket.ready(interest).await
    }

    pub async fn readable(&self) -> Result<()> {
        self.socket.ready(Interest::READABLE).await.map(drop)
    }
    pub fn poll_read_ready(&self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.socket.poll_ready(Interest::READABLE, cx)
    }

    fn read_io<B: BufMut>(socket: &mut Socket<'static>, buf: &mut B) -> Poll<Result<usize>> {
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
    pub fn try_read<B: BufMut>(&self, buf: &mut B) -> Result<usize> {
        self.socket.try_io(|s| Self::read_io(s, buf))
    }

    pub async fn writable(&self) -> Result<()> {
        self.socket.ready(Interest::WRITABLE).await.map(drop)
    }
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
    pub fn try_write(&self, buf: &[u8]) -> Result<usize> {
        self.socket.try_io(|s| Self::write_io(s, buf))
    }

    pub fn nodelay(&self) -> Result<bool> {
        self.socket.with(|s| !s.nagle_enabled())
    }
    pub fn set_nodelay(&mut self, nodelay: bool) -> Result<()> {
        self.socket.with(|s| s.set_nagle_enabled(!nodelay))
    }

    pub fn ttl(&self) -> Result<u32> {
        self.socket.with(|s| s.hop_limit().unwrap_or(64).into())
    }
    pub fn set_ttl(&mut self, ttl: u32) -> Result<()> {
        self.socket.with(|s| s.set_hop_limit(ttl.try_into().ok()))
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
        self.socket.poll_io(Interest::WRITABLE, cx, |s| {
            if !s.may_send() {
                Poll::Ready(Ok(()))
            } else {
                s.close();
                Poll::Pending
            }
        })
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
                .register_tcp(stream.socket.clone())
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
        self.interface.register_tcp(stream.socket.clone())?;

        Ok((stream, addr))
    }

    pub async fn poll_accept(&self, cx: &mut Context<'_>) -> Poll<Result<(TcpStream, SocketAddr)>> {
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
                self.interface.register_tcp(stream.socket.clone())?;

                Poll::Ready(Ok((stream, addr)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.allocation.address())
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        self.interface.deallocate(self.allocation);
    }
}

impl Evented for Socket<'static> {
    #[inline]
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

    #[inline]
    fn register_read_waker(&mut self, waker: &Waker) {
        self.register_recv_waker(waker)
    }
    #[inline]
    fn register_write_waker(&mut self, waker: &Waker) {
        self.register_send_waker(waker)
    }
}
