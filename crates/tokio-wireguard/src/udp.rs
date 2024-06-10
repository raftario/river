use std::{
    net::{IpAddr, SocketAddr},
    task::{Context, Poll, Waker},
};

use bytes::BufMut;
use smoltcp::{
    socket::udp::{SendError, Socket},
    storage::{PacketBuffer, PacketMetadata},
};
use tokio::{
    io::{Error, ErrorKind, Interest, ReadBuf, Ready, Result},
    net::{lookup_host, ToSocketAddrs},
};

use crate::{
    config::Address,
    interface::ToInterface,
    io::{Evented, IO},
};

pub struct UdpSocket {
    socket: IO<Socket<'static>>,
}

impl UdpSocket {
    pub async fn bind<A: ToSocketAddrs, I: ToInterface>(addr: A, iface: I) -> Result<Self> {
        let interface = iface.to_interface().await?;
        let allocation = lookup_host(addr)
            .await?
            .find_map(|addr| interface.allocate_udp(addr))
            .ok_or_else(|| {
                Error::new(ErrorKind::AddrNotAvailable, "not a suitable bind address")
            })?;

        let mut socket = Socket::new(
            PacketBuffer::new(
                vec![PacketMetadata::EMPTY; interface.options().udp.recv_buffer_size / 1024],
                vec![0; interface.options().udp.recv_buffer_size],
            ),
            PacketBuffer::new(
                vec![PacketMetadata::EMPTY; interface.options().udp.send_buffer_size / 1024],
                vec![0; interface.options().udp.send_buffer_size],
            ),
        );
        socket.bind(allocation.address()).unwrap();

        let socket = IO::new(interface, socket, Some(allocation));
        socket.interface().register_udp(socket.clone())?;

        Ok(UdpSocket { socket })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        let endpoint = self.socket.with(|s| s.endpoint())?;
        let address: IpAddr = endpoint.addr.unwrap().into();
        let port = endpoint.port;

        Ok(SocketAddr::new(address, port))
    }

    pub async fn ready(&self, interest: Interest) -> Result<Ready> {
        self.socket.ready(interest).await
    }

    pub async fn writable(&self) -> Result<()> {
        self.socket.ready(Interest::WRITABLE).await.map(drop)
    }
    pub fn poll_send_ready(&self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.socket.poll_ready(Interest::WRITABLE, cx)
    }

    fn send_to_io(
        socket: &mut Socket<'static>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<Result<usize>> {
        match socket.send_slice(buf, target) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(SendError::Unaddressable) => Poll::Ready(Err(Error::new(
                ErrorKind::InvalidInput,
                "not a valid target address",
            ))),
            Err(SendError::BufferFull) => Poll::Pending,
        }
    }
    pub async fn send_to<A: ToSocketAddrs>(&self, buf: &[u8], target: A) -> Result<usize> {
        let target = lookup_host(target)
            .await?
            .find(|target| match (target, self.socket.interface().address()) {
                (SocketAddr::V4(..), Address::Dual(..) | Address::V4(..)) => true,
                (SocketAddr::V6(..), Address::Dual(..) | Address::V6(..)) => true,
                _ => false,
            })
            .ok_or_else(|| {
                Error::new(ErrorKind::AddrNotAvailable, "not a suitable target address")
            })?;

        self.socket
            .io(Interest::WRITABLE, |s| Self::send_to_io(s, buf, target))
            .await
    }
    pub fn poll_send_to(
        &self,
        cx: &mut Context<'_>,
        buf: &[u8],
        target: SocketAddr,
    ) -> Poll<Result<usize>> {
        self.socket
            .poll_io(Interest::READABLE, cx, |s| Self::send_to_io(s, buf, target))
    }
    pub fn try_send_to(&self, buf: &mut [u8], target: SocketAddr) -> Result<usize> {
        self.socket.try_io(|s| Self::send_to_io(s, buf, target))
    }

    pub async fn readable(&self) -> Result<()> {
        self.socket.ready(Interest::READABLE).await.map(drop)
    }
    pub fn poll_recv_ready(&self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        self.socket.poll_ready(Interest::READABLE, cx)
    }

    fn recv_from_io<B: BufMut>(
        socket: &mut Socket<'static>,
        buf: &mut B,
    ) -> Poll<Result<(usize, SocketAddr)>> {
        match socket.recv() {
            Ok((packet, meta)) => {
                let len = usize::min(buf.remaining_mut(), packet.len());
                let addr = SocketAddr::new(meta.endpoint.addr.into(), meta.endpoint.port);
                buf.put_slice(&packet[..len]);
                Poll::Ready(Ok((len, addr)))
            }
            _ => Poll::Pending,
        }
    }
    pub async fn recv_from<B: BufMut>(&self, buf: &mut B) -> Result<(usize, SocketAddr)> {
        self.socket
            .io(Interest::READABLE, |s| Self::recv_from_io(s, buf))
            .await
    }
    pub fn poll_recv_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<SocketAddr>> {
        self.socket
            .poll_io(Interest::READABLE, cx, |s| Self::recv_from_io(s, buf))
            .map_ok(|(_, addr)| addr)
    }
    pub fn try_recv_from<B: BufMut>(&self, buf: &mut B) -> Result<(usize, SocketAddr)> {
        self.socket.try_io(|s| Self::recv_from_io(s, buf))
    }

    fn peek_from_io<B: BufMut>(
        socket: &mut Socket<'static>,
        buf: &mut B,
    ) -> Poll<Result<(usize, SocketAddr)>> {
        match socket.peek() {
            Ok((packet, meta)) => {
                let len = usize::min(buf.remaining_mut(), packet.len());
                let addr = SocketAddr::new(meta.endpoint.addr.into(), meta.endpoint.port);
                buf.put_slice(&packet[..len]);
                Poll::Ready(Ok((len, addr)))
            }
            _ => Poll::Pending,
        }
    }
    pub async fn peek_from<B: BufMut>(&self, buf: &mut B) -> Result<(usize, SocketAddr)> {
        self.socket
            .io(Interest::READABLE, |s| Self::peek_from_io(s, buf))
            .await
    }
    pub fn poll_peek_from(
        &self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<Result<SocketAddr>> {
        self.socket
            .poll_io(Interest::READABLE, cx, |s| Self::peek_from_io(s, buf))
            .map_ok(|(_, addr)| addr)
    }
    pub fn try_peek_from<B: BufMut>(&self, buf: &mut B) -> Result<(usize, SocketAddr)> {
        self.socket.try_io(|s| Self::peek_from_io(s, buf))
    }

    fn peek_sender_io(socket: &mut Socket<'static>) -> Poll<Result<SocketAddr>> {
        match socket.peek() {
            Ok((_, meta)) => Poll::Ready(Ok(SocketAddr::new(
                meta.endpoint.addr.into(),
                meta.endpoint.port,
            ))),
            _ => Poll::Pending,
        }
    }
    pub async fn peek_sender(&self) -> Result<SocketAddr> {
        self.socket
            .io(Interest::READABLE, Self::peek_sender_io)
            .await
    }
    pub fn poll_peek_sender(&self, cx: &mut Context<'_>) -> Poll<Result<SocketAddr>> {
        self.socket
            .poll_io(Interest::READABLE, cx, Self::peek_sender_io)
    }
    pub fn try_peek_sender(&self) -> Result<SocketAddr> {
        self.socket.try_io(Self::peek_sender_io)
    }

    pub fn ttl(&self) -> Result<u32> {
        self.socket.with(|s| s.hop_limit().unwrap_or(64).into())
    }
    pub fn set_ttl(&mut self, ttl: u32) -> Result<()> {
        self.socket.with(|s| s.set_hop_limit(ttl.try_into().ok()))
    }
}

impl Evented for Socket<'static> {
    #[inline]
    fn readiness(&self) -> Ready {
        let mut readiness = Ready::EMPTY;
        if self.is_open() && self.can_recv() {
            readiness |= Ready::READABLE;
        }
        if self.is_open() && self.can_send() {
            readiness |= Ready::WRITABLE;
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
