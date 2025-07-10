use std::{
    any::type_name,
    fmt,
    future::{Future, poll_fn},
    io,
    net::{IpAddr, SocketAddr},
    ops::Deref,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};

use allocations::Proto;
use boringtun::x25519::PublicKey;
use pin_project_lite::pin_project;
use rand::{SeedableRng, TryRngCore, rngs::OsRng};
use random::AtomicXorShift32;
use smoltcp::{
    socket::{tcp, udp},
    wire::HardwareAddress,
};
use tokio::{
    runtime::Handle,
    sync::{Notify, futures::Notified, mpsc, oneshot},
    time,
};

mod allocations;
mod device;
mod random;
mod sockets;
mod tunnel;

pub(crate) use allocations::Allocation;

/// A handle to a WireGuard interface
///
/// Cloning returns a new handle to the same interface.
#[derive(Clone)]
pub struct Interface {
    tx: mpsc::UnboundedSender<Message>,
    shared: Arc<Shared>,
    allocations: allocations::Allocations,
    _drop: Arc<CloseOnDrop>,
}

/// Advanced options for configuring an [`Interface`]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Options {
    /// Handle to the Tokio runtime on which the interface will be run
    pub runtime: Handle,
    /// Default poll interval for the interface when idle
    pub poll_interval: Duration,
    /// Inteval at which to update the internal WireGuard timers
    pub timer_interval: Duration,
    /// TCP options
    pub tcp: TcpOptions,
    /// UDP options
    pub udp: UdpOptions,
}

/// Advanced TCP options for configuring an [`Interface`]
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TcpOptions {
    /// Timeout for connecting to a remote peer
    pub connect_timeout: Duration,
    /// Size of the TCP receive buffer
    pub recv_buffer_size: usize,
    /// Size of the TCP send buffer
    pub send_buffer_size: usize,
    /// Maximum number of pending connections on the listener
    pub backlog: usize,
}

/// Advanced UDP options for configuring an [`Interface`]
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct UdpOptions {
    /// Size of the UDP receive buffer
    pub recv_buffer_size: usize,
    /// Size of the UDP send buffer
    pub send_buffer_size: usize,
}

/// A trait for types that can be converted into an [`Interface`]
pub trait ToInterface {
    fn to_interface(self) -> impl Future<Output = Result<Interface, io::Error>>;
}

struct Shared {
    is_closed: AtomicBool,
    notify_closed: Notify,
    options: Options,
    rng: AtomicXorShift32,
}

#[derive(Debug)]
enum Message {
    Tcp(crate::Shared<tcp::Socket<'static>>),
    Udp(crate::Shared<udp::Socket<'static>>),
    TcpConnect {
        socket: crate::Shared<tcp::Socket<'static>>,
        allocation: Allocation,
        target: SocketAddr,
        result: oneshot::Sender<Result<(), tcp::ConnectError>>,
    },
    AddPeer {
        config: crate::config::Peer,
        result: oneshot::Sender<Result<(), io::Error>>,
    },
    RemovePeer {
        key: PublicKey,
        result: oneshot::Sender<bool>,
    },
    Close,
}

pin_project! {
    /// Future that resolves once its associated interface is in the closed state
    pub struct Closed<'a> {
        #[pin]
        notified: Notified<'a>,
        shared: Arc<Shared>,
    }
}

impl Interface {
    /// Create a new interface
    pub fn new(config: crate::config::Config) -> Result<Self, io::Error> {
        Self::new_with(config, Options::default())
    }

    /// Local address of the interface within the WireGuard network
    pub fn address(&self) -> Address {
        self.allocations.address
    }

    /// Advanced options for the interface
    pub fn options(&self) -> &Options {
        &self.shared.options
    }

    /// Request that the interface be closed
    ///
    /// All sockets created by the interface will be closed, and any attempt to send or receive data
    /// using them will result in an error. Once all remaining queued packets have been sent,
    /// the interface will enter the closed state.
    pub fn close(&self) {
        self.tx.send(Message::Close).ok();
    }

    /// Returns a future that resolves once the interface is in the closed state
    ///
    /// See [`close`](Self::close) for more information.
    pub fn closed(&self) -> Closed<'_> {
        Closed {
            notified: self.shared.notify_closed.notified(),
            shared: self.shared.clone(),
        }
    }

    /// Whether the interface is in the closed state
    ///
    /// See [`close`](Self::close) for more information.
    pub fn is_closed(&self) -> bool {
        self.shared.is_closed.load(Ordering::Acquire)
    }

    /// Create a new interface with advanced options
    pub fn new_with(config: crate::config::Config, options: Options) -> Result<Self, io::Error> {
        #[derive(Clone, Copy)]
        enum Close {
            No,
            Requested,
            Ready,
        }
        let runtime = options.runtime.clone();
        let scope = runtime.enter();

        let crate::config::Config {
            interface: config,
            peers: peer_configs,
        } = config;
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (mut interface, mut device) = Self::smol(&config);

        let mut sockets = sockets::Sockets::new();
        let mut tunnel = tunnel::Tunnel::new(&config, peer_configs)?;

        let poll = time::sleep_until(time::Instant::now());
        let mut timers = time::interval(options.timer_interval);
        timers.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

        let mut close = Close::No;
        let shared = Arc::new(Shared {
            is_closed: AtomicBool::new(false),
            notify_closed: Notify::new(),
            options,
            rng: AtomicXorShift32::from_os_rng(),
        });

        let i = Self {
            tx: tx.clone(),
            shared: shared.clone(),
            allocations: allocations::Allocations::new(&config),
            _drop: Arc::new(CloseOnDrop { tx }),
        };
        let shared = NotifyOnDrop(shared);

        tokio::spawn(async move {
            tokio::pin!(poll);
            loop {
                #[derive(Debug)]
                enum Select {
                    Poll,
                    Message(Message),
                    Recv,
                    Send,
                    Timers,
                    Close,
                }

                let selected = poll_fn(|cx| {
                    let poll = poll.as_mut().poll(cx);
                    let recv = tunnel.socket().poll_recv_ready(cx);
                    let send = tunnel.socket().poll_send_ready(cx);
                    let can_send = device.can_send();

                    if poll.is_ready() {
                        Poll::Ready(Select::Poll)
                    } else if let (Poll::Ready(Some(message)), Close::No) =
                        (rx.poll_recv(cx), close)
                    {
                        Poll::Ready(Select::Message(message))
                    } else if let (Poll::Ready(..), Poll::Ready(..)) = (recv, &send) {
                        Poll::Ready(Select::Recv)
                    } else if let (true, Poll::Ready(..)) = (can_send, send) {
                        Poll::Ready(Select::Send)
                    } else if timers.poll_tick(cx).is_ready() {
                        Poll::Ready(Select::Timers)
                    } else if let (false, Close::Ready) = (can_send, close) {
                        Poll::Ready(Select::Close)
                    } else {
                        Poll::Pending
                    }
                })
                .await;

                match selected {
                    Select::Poll => {
                        let wait = sockets.with(|s| {
                            let now = smoltcp::time::Instant::now();
                            interface.poll(now, &mut device, s);
                            interface.poll_delay(now, s).map(time::Duration::from)
                        });
                        match wait {
                            Some(wait) => poll.as_mut().reset(time::Instant::now() + wait),
                            None => {
                                poll.as_mut()
                                    .reset(time::Instant::now() + shared.options.poll_interval);
                                if let Close::Requested = close {
                                    close = Close::Ready;
                                }
                            }
                        }
                    }
                    Select::Message(Message::Tcp(socket)) => {
                        sockets.register_tcp(socket);
                        poll.as_mut().reset(time::Instant::now());
                    }
                    Select::Message(Message::Udp(socket)) => {
                        sockets.register_udp(socket);
                        poll.as_mut().reset(time::Instant::now());
                    }
                    Select::Message(Message::TcpConnect {
                        socket,
                        allocation,
                        target,
                        result,
                    }) => {
                        if let Some(socket) = socket.lock().as_mut() {
                            result
                                .send(socket.connect(
                                    interface.context(),
                                    target,
                                    allocation.address(),
                                ))
                                .ok();
                        }
                        sockets.register_tcp(socket);
                        poll.as_mut().reset(time::Instant::now());
                    }
                    Select::Message(Message::AddPeer { config, result }) => {
                        result.send(tunnel.add_peer(config)).ok();
                    }
                    Select::Message(Message::RemovePeer { key, result }) => {
                        result.send(tunnel.remove_peer(&key)).ok();
                    }
                    Select::Message(Message::Close) => {
                        close = Close::Requested;
                        sockets.close();
                        poll.as_mut().reset(time::Instant::now());
                    }
                    Select::Recv => {
                        if let Some(packet) = tunnel.recv().await {
                            device.enqueue_received(packet);
                        }
                    }
                    Select::Send => {
                        if let Some(packet) = device.dequeue_sent() {
                            tunnel.send(packet, |_| true).await;
                        }
                    }
                    Select::Timers => tunnel.update_timers().await,
                    Select::Close => break,
                }
            }
        });

        drop(scope);
        Ok(i)
    }

    /// Dynamically add a new peer to the interface. The peer will only become available
    /// once the returned future resolves.
    pub async fn add_peer(&self, config: crate::config::Peer) -> Result<(), io::Error> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Message::AddPeer { config, result: tx })
            .map_err(|_| Self::error())?;
        rx.await.map_err(|_| Self::error())?
    }
    /// Removes a peer from the interface. Returns whether the peer existed.
    pub async fn remove_peer(&self, key: &PublicKey) -> Result<bool, io::Error> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(Message::RemovePeer {
                key: *key,
                result: tx,
            })
            .map_err(|_| Self::error())?;
        rx.await.map_err(|_| Self::error())
    }

    pub(crate) fn error() -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "interface is closed")
    }

    pub(crate) fn register_tcp(
        &self,
        socket: crate::Shared<tcp::Socket<'static>>,
    ) -> io::Result<()> {
        self.tx
            .send(Message::Tcp(socket))
            .map_err(|_| Self::error())
    }
    pub(crate) fn register_udp(
        &self,
        socket: crate::Shared<udp::Socket<'static>>,
    ) -> io::Result<()> {
        self.tx
            .send(Message::Udp(socket))
            .map_err(|_| Self::error())
    }

    pub(crate) fn allocate_tcp(&self, address: SocketAddr) -> Option<Allocation> {
        self.allocations
            .acquire(address, Proto::Tcp, &mut &self.shared.rng)
    }
    pub(crate) fn allocate_udp(&self, address: SocketAddr) -> Option<Allocation> {
        self.allocations
            .acquire(address, Proto::Udp, &mut &self.shared.rng)
    }

    pub(crate) async fn connect_tcp(
        &self,
        socket: crate::Shared<tcp::Socket<'static>>,
        allocation: Allocation,
        target: SocketAddr,
    ) -> io::Result<Result<(), tcp::ConnectError>> {
        let (tx, result) = oneshot::channel();
        self.tx
            .send(Message::TcpConnect {
                socket,
                allocation,
                target,
                result: tx,
            })
            .map_err(|_| Self::error())?;
        result.await.map_err(|_| Self::error())
    }

    pub(crate) fn deallocate(&self, allocation: Allocation) {
        self.allocations.release(allocation);
    }

    fn smol(config: &crate::config::Interface) -> (smoltcp::iface::Interface, device::Device) {
        let ips = config.address.addresses();
        let mut device = device::Device::new(config);
        let mut config = smoltcp::iface::Config::new(HardwareAddress::Ip);
        config.random_seed = OsRng.try_next_u64().unwrap();

        let mut interface =
            smoltcp::iface::Interface::new(config, &mut device, smoltcp::time::Instant::now());
        interface.update_ip_addrs(|a| {
            for ip in ips {
                match ip {
                    IpAddr::V4(ip) => a.push(smoltcp::wire::Ipv4Cidr::new(ip, 32).into()),
                    IpAddr::V6(ip) => a.push(smoltcp::wire::Ipv6Cidr::new(ip, 128).into()),
                }
                .ok();
            }
        });

        (interface, device)
    }
}

use crate::config::Address;

impl fmt::Debug for Interface {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple(type_name::<Self>())
            .field(&self.address())
            .finish()
    }
}

impl ToInterface for Interface {
    async fn to_interface(self) -> Result<Interface, io::Error> {
        Ok(self)
    }
}

impl ToInterface for &Interface {
    async fn to_interface(self) -> Result<Interface, io::Error> {
        Ok(self.clone())
    }
}

impl ToInterface for &mut Interface {
    async fn to_interface(self) -> Result<Interface, io::Error> {
        Ok(self.clone())
    }
}

impl ToInterface for crate::config::Config {
    async fn to_interface(self) -> Result<Interface, io::Error> {
        Interface::new(self)
    }
}

impl Default for Options {
    fn default() -> Self {
        Self {
            runtime: Handle::current(),
            poll_interval: Duration::from_millis(100),
            timer_interval: Duration::from_millis(100),
            tcp: TcpOptions::default(),
            udp: UdpOptions::default(),
        }
    }
}

impl Default for TcpOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            recv_buffer_size: 64 * 1024,
            send_buffer_size: 16 * 1024,
            backlog: 128,
        }
    }
}

impl Default for UdpOptions {
    fn default() -> Self {
        Self {
            recv_buffer_size: 64 * 1024,
            send_buffer_size: 16 * 1024,
        }
    }
}

impl<'a> Future for Closed<'a> {
    type Output = <Notified<'a> as Future>::Output;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self.shared.is_closed.load(Ordering::Acquire) {
            Poll::Ready(())
        } else {
            self.project().notified.poll(cx)
        }
    }
}

struct CloseOnDrop {
    tx: mpsc::UnboundedSender<Message>,
}

struct NotifyOnDrop(Arc<Shared>);

impl Drop for CloseOnDrop {
    fn drop(&mut self) {
        self.tx.send(Message::Close).ok();
    }
}

impl Deref for NotifyOnDrop {
    type Target = Shared;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Drop for NotifyOnDrop {
    fn drop(&mut self) {
        self.is_closed.store(true, Ordering::Release);
        self.notify_closed.notify_waiters();
    }
}
