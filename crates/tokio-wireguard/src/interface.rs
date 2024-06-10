use std::{
    any::type_name,
    fmt,
    future::{poll_fn, Future},
    io,
    net::{IpAddr, SocketAddr},
    ops::Deref,
    pin::Pin,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    task::{Context, Poll},
    time::Duration,
};

use allocations::Proto;
use pin_project_lite::pin_project;
use rand::{rngs::OsRng, Rng, SeedableRng};
use random::AtomicXorShift32;
use smoltcp::{
    socket::{tcp, udp},
    wire::HardwareAddress,
};
use tokio::{
    runtime::Handle,
    sync::{futures::Notified, mpsc, oneshot, Notify},
    time,
};

mod allocations;
mod device;
mod random;
mod sockets;
mod tunnel;

pub(crate) use allocations::Allocation;

#[derive(Clone)]
pub struct Interface {
    tx: mpsc::UnboundedSender<Message>,
    shared: Arc<Shared>,
    allocations: allocations::Allocations,
    _drop: Arc<CloseOnDrop>,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Options {
    pub runtime: Handle,
    pub poll_interval: Duration,
    pub timer_interval: Duration,
    pub tcp: TcpOptions,
    pub udp: UdpOptions,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct TcpOptions {
    pub connect_timeout: Duration,
    pub recv_buffer_size: usize,
    pub send_buffer_size: usize,
    pub backlog: usize,
}

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct UdpOptions {
    pub recv_buffer_size: usize,
    pub send_buffer_size: usize,
}

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
    Close,
}

pin_project! {
    pub struct Closed<'a> {
        #[pin]
        notified: Notified<'a>,
        shared: Arc<Shared>,
    }
}

impl Interface {
    pub fn new(config: crate::config::Config) -> Result<Self, io::Error> {
        Self::new_with(config, Options::default())
    }

    pub fn error() -> io::Error {
        io::Error::new(io::ErrorKind::BrokenPipe, "interface is closed")
    }

    pub fn address(&self) -> Address {
        self.allocations.address
    }

    pub fn options(&self) -> &Options {
        &self.shared.options
    }

    pub fn close(&self) {
        self.tx.send(Message::Close).ok();
    }

    pub fn closed(&self) -> Closed<'_> {
        Closed {
            notified: self.shared.notify_closed.notified(),
            shared: self.shared.clone(),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.shared.is_closed.load(Ordering::Acquire)
    }

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
            rng: AtomicXorShift32::from_entropy(),
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
                    let recv = tunnel.socket().poll_recv_ready(cx);
                    let send = tunnel.socket().poll_send_ready(cx);
                    let can_send = device.can_send();

                    if let Poll::Ready(()) = poll.as_mut().poll(cx) {
                        Poll::Ready(Select::Poll)
                    } else if let (Poll::Ready(Some(message)), Close::No) =
                        (rx.poll_recv(cx), close)
                    {
                        Poll::Ready(Select::Message(message))
                    } else if let (Poll::Ready(..), Poll::Ready(..)) = (recv, &send) {
                        Poll::Ready(Select::Recv)
                    } else if let (true, Poll::Ready(..)) = (can_send, send) {
                        Poll::Ready(Select::Send)
                    } else if let Poll::Ready(..) = timers.poll_tick(cx) {
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

    pub(crate) fn allocate_tcp(&self, address: impl Into<SocketAddr>) -> Option<Allocation> {
        self.allocations
            .acquire(address, Proto::Tcp, &mut &self.shared.rng)
    }
    pub(crate) fn allocate_udp(&self, address: impl Into<SocketAddr>) -> Option<Allocation> {
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
        let ips = config.address.ips();
        let mut device = device::Device::new(&config);
        let mut config = smoltcp::iface::Config::new(HardwareAddress::Ip);
        config.random_seed = OsRng.gen();

        let mut interface =
            smoltcp::iface::Interface::new(config, &mut device, smoltcp::time::Instant::now());
        interface.update_ip_addrs(|a| {
            for ip in ips {
                match ip {
                    IpAddr::V4(ip) => a.push(smoltcp::wire::Ipv4Cidr::new(ip.into(), 32).into()),
                    IpAddr::V6(ip) => a.push(smoltcp::wire::Ipv6Cidr::new(ip.into(), 128).into()),
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

impl<'a> ToInterface for &'a Interface {
    async fn to_interface(self) -> Result<Interface, io::Error> {
        Ok(self.clone())
    }
}

impl<'a> ToInterface for &'a mut Interface {
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
            recv_buffer_size: 32 * 1024,
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
