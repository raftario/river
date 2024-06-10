use std::sync::Arc;

use parking_lot::{ArcMutexGuard, Mutex, RawMutex};
use smoltcp::{
    iface::{SocketHandle, SocketSet},
    socket::{tcp, udp, Socket},
};

pub struct Sockets {
    set: SocketSet<'static>,
    tcp: SocketsInner<tcp::Socket<'static>>,
    udp: SocketsInner<udp::Socket<'static>>,
}

impl Sockets {
    pub fn new() -> Self {
        Self {
            set: SocketSet::new(Vec::new()),
            tcp: SocketsInner::new(),
            udp: SocketsInner::new(),
        }
    }

    pub fn register_tcp(&mut self, socket: crate::Shared<tcp::Socket<'static>>) {
        self.tcp.register(socket);
    }

    pub fn register_udp(&mut self, socket: crate::Shared<udp::Socket<'static>>) {
        self.udp.register(socket);
    }

    pub fn close(&mut self) {
        self.tcp.close();
        self.udp.close();
    }

    pub fn with<T>(&mut self, f: impl FnOnce(&mut SocketSet) -> T) -> T {
        let Self { set, tcp, udp } = self;

        tcp.lock(set);
        udp.lock(set);
        let result = f(set);

        tcp.unlock(set);
        udp.unlock(set);
        result
    }
}

struct SocketsInner<T> {
    sockets: Vec<crate::Shared<T>>,
    guards: Vec<(SocketHandle, ArcMutexGuard<RawMutex, Option<T>>)>,
}

impl<T> SocketsInner<T> {
    const fn new() -> Self {
        Self {
            sockets: Vec::new(),
            guards: Vec::new(),
        }
    }

    fn register(&mut self, socket: crate::Shared<T>) {
        let slot = self.sockets.iter_mut().enumerate().find_map(|(i, s)| {
            match Arc::get_mut(s).map(Mutex::get_mut) {
                Some(_) => None,
                None => Some(i),
            }
        });

        if let Some(slot) = slot.and_then(|s| self.sockets.get_mut(s)) {
            *slot = socket;
        } else {
            self.sockets.push(socket);
        }
    }
}

impl SocketsInner<tcp::Socket<'static>> {
    fn close(&mut self) {
        for socket in &mut self.sockets {
            if let Some(socket) = &mut *socket.lock() {
                socket.abort();
            }
        }
    }

    fn lock(&mut self, set: &mut SocketSet<'static>) {
        let Self { sockets, guards } = self;

        for socket in sockets {
            let mut guard = socket.lock_arc();
            if let Some(mut socket) = guard.take() {
                if Arc::strong_count(ArcMutexGuard::mutex(&guard)) == 2 {
                    socket.abort();
                }
                guards.push((set.add(socket), guard));
            }
        }
    }

    fn unlock(&mut self, set: &mut SocketSet<'static>) {
        let Self { guards, .. } = self;

        while let Some((handle, mut guard)) = guards.pop() {
            if let Socket::Tcp(socket) = set.remove(handle) {
                if let (tcp::State::Closed, None) = (socket.state(), socket.local_endpoint()) {
                    continue;
                }
                guard.replace(socket);
            }
        }
    }
}

impl SocketsInner<udp::Socket<'static>> {
    fn close(&mut self) {
        for socket in &mut self.sockets {
            if let Some(socket) = &mut *socket.lock() {
                socket.close();
            }
        }
    }

    fn lock(&mut self, set: &mut SocketSet<'static>) {
        let Self { sockets, guards } = self;

        for socket in sockets {
            let mut guard = socket.lock_arc();
            if let Some(socket) = guard.take() {
                guards.push((set.add(socket), guard));
            }
        }
    }

    fn unlock(&mut self, set: &mut SocketSet<'static>) {
        let Self { guards, .. } = self;

        while let Some((handle, mut guard)) = guards.pop() {
            if let Socket::Udp(socket) = set.remove(handle) {
                if Arc::strong_count(ArcMutexGuard::mutex(&guard)) == 2 {
                    continue;
                }
                guard.replace(socket);
            }
        }
    }
}
