use std::{
    mem::transmute,
    ops::{Deref, DerefMut},
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
};

use atomic_waker::AtomicWaker;
use parking_lot::Mutex;
use tokio::{
    io::{Error, ErrorKind, Interest, Ready, Result},
    sync::Notify,
};

use crate::{interface::Allocation, Interface, Shared};

pub struct IO<E: Evented> {
    interface: Interface,
    evented: Shared<E>,
    allocation: Option<Allocation>,
    wake: Arc<WakeState>,
    wakers: Wakers,
}

impl<E: Evented> IO<E> {
    pub fn new(interface: Interface, evented: E, allocation: Option<Allocation>) -> Self {
        let (wake, wakers) = wakers();
        Self {
            interface,
            evented: Arc::new(Mutex::new(Some(evented))),
            allocation,
            wake,
            wakers,
        }
    }

    pub fn interface(&self) -> &Interface {
        &self.interface
    }

    pub fn with<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut E) -> R,
    {
        if self.interface.is_closed() {
            return Err(Interface::error());
        }

        self.evented
            .lock()
            .as_mut()
            .map(f)
            .ok_or_else(Interface::error)
    }

    pub fn try_io<F, R>(&self, f: F) -> Result<R>
    where
        F: FnOnce(&mut E) -> Poll<Result<R>>,
    {
        let result = self.with(f);
        match result {
            Ok(Poll::Ready(result)) => result,
            Ok(Poll::Pending) => Err(Error::from(ErrorKind::WouldBlock)),
            Err(e) => Err(e),
        }
    }

    pub async fn io<F, R>(&self, interest: Interest, mut f: F) -> Result<R>
    where
        F: FnMut(&mut E) -> Poll<Result<R>>,
    {
        loop {
            let notified = self.wake.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let result = self.with(|e| {
                if interest.is_readable() {
                    e.register_read_waker(&self.wakers.read);
                } else if interest.is_writable() {
                    e.register_write_waker(&self.wakers.write);
                }
                f(e)
            });

            match result {
                Ok(Poll::Pending) => notified.await,
                Ok(Poll::Ready(result)) => break result,
                Err(e) => break Err(e),
            }
        }
    }

    pub async fn ready(&self, interest: Interest) -> Result<Ready> {
        loop {
            let notified = self.wake.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();

            let ready = self.with(|e| {
                let ready = e.readiness();
                if satisfies(ready, interest) {
                    Some(ready)
                } else {
                    if interest.is_readable() || interest.is_error() {
                        e.register_read_waker(&self.wakers.read);
                    }
                    if interest.is_writable() || interest.is_error() {
                        e.register_write_waker(&self.wakers.write);
                    }
                    None
                }
            });

            match ready {
                Ok(None) => notified.await,
                Ok(Some(ready)) => break Ok(ready),
                Err(e) => break Err(e),
            }
        }
    }

    pub fn poll_io<F, R>(&self, interest: Interest, cx: &mut Context<'_>, f: F) -> Poll<Result<R>>
    where
        F: FnOnce(&mut E) -> Poll<Result<R>>,
    {
        let result = self.with(|e| {
            let poll = f(e);
            if poll.is_pending() {
                if interest.is_readable() {
                    self.wake.read.register(cx.waker());
                    e.register_read_waker(&self.wakers.read)
                } else if interest.is_writable() {
                    self.wake.read.register(cx.waker());
                    e.register_write_waker(&self.wakers.write)
                }
            }
            poll
        });
        match result {
            Ok(poll) => poll,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    pub fn poll_ready(&self, interest: Interest, cx: &mut Context<'_>) -> Poll<Result<()>> {
        let ready = self.with(|e| {
            if satisfies(e.readiness(), interest) {
                Poll::Ready(Ok(()))
            } else {
                if interest.is_readable() || interest.is_error() {
                    self.wake.read.register(cx.waker());
                    e.register_read_waker(&self.wakers.read)
                } else if interest.is_writable() || interest.is_error() {
                    self.wake.write.register(cx.waker());
                    e.register_write_waker(&self.wakers.write)
                }
                Poll::Pending
            }
        });
        match ready {
            Ok(poll) => poll,
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    pub fn is(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.evented, &other.evented)
    }
}

impl<E: Evented> Clone for IO<E> {
    fn clone(&self) -> Self {
        Self {
            interface: self.interface.clone(),
            evented: self.evented.clone(),
            allocation: self.allocation,
            wake: self.wake.clone(),
            wakers: self.wakers.clone(),
        }
    }
}

impl<E: Evented> Deref for IO<E> {
    type Target = Shared<E>;

    fn deref(&self) -> &Self::Target {
        &self.evented
    }
}

impl<E: Evented> DerefMut for IO<E> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.evented
    }
}

impl<E: Evented> Drop for IO<E> {
    fn drop(&mut self) {
        if let Some(allocation) = self.allocation.take() {
            self.interface.deallocate(allocation);
        }
    }
}

pub trait Evented {
    fn readiness(&self) -> Ready;

    fn register_read_waker(&mut self, waker: &Waker);
    fn register_write_waker(&mut self, waker: &Waker);
}

fn satisfies(readiness: Ready, interest: Interest) -> bool {
    let mut anyof = Ready::EMPTY;
    if interest.is_readable() || interest.is_error() {
        anyof |= Ready::READABLE;
        anyof |= Ready::READ_CLOSED;
    }
    if interest.is_writable() || interest.is_error() {
        anyof |= Ready::WRITABLE;
        anyof |= Ready::WRITE_CLOSED;
    }
    anyof & readiness != Ready::EMPTY
}

fn wakers() -> (Arc<WakeState>, Wakers) {
    let state = Arc::new(WakeState {
        notify: Notify::new(),
        read: AtomicWaker::new(),
        write: AtomicWaker::new(),
    });
    // Safety: #[repr(transparent)]
    let wakers = unsafe {
        Wakers {
            read: Waker::from(transmute::<Arc<WakeState>, Arc<ReadWaker>>(state.clone())),
            write: Waker::from(transmute::<Arc<WakeState>, Arc<WriteWaker>>(state.clone())),
        }
    };

    (state, wakers)
}

struct WakeState {
    notify: Notify,
    read: AtomicWaker,
    write: AtomicWaker,
}

#[derive(Clone)]
struct Wakers {
    read: Waker,
    write: Waker,
}

#[repr(transparent)]
struct ReadWaker(WakeState);

#[repr(transparent)]
struct WriteWaker(WakeState);

impl Wake for ReadWaker {
    fn wake(self: Arc<Self>) {
        self.0.notify.notify_waiters();
        self.0.read.wake();
    }
}

impl Wake for WriteWaker {
    fn wake(self: Arc<Self>) {
        self.0.notify.notify_waiters();
        self.0.write.wake();
    }
}
