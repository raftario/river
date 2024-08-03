//! In-process WireGuard for Tokio
//!
//! This crate provides a Tokio-based in-process implementation of WireGuard.
//! Each [`Interface`] is backed by an independent TCP/IP stack that tunnels all of its traffic
//! over WireGuard, and can be used to create TCP ([`TcpStream`] and [`TcpListener`])
//! and UDP ([`UdpSocket`]) sockets, which attempt to follow the API of [`tokio::net`] as closely as
//! possible.
//!
//! The interface can be dynamically configured at runtime, and any number of interfaces can exist
//! in the same process. This makes it possible for an application to support WireGuard with fine
//! grained control without root privileges on any platform supported by Tokio.
//!
//! Interfaces can also forward traffic to remote WireGuard peers. However, at the moment, they cannot
//! forward traffic to other interfaces outside of the WireGuard network.
//!
//! This library is built on top of [`smoltcp`] and [`boringtun`], and could not exist without these
//! amazing projects.

pub mod config;
pub mod interface;
mod io;
pub mod tcp;
pub mod udp;
pub mod x25519;

pub(crate) type Shared<T> = std::sync::Arc<parking_lot::Mutex<Option<T>>>;

pub use crate::{
    config::Config,
    interface::Interface,
    tcp::{TcpListener, TcpStream},
    udp::UdpSocket,
};
