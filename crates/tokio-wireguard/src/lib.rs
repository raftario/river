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
//! ```no_run
//! # #[tokio::main]
//! # async fn main() {
//! # let (private_key, remote_public_key) = tokio_wireguard::x25519::keypair();
//! use tokio::io::AsyncWriteExt;
//! use tokio_wireguard::{
//!     config::{Config, Interface, Peer},
//!     interface::ToInterface,
//!     TcpStream,
//! };
//!
//! let config = Config {
//!     interface: Interface {
//!         private_key,
//!         // Our address on the WireGuard network
//!         address: "100.64.0.2/32".parse().unwrap(),
//!         // Let the interface pick a random port
//!         listen_port: None,
//!         // Let the interface pick an appropriate MTU
//!         mtu: None,
//!     },
//!     peers: vec![Peer {
//!         public_key: remote_public_key,
//!         // This is where the tunneled WireGuard traffic will be sent
//!         endpoint: Some("198.51.100.30:51820".parse().unwrap()),
//!         // IP addresses the peer can handle traffic to and from on the WireGuard network
//!         // The /32 suffix indicates that the peer only handles traffic for itself
//!         allowed_ips: vec!["100.64.0.1/32".parse().unwrap()],
//!         // Send a keepalive packet every 15 seconds
//!         persistent_keepalive: Some(15),
//!     }],
//! };
//! let interface = config.to_interface().await.unwrap();
//!
//! let mut stream = TcpStream::connect("100.64.0.1:8080", &interface)
//!     .await
//!     .unwrap();
//! stream.write_all(b"Bonjour").await.unwrap();
//! # }
//! ```
//!
//! This library is built on top of [`smoltcp`] and [`boringtun`], and could not exist without these
//! amazing projects.

#![allow(clippy::match_like_matches_macro)]

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
