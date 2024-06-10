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
