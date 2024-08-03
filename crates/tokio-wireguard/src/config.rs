use std::{
    array, fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use boringtun::x25519::{PublicKey, StaticSecret};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

/// WireGuard configuration
pub struct Config {
    /// Local interface configuration
    pub interface: Interface,
    /// Remote peer configurations
    ///
    /// Peers can also be added and removed dynamically at runtime using
    /// [`Interface::add_peer`](crate::Interface::add_peer) and [`Interface::remove_peer`](crate::Interface::remove_peer).
    pub peers: Vec<Peer>,
}

/// Local interface configuration
pub struct Interface {
    /// Local WireGuard address
    ///
    /// This is the address of the local peer on the WireGuard network,
    /// as opposed to the address on which WireGuard traffic is tunneled.
    ///
    /// This should be a unicast IPv4 or IPv6 address, or both. The network mask
    /// specifies which IP addresses the interface can forward traffic to in addition
    /// to its own address.
    pub address: Address,
    /// Port on which tunneled WireGuard traffic is listened for.
    ///
    /// If not specified, a random port is chosen.
    pub listen_port: Option<u16>,
    /// Private key of the local peer
    pub private_key: StaticSecret,
    /// MTU
    ///
    /// Should be left unspecified.
    pub mtu: Option<usize>,
}

/// Remote peer configuration
#[derive(Debug, Clone)]
pub struct Peer {
    /// Endpoint of the remote peer
    ///
    /// If not specified, the endpoint will be automatically populated when
    /// tunneled traffic from the peer is received.
    pub endpoint: Option<SocketAddr>,
    /// IP addresses for which the peer is allowed to send and receive traffic
    ///
    /// Some peers are capable of forwarding traffic, in which case this can be set to
    /// any number of IP addresses.
    pub allowed_ips: Vec<IpNet>,
    /// Public key of the remote peer
    pub public_key: PublicKey,
    /// Keepalive interval at which the peer is pinged
    ///
    /// This is useful when the local interface is behind a NAT to
    /// keep the connection alive.
    pub persistent_keepalive: Option<u16>,
}

/// An IPv4 or IPv6 address, or both, and their associated network mask
#[derive(Debug, Clone, Copy)]
pub enum Address {
    Dual(Ipv4Net, Ipv6Net),
    V4(Ipv4Net),
    V6(Ipv6Net),
}

#[derive(Debug)]
pub enum AddressFromStrErr {
    Invalid(<IpNet as FromStr>::Err),
    Multicast(IpNet),
    DuplicateV4,
    DuplicateV6,
    Empty,
}

impl Address {
    /// Returns an iterator over the full IP networks of the address
    pub fn networks(&self) -> impl Iterator<Item = IpNet> {
        match self {
            Self::Dual(v4, v6) => {
                AddressIterator::Dual([IpNet::V4(*v4), IpNet::V6(*v6)].into_iter())
            }
            Self::V4(net) => AddressIterator::Single([IpNet::V4(*net)].into_iter()),
            Self::V6(net) => AddressIterator::Single([IpNet::V6(*net)].into_iter()),
        }
    }

    /// Returns an iterator over the specific IP addresses of the address
    ///
    /// The iterator will only yield one or two addresses, as opposed to every address
    /// included in its networks.
    pub fn addresses(&self) -> impl Iterator<Item = IpAddr> {
        self.networks().map(|net| net.addr())
    }

    /// Returns the IPv4 address if there is one
    pub fn v4(&self) -> Option<Ipv4Addr> {
        match self {
            Self::V4(net) | Self::Dual(net, _) => Some(net.addr()),
            _ => None,
        }
    }
    /// Returns the IPv6 address if there is one
    pub fn v6(&self) -> Option<Ipv6Addr> {
        match self {
            Self::V6(net) | Self::Dual(_, net) => Some(net.addr()),
            _ => None,
        }
    }

    /// Whether the address is a dual stack address
    pub fn is_dual(&self) -> bool {
        matches!(self, Self::Dual(..))
    }
    /// Whether the address has an IPv4 address
    pub fn is_v4(&self) -> bool {
        matches!(self, Self::V4(..) | Self::Dual(..))
    }
    /// Whether the address has an IPv6 address
    pub fn is_v6(&self) -> bool {
        matches!(self, Self::V6(..) | Self::Dual(..))
    }

    /// Whether the address has the same family as the given address
    pub fn is_compatible(&self, other: SocketAddr) -> bool {
        match (self, other) {
            (Self::Dual(..) | Self::V4(..), SocketAddr::V4(..)) => true,
            (Self::Dual(..) | Self::V6(..), SocketAddr::V6(..)) => true,
            _ => false,
        }
    }
}

impl FromStr for Address {
    type Err = AddressFromStrErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut v4 = None;
        let mut v6 = None;

        let nets = s.split(',').map(|s| <IpNet as FromStr>::from_str(s.trim()));
        for net in nets {
            match net {
                Ok(net) if net.addr().is_multicast() => {
                    return Err(AddressFromStrErr::Multicast(net))
                }
                Ok(IpNet::V4(net)) => {
                    if v4.replace(net).is_some() {
                        return Err(AddressFromStrErr::DuplicateV4);
                    }
                }
                Ok(IpNet::V6(net)) => {
                    if v6.replace(net).is_some() {
                        return Err(AddressFromStrErr::DuplicateV6);
                    }
                }
                Err(err) => return Err(AddressFromStrErr::Invalid(err)),
            }
        }

        match (v4, v6) {
            (Some(v4), Some(v6)) => Ok(Address::Dual(v4, v6)),
            (Some(v4), None) => Ok(Address::V4(v4)),
            (None, Some(v6)) => Ok(Address::V6(v6)),
            (None, None) => Err(AddressFromStrErr::Empty),
        }
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Dual(v4, v6) => {
                fmt::Display::fmt(v4, f)?;
                f.write_str(",")?;
                fmt::Display::fmt(v6, f)?;
                Ok(())
            }
            Self::V4(v4) => fmt::Display::fmt(v4, f),
            Self::V6(v6) => fmt::Display::fmt(v6, f),
        }
    }
}

impl From<IpNet> for Address {
    fn from(net: IpNet) -> Self {
        match net {
            IpNet::V4(net) => Self::V4(net),
            IpNet::V6(net) => Self::V6(net),
        }
    }
}
impl From<Ipv4Net> for Address {
    fn from(net: Ipv4Net) -> Self {
        Self::V4(net)
    }
}
impl From<Ipv6Net> for Address {
    fn from(net: Ipv6Net) -> Self {
        Self::V6(net)
    }
}
impl From<IpAddr> for Address {
    fn from(addr: IpAddr) -> Self {
        Self::from(IpNet::from(addr))
    }
}
impl From<Ipv4Addr> for Address {
    fn from(addr: Ipv4Addr) -> Self {
        Self::from(Ipv4Net::from(addr))
    }
}
impl From<Ipv6Addr> for Address {
    fn from(addr: Ipv6Addr) -> Self {
        Self::from(Ipv6Net::from(addr))
    }
}

impl fmt::Display for AddressFromStrErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(err) => err.fmt(f),
            Self::Multicast(..) => f.write_str("multicast address"),
            Self::DuplicateV4 => f.write_str("duplicate IPv4 address"),
            Self::DuplicateV6 => f.write_str("duplicate IPv6 address"),
            Self::Empty => f.write_str("empty address"),
        }
    }
}

impl std::error::Error for AddressFromStrErr {}

enum AddressIterator<T> {
    Dual(array::IntoIter<T, 2>),
    Single(array::IntoIter<T, 1>),
}

impl<T> Iterator for AddressIterator<T> {
    type Item = T;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Dual(iter) => iter.next(),
            Self::Single(iter) => iter.next(),
        }
    }
}
impl<T> ExactSizeIterator for AddressIterator<T> {
    fn len(&self) -> usize {
        match self {
            Self::Dual(iter) => iter.len(),
            Self::Single(iter) => iter.len(),
        }
    }
}
impl<T> DoubleEndedIterator for AddressIterator<T> {
    fn next_back(&mut self) -> Option<Self::Item> {
        match self {
            Self::Dual(iter) => iter.next_back(),
            Self::Single(iter) => iter.next_back(),
        }
    }
}
