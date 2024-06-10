use std::{
    array,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    str::FromStr,
};

use boringtun::x25519::{PublicKey, StaticSecret};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

pub struct Config {
    pub interface: Interface,
    pub peers: Vec<Peer>,
}

pub struct Interface {
    pub address: Address,
    pub listen_port: Option<u16>,
    pub private_key: StaticSecret,
    pub mtu: Option<usize>,
}

#[derive(Debug, Clone)]
pub struct Peer {
    pub endpoint: Option<SocketAddr>,
    pub allowed_ips: Vec<IpNet>,
    pub public_key: PublicKey,
    pub persistent_keepalive: Option<u16>,
}

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
    pub fn cidrs(&self) -> impl Iterator<Item = IpNet> {
        match self {
            Self::Dual(v4, v6) => {
                AddressIterator::Dual([IpNet::V4(*v4), IpNet::V6(*v6)].into_iter())
            }
            Self::V4(net) => AddressIterator::Single([IpNet::V4(*net)].into_iter()),
            Self::V6(net) => AddressIterator::Single([IpNet::V6(*net)].into_iter()),
        }
    }

    pub fn ips(&self) -> impl Iterator<Item = IpAddr> {
        self.cidrs().map(|net| net.addr())
    }

    pub fn v4(&self) -> Option<Ipv4Addr> {
        match self {
            crate::config::Address::V4(net) | crate::config::Address::Dual(net, _) => {
                Some(net.addr())
            }
            _ => None,
        }
    }
    pub fn v6(&self) -> Option<Ipv6Addr> {
        match self {
            crate::config::Address::V6(net) | crate::config::Address::Dual(_, net) => {
                Some(net.addr())
            }
            _ => None,
        }
    }

    pub fn is_dual(&self) -> bool {
        matches!(self, Self::Dual(_, _))
    }
    pub fn is_v4(&self) -> bool {
        self.v4().is_some()
    }
    pub fn is_v6(&self) -> bool {
        self.v6().is_some()
    }

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
