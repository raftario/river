use tokio::io::{AsyncRead, AsyncWrite};

pub trait UdpSocket {}

pub trait TcpStream: AsyncRead + AsyncWrite {}
