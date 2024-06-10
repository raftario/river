use tokio::io::{AsyncBufReadExt, BufReader};
use tokio_wireguard::{config::*, x25519, UdpSocket};

#[tokio::main]
async fn main() {
    let (server_secret, server_public) = x25519::keypair();
    let (client_secret, client_public) = x25519::keypair();

    let server_config = Config {
        interface: Interface {
            address: "100.64.0.1/32".parse().unwrap(),
            private_key: server_secret,
            listen_port: Some(51820),
            mtu: None,
        },
        peers: vec![Peer {
            allowed_ips: vec!["100.64.0.2/32".parse().unwrap()],
            public_key: client_public,
            endpoint: None,
            persistent_keepalive: None,
        }],
    };
    let client_config = Config {
        interface: Interface {
            address: "100.64.0.2/32".parse().unwrap(),
            private_key: client_secret,
            listen_port: None,
            mtu: None,
        },
        peers: vec![Peer {
            endpoint: "127.0.0.1:51820".parse().ok(),
            allowed_ips: vec!["100.64.0.1/32".parse().unwrap()],
            public_key: server_public,
            persistent_keepalive: None,
        }],
    };

    tokio::spawn(async move {
        let server = UdpSocket::bind("0.0.0.0:8080", server_config)
            .await
            .unwrap();

        println!(
            "Listening on {} (.exit to quit)",
            server.local_addr().unwrap()
        );

        let mut buf = Vec::new();
        loop {
            let (len, addr) = server.recv_from(&mut buf).await.unwrap();

            let message = std::str::from_utf8(&buf[..len]).unwrap();
            println!("[{addr}] {message}");

            buf.clear();
        }
    });

    let client = UdpSocket::bind("0.0.0.0:0", client_config).await.unwrap();

    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    while let Some(message) = stdin.next_line().await.unwrap() {
        if message == ".exit" {
            break;
        }

        client
            .send_to(message.as_bytes(), "100.64.0.1:8080")
            .await
            .unwrap();
    }
}
