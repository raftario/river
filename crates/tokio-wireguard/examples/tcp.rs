use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio_wireguard::{config::*, x25519, TcpListener, TcpStream};

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
        let server = TcpListener::bind("0.0.0.0:8080", server_config)
            .await
            .unwrap();

        println!(
            "Listening on {} (.exit to quit)",
            server.local_addr().unwrap()
        );

        while let Ok((stream, addr)) = server.accept().await {
            tokio::spawn(async move {
                let mut stream = BufReader::new(stream).lines();
                while let Some(line) = stream.next_line().await.unwrap() {
                    println!("[{addr}] {line}");
                }
            });
        }
    });

    let mut client = TcpStream::connect("100.64.0.1:8080", client_config)
        .await
        .unwrap();

    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    while let Some(mut message) = stdin.next_line().await.unwrap() {
        if message == ".exit" {
            break;
        }

        message.push('\n');
        client.write_all(message.as_bytes()).await.unwrap();
    }
}
