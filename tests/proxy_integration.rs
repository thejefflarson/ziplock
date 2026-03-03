use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Start a local TCP echo server. Returns the port it's listening on.
async fn start_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            if let Ok((mut stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    loop {
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                if stream.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
            }
        }
    });

    port
}

mod socks5 {
    use super::*;
    use fast_socks5::client;

    #[tokio::test]
    async fn connect_to_localhost_echo_server() {
        let echo_port = start_echo_server().await;

        let resolver = ziplock::dns::create_resolver().unwrap();
        let (ports, _shutdown) = ziplock::proxy::start(resolver).await.unwrap();

        // Connect through our SOCKS5 proxy to the local echo server
        let mut stream = client::Socks5Stream::connect(
            format!("127.0.0.1:{}", ports.socks5),
            "127.0.0.1".to_string(),
            echo_port,
            client::Config::default(),
        )
        .await
        .unwrap();

        // Send data and verify echo
        stream.write_all(b"hello ziplock").await.unwrap();
        stream.flush().await.unwrap();

        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello ziplock");
    }

    #[tokio::test]
    async fn blocks_public_ip_connections() {
        let resolver = ziplock::dns::create_resolver().unwrap();
        let (ports, _shutdown) = ziplock::proxy::start(resolver).await.unwrap();

        // Attempt to connect to a public IP (8.8.8.8) — should be rejected
        let result = client::Socks5Stream::connect(
            format!("127.0.0.1:{}", ports.socks5),
            "8.8.8.8".to_string(),
            53,
            client::Config::default(),
        )
        .await;

        assert!(result.is_err(), "public IP connection should be blocked");
    }

    #[tokio::test]
    #[ignore] // requires outbound network (DNS to 1.1.1.3 + TCP to example.com) — run with `cargo test -- --ignored`
    async fn resolves_real_domain() {
        let resolver = ziplock::dns::create_resolver().unwrap();
        let (ports, _shutdown) = ziplock::proxy::start(resolver).await.unwrap();

        // Connect to a real domain through the proxy — DNS should resolve via 1.1.1.3
        let result = client::Socks5Stream::connect(
            format!("127.0.0.1:{}", ports.socks5),
            "example.com".to_string(),
            80,
            client::Config::default(),
        )
        .await;

        // Should succeed — example.com is not blocked by Cloudflare family DNS
        assert!(
            result.is_ok(),
            "example.com should be resolvable: {:?}",
            result.err()
        );
    }

    #[tokio::test]
    async fn blocks_malware_domain() {
        let resolver = ziplock::dns::create_resolver().unwrap();
        let (ports, _shutdown) = ziplock::proxy::start(resolver).await.unwrap();

        // malware.testcategory.com is Cloudflare's official test domain for family DNS.
        // 1.1.1.3 returns 0.0.0.0 for it.
        let result = client::Socks5Stream::connect(
            format!("127.0.0.1:{}", ports.socks5),
            "malware.testcategory.com".to_string(),
            80,
            client::Config::default(),
        )
        .await;

        assert!(
            result.is_err(),
            "malware test domain should be blocked by DNS filter"
        );
    }
}

mod http_connect {
    use super::*;
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn connect_to_localhost_echo_server() {
        let echo_port = start_echo_server().await;

        let resolver = ziplock::dns::create_resolver().unwrap();
        let (ports, _shutdown) = ziplock::proxy::start(resolver).await.unwrap();

        // Send HTTP CONNECT to our proxy
        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", ports.http))
            .await
            .unwrap();

        let connect_req = format!(
            "CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\nHost: 127.0.0.1:{echo_port}\r\n\r\n"
        );
        stream.write_all(connect_req.as_bytes()).await.unwrap();

        // Read the 200 response
        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("200"),
            "expected 200 response, got: {response}"
        );

        // Now we have a tunnel — send data and verify echo
        stream.write_all(b"hello http connect").await.unwrap();
        stream.flush().await.unwrap();

        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello http connect");
    }

    #[tokio::test]
    async fn blocks_public_ip() {
        let resolver = ziplock::dns::create_resolver().unwrap();
        let (ports, _shutdown) = ziplock::proxy::start(resolver).await.unwrap();

        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", ports.http))
            .await
            .unwrap();

        let connect_req = "CONNECT 8.8.8.8:53 HTTP/1.1\r\nHost: 8.8.8.8:53\r\n\r\n";
        stream.write_all(connect_req.as_bytes()).await.unwrap();

        let mut buf = [0u8; 256];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("403"),
            "expected 403 for public IP, got: {response}"
        );
    }

    #[tokio::test]
    async fn blocks_malware_domain() {
        let resolver = ziplock::dns::create_resolver().unwrap();
        let (ports, _shutdown) = ziplock::proxy::start(resolver).await.unwrap();

        let mut stream = TcpStream::connect(format!("127.0.0.1:{}", ports.http))
            .await
            .unwrap();

        // malware.testcategory.com is Cloudflare's official test domain
        let connect_req = "CONNECT malware.testcategory.com:443 HTTP/1.1\r\nHost: malware.testcategory.com\r\n\r\n";
        stream.write_all(connect_req.as_bytes()).await.unwrap();

        let mut buf = [0u8; 512];
        let n = stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("403"),
            "expected 403 for blocked domain, got: {response}"
        );
    }
}
