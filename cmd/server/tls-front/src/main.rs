use std::env;
use std::fs::File;
use std::io::BufReader;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::sync::Arc;

use rustls::crypto::ring;
use rustls::ServerConfig;
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("WinRM Rustls TLS Front-End (Windows Server AES-GCM only, NO ChaCha20)");
        eprintln!("Usage: {} <listen_addr> <backend_addr> <cert.pem> <key.pem>", args[0]);
        eprintln!("Example: {} 0.0.0.0:5986 127.0.0.1:15986 winrm_cert.pem winrm_key.pem", args[0]);
        std::process::exit(1);
    }

    let listen_addr = &args[1];
    let backend_addr = args[2].clone();
    let cert_path = &args[3];
    let key_path = &args[4];

    // Загружаем сертификат и приватный ключ, сгенерированные winrm-vpn-server
    let mut cert_reader = BufReader::new(File::open(cert_path)?);
    let certs = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;

    let mut key_reader = BufReader::new(File::open(key_path)?);
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or("no private key found in key file")?;

    // Настраиваем CryptoProvider строго БЕЗ ChaCha20 (как в Windows Server 2022/2025 Schannel)
    let mut provider = ring::default_provider();
    provider.cipher_suites = vec![
        ring::cipher_suite::TLS13_AES_256_GCM_SHA384,
        ring::cipher_suite::TLS13_AES_128_GCM_SHA256,
        ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        ring::cipher_suite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    ];

    let mut config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    // WinRM http.sys не использует ALPN h2
    config.alpn_protocols.clear();

    let acceptor = TlsAcceptor::from(Arc::new(config));

    // Выставляем IP_TTL = 128 на слушающий сокет (как в Windows Server, без root)
    let addr: SocketAddr = listen_addr.parse()?;
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_ttl(128)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    let std_listener: StdTcpListener = socket.into();
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;

    println!("[rustls] Listening on {} -> backend {} (AES-GCM only, ChaCha20 disabled, TTL=128)", listen_addr, backend_addr);

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let acceptor = acceptor.clone();
        let backend = backend_addr.clone();

        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            let mut tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut back_stream = match TcpStream::connect(&backend).await {
                Ok(s) => s,
                Err(_) => return,
            };
            let _ = back_stream.set_nodelay(true);
            let _ = copy_bidirectional(&mut tls_stream, &mut back_stream).await;
        });
    }
}
