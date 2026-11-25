use std::env;
use std::net::{SocketAddr, TcpListener as StdTcpListener};
use std::pin::Pin;
use std::sync::Arc;

use openssl::ssl::{AlpnError, Ssl, SslAcceptor, SslFiletype, SslMethod, SslOptions, SslVersion};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio_openssl::SslStream;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 5 {
        eprintln!("WinRM OpenSSL 3 TLS Front-End (Windows Schannel: TLS 1.2 CBC + AES-GCM, NO ChaCha20)");
        eprintln!("Usage: {} <listen_addr> <backend_addr> <cert.pem> <key.pem>", args[0]);
        std::process::exit(1);
    }

    let listen_addr = &args[1];
    let backend_addr = args[2].clone();
    let cert_path = &args[3];
    let key_path = &args[4];

    // Настраиваем OpenSSL 3 под профиль Windows Server 2022/2025 Schannel:
    // - TLS 1.3 строго AES-GCM (без ChaCha20)
    // - TLS 1.2 с поддержкой CBC-шифров (ECDHE-RSA-AES256-SHA384 и др.)
    // - Без ALPN h2
    let mut builder = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server())?;
    builder.set_private_key_file(key_path, SslFiletype::PEM)?;
    builder.set_certificate_chain_file(cert_path)?;
    builder.set_min_proto_version(Some(SslVersion::TLS1_2))?;
    builder.set_max_proto_version(Some(SslVersion::TLS1_3))?;
    builder.set_ciphersuites("TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256")?;
    builder.set_cipher_list(
        "ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256:\
         ECDHE-RSA-AES256-SHA384:ECDHE-RSA-AES128-SHA256:\
         ECDHE-RSA-AES256-SHA:ECDHE-RSA-AES128-SHA:\
         AES256-GCM-SHA384:AES128-GCM-SHA256:\
         AES256-SHA256:AES128-SHA256:\
         AES256-SHA:AES128-SHA:@SECLEVEL=1",
    )?;
    builder.set_options(SslOptions::CIPHER_SERVER_PREFERENCE);
    builder.set_groups_list("X25519:P-256:P-384")?;
    builder.set_alpn_select_callback(|_, _| Err(AlpnError::NOACK));

    let acceptor = Arc::new(builder.build());

    // Выставляем IP_TTL = 128 на слушающий сокет (как в Windows Server)
    let addr: SocketAddr = listen_addr.parse()?;
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_ttl(128)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;

    let std_listener: StdTcpListener = socket.into();
    std_listener.set_nonblocking(true)?;
    let listener = TcpListener::from_std(std_listener)?;

    println!(
        "[openssl3] Listening on {} -> backend {} (Schannel CBC+GCM, ChaCha20 disabled, TTL=128)",
        listen_addr, backend_addr
    );

    loop {
        let (stream, _peer) = match listener.accept().await {
            Ok(v) => v,
            Err(_) => continue,
        };
        let acceptor = acceptor.clone();
        let backend = backend_addr.clone();

        tokio::spawn(async move {
            let _ = stream.set_nodelay(true);
            let ssl = match Ssl::new(acceptor.context()) {
                Ok(s) => s,
                Err(_) => return,
            };
            let mut tls_stream = match SslStream::new(ssl, stream) {
                Ok(s) => s,
                Err(_) => return,
            };
            if Pin::new(&mut tls_stream).accept().await.is_err() {
                return;
            }
            let mut back_stream = match TcpStream::connect(&backend).await {
                Ok(s) => s,
                Err(_) => return,
            };
            let _ = back_stream.set_nodelay(true);
            let _ = copy_bidirectional(&mut tls_stream, &mut back_stream).await;
        });
    }
}
