use super::io::{MAX_PACKET_LENGTH, TunnelRead, TunnelWrite};
use crate::protocols::tls;
use crate::tunnel::RemoteAddr;
use crate::tunnel::client::WsClient;
use crate::tunnel::transport::jwt::tunnel_to_jwt_token;
use crate::tunnel::transport::{TransportScheme, headers_from_file};
use anyhow::{Context, anyhow};
use bytes::{Bytes, BytesMut};
use hyper::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, HOST};
use hyper::http::response::Parts;
use hyper::{Request, Response};
use quinn::{Endpoint, RecvStream, SendStream};
use std::future::Future;
use std::io;
use std::io::ErrorKind;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};
use std::str::FromStr;
use std::sync::{Arc, LazyLock};
use tokio::io::AsyncWriteExt;
use tokio::sync::Notify;
use url::Host;
use uuid::Uuid;

pub struct QuicTunnelRead {
    inner: RecvStream,
    pre_read: Option<Bytes>,
}

impl QuicTunnelRead {
    pub const fn new(inner: RecvStream) -> Self {
        Self { inner, pre_read: None }
    }

    pub fn with_pre_read(mut self, pre_read: Option<Bytes>) -> Self {
        self.pre_read = pre_read;
        self
    }
}

impl TunnelRead for QuicTunnelRead {
    async fn copy(&mut self, mut writer: impl tokio::io::AsyncWrite + Unpin + Send) -> Result<(), io::Error> {
        if let Some(data) = self.pre_read.take() {
            writer.write_all(&data).await?;
        }
        loop {
            match self.inner.read_chunk(MAX_PACKET_LENGTH, true).await {
                Ok(Some(chunk)) => {
                    writer.write_all(&chunk.bytes).await?;
                }
                Ok(None) => return Ok(()),
                Err(e) => return Err(io::Error::new(ErrorKind::ConnectionAborted, e)),
            }
        }
    }
}

pub struct QuicTunnelWrite {
    inner: SendStream,
    buf: BytesMut,
}

impl QuicTunnelWrite {
    pub fn new(inner: SendStream) -> Self {
        Self {
            inner,
            buf: BytesMut::with_capacity(MAX_PACKET_LENGTH),
        }
    }
}

impl TunnelWrite for QuicTunnelWrite {
    fn buf_mut(&mut self) -> &mut BytesMut {
        &mut self.buf
    }

    async fn write(&mut self) -> Result<(), io::Error> {
        let data = self.buf.split().freeze();
        match self.inner.write_chunk(data).await {
            Ok(_) => Ok(()),
            Err(e) => Err(io::Error::new(ErrorKind::ConnectionAborted, e)),
        }
    }

    async fn ping(&mut self) -> Result<(), io::Error> {
        Ok(())
    }

    async fn close(&mut self) -> Result<(), io::Error> {
        match self.inner.finish() {
            Ok(_) => Ok(()),
            Err(e) => Err(io::Error::new(ErrorKind::BrokenPipe, e)),
        }
    }

    fn pending_operations_notify(&mut self) -> Arc<Notify> {
        Arc::new(Notify::new())
    }

    fn handle_pending_operations(&mut self) -> impl Future<Output = Result<(), io::Error>> + Send {
        std::future::ready(Ok(()))
    }
}

// Global endpoint to reuse the socket and configuration
static ENDPOINT: LazyLock<Endpoint> = LazyLock::new(|| {
    let mut endpoint = Endpoint::client(SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0)))
        .expect("Failed to create QUIC endpoint");
    let mut client_config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(
            crate::protocols::tls::rustls_client_config(
                true, // Default verify
                vec![b"h3".to_vec()],
                true, // enable SNI
                None, // ech
                None, // client cert
                None, // client key
            )
            .expect("Failed to create default rustls config"),
        )
        .expect("Failed to create quic client config"),
    ));

    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
    transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    client_config.transport_config(Arc::new(transport_config));

    endpoint.set_default_client_config(client_config);
    endpoint
});

fn get_endpoint() -> Endpoint {
    ENDPOINT.clone()
}

pub async fn connect(
    request_id: Uuid,
    client: &WsClient<impl crate::TokioExecutorRef>,
    dest_addr: &RemoteAddr,
) -> anyhow::Result<(QuicTunnelRead, QuicTunnelWrite, Parts)> {
    let endpoint = get_endpoint();

    // 1. Resolve DNS
    let host = client.config.remote_addr.host();
    let port = client.config.remote_addr.port();

    let remote_addr = match host {
        Host::Domain(domain) => {
            let addrs = client
                .config
                .dns_resolver
                .lookup_host(domain, port)
                .await
                .with_context(|| format!("cannot resolve domain: {domain}"))?;
            addrs
                .first()
                .cloned()
                .ok_or_else(|| anyhow!("no address found for {domain}"))?
        }
        Host::Ipv4(ip) => SocketAddr::V4(SocketAddrV4::new(*ip, port)),
        Host::Ipv6(ip) => SocketAddr::V6(SocketAddrV6::new(*ip, port, 0, 0)),
    };

    // 2. Connect
    // We need to configure TLS based on client config
    let tls_config = client
        .config
        .remote_addr
        .tls()
        .ok_or_else(|| anyhow!("QUIC requires TLS configuration"))?;

    let (tls_client_certificate, tls_client_key) =
        if let (Some(cert_path), Some(key_path)) = (&tls_config.tls_certificate_path, &tls_config.tls_key_path) {
            let certs = tls::load_certificates_from_pem(cert_path).context("Cannot load client TLS certificate")?;
            let key = tls::load_private_key_from_file(key_path).context("Cannot load client TLS private key")?;
            (Some(certs), Some(key))
        } else {
            (None, None)
        };

    let rustls_config = tls::rustls_client_config(
        tls_config.tls_verify_certificate,
        vec![b"h3".to_vec()],
        !tls_config.tls_sni_disabled,
        None, // ECH not piped through yet
        tls_client_certificate,
        tls_client_key,
    )?;

    let mut client_config =
        quinn::ClientConfig::new(Arc::new(quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)?));
    let mut transport_config = quinn::TransportConfig::default();
    transport_config.max_idle_timeout(Some(std::time::Duration::from_secs(30).try_into().unwrap()));
    if let Some(ping) = client.config.websocket_ping_frequency {
        transport_config.keep_alive_interval(Some(ping));
    }
    client_config.transport_config(Arc::new(transport_config));

    // Connect using the configured client config
    let connection = endpoint
        .connect_with(client_config, remote_addr, client.config.tls_server_name().to_str().as_ref())?
        .await
        .context("failed to connect to QUIC server")?;

    // 3. Open bi-directional stream
    let (mut send, mut recv) = connection.open_bi().await.context("failed to open QUIC stream")?;

    // 4. Send HTTP handshake
    let (headers_file, authority) =
        client
            .config
            .http_headers_file
            .as_ref()
            .map_or((None, None), |headers_file_path| {
                let (host, headers) = headers_from_file(headers_file_path);
                let host = if let Some((_, v)) = host {
                    match (client.config.remote_addr.scheme(), client.config.remote_addr.port()) {
                        (TransportScheme::Http, 80) | (TransportScheme::Https, 443) => {
                            Some(v.to_str().unwrap_or("").to_string())
                        }
                        (_, port) => Some(format!("{}:{}", v.to_str().unwrap_or(""), port)),
                    }
                } else {
                    None
                };

                (Some(headers), host)
            });

    let mut req = Request::builder()
        .method("POST")
        .uri(format!(
            "{}://{}/{}/events",
            client.config.remote_addr.scheme(),
            authority
                .as_deref()
                .unwrap_or_else(|| client.config.http_header_host.to_str().unwrap_or("")),
            &client.config.http_upgrade_path_prefix
        ))
        .header(COOKIE, tunnel_to_jwt_token(request_id, dest_addr))
        .header(CONTENT_TYPE, "application/json")
        .header(HOST, client.config.http_header_host.as_bytes())
        .version(hyper::Version::HTTP_11);

    let headers = match req.headers_mut() {
        Some(h) => h,
        None => {
            return Err(anyhow!(
                "failed to build HTTP request. Most likely path_prefix `{}` or http headers is not valid",
                client.config.http_upgrade_path_prefix
            ));
        }
    };

    for (k, v) in &client.config.http_headers {
        let _ = headers.remove(k);
        headers.append(k, v.clone());
    }

    if let Some(auth) = &client.config.http_upgrade_credentials {
        let _ = headers.remove(AUTHORIZATION);
        headers.append(AUTHORIZATION, auth.clone());
    }

    if let Some(headers_file) = headers_file {
        for (k, v) in headers_file {
            let _ = headers.remove(&k);
            headers.append(k, v);
        }
    }

    let req = req.body(()).unwrap();

    // Serialize request
    let mut buf = BytesMut::new();
    buf.extend_from_slice(format!("{} {} {:?}\r\n", req.method(), req.uri().path(), req.version()).as_bytes());
    for (name, value) in req.headers() {
        buf.extend_from_slice(name.as_str().as_bytes());
        buf.extend_from_slice(b": ");
        buf.extend_from_slice(value.as_bytes());
        buf.extend_from_slice(b"\r\n");
    }
    buf.extend_from_slice(b"\r\n");

    send.write_all(&buf).await?;

    // 5. Read response
    let mut resp_buf = BytesMut::with_capacity(4096);

    // Read enough for headers
    loop {
        let mut header_buf = [httparse::EMPTY_HEADER; 64];
        let chunk = recv
            .read_chunk(4096, true)
            .await?
            .ok_or_else(|| anyhow!("Connection closed during handshake"))?;
        resp_buf.extend_from_slice(&chunk.bytes);

        let (size, parts) = {
            let mut resp = httparse::Response::new(&mut header_buf);
            match resp.parse(&resp_buf) {
                Ok(httparse::Status::Complete(size)) => {
                    // Parse complete
                    if resp.code.unwrap_or(0) != 200 {
                        return Err(anyhow!("QUIC handshake failed: status {:?}", resp.code));
                    }

                    let mut parts = Response::builder()
                        .status(resp.code.unwrap())
                        .version(hyper::Version::HTTP_11)
                        .body(())
                        .unwrap()
                        .into_parts()
                        .0;

                    for h in resp.headers {
                        parts.headers.append(
                            hyper::header::HeaderName::from_str(h.name).unwrap(),
                            hyper::header::HeaderValue::from_bytes(h.value).unwrap(),
                        );
                    }
                    (size, parts)
                }
                Ok(httparse::Status::Partial) => continue,
                Err(e) => return Err(anyhow!("Failed to parse response: {:?}", e)),
            }
        };

        let extra_bytes = if resp_buf.len() > size {
            Some(resp_buf.split_off(size).freeze())
        } else {
            None
        };

        return Ok((
            QuicTunnelRead {
                inner: recv,
                pre_read: extra_bytes,
            },
            QuicTunnelWrite::new(send),
            parts,
        ));
    }
}
