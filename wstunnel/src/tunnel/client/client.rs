use crate::executor::{DefaultTokioExecutor, TokioExecutorRef};
use crate::tunnel;
use crate::tunnel::RemoteAddr;
use crate::tunnel::client::WsClientConfig;
use crate::tunnel::client::cnx_pool::WsConnection;
use crate::tunnel::client::quic_cnx_pool::QuicConnection;
use crate::tunnel::connectors::TunnelConnector;
use crate::tunnel::listeners::TunnelListener;
use crate::tunnel::tls_reloader::TlsReloader;
use crate::tunnel::transport::io::{TunnelReader, TunnelWriter};
use crate::tunnel::transport::{TransportScheme, jwt_token_to_tunnel};
use anyhow::Context;
use bb8::ManageConnection;
use futures_util::pin_mut;
use hyper::header::COOKIE;
use log::debug;
use rand::Rng;
use std::cmp::min;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{Mutex, Semaphore, oneshot};
use tokio_stream::StreamExt;
use tracing::{Instrument, Level, Span, error, event, span};
use url::Host;
use uuid::Uuid;

#[derive(Clone)]
pub struct WsClient<E: TokioExecutorRef = DefaultTokioExecutor> {
    pub config: Arc<WsClientConfig>,
    pub cnx_pool: bb8::Pool<WsConnection>,
    pub quic_cnx_pool: Option<bb8::Pool<QuicConnection>>,
    reverse_tunnel_connection_retry_max_backoff: Duration,
    reverse_tunnel_concurrency: usize,
    _tls_reloader: Arc<TlsReloader>,
    pub(crate) executor: E,
}

impl<E: TokioExecutorRef> WsClient<E> {
    pub async fn new(
        config: WsClientConfig,
        connection_min_idle: u32,
        connection_retry_max_backoff: Duration,
        reverse_tunnel_connection_retry_max_backoff: Duration,
        reverse_tunnel_concurrency: usize,
        executor: E,
    ) -> anyhow::Result<Self> {
        let config = Arc::new(config);
        let cnx = WsConnection::new(config.clone());
        let tls_reloader = TlsReloader::new_for_client(config.clone()).with_context(|| "Cannot create tls reloader")?;
        let cnx_pool = bb8::Pool::builder()
            .max_size(1000)
            .min_idle(Some(connection_min_idle))
            .max_lifetime(Some(Duration::from_secs(30)))
            .connection_timeout(connection_retry_max_backoff)
            .retry_connection(true)
            .build(cnx)
            .await?;

        // Create QUIC connection pool if using QUIC transport
        let quic_cnx_pool = match config.remote_addr.scheme() {
            TransportScheme::Quic | TransportScheme::Quics => {
                let quic_cnx = QuicConnection::new(config.clone());
                let pool = bb8::Pool::builder()
                    .max_size(1000)
                    .min_idle(Some(connection_min_idle))
                    // No max_lifetime for QUIC - connections can have long-lived streams
                    // (reverse tunnels, long file transfers, etc.)
                    .connection_timeout(connection_retry_max_backoff)
                    .retry_connection(true)
                    .build(quic_cnx)
                    .await?;
                Some(pool)
            }
            _ => None,
        };

        Ok(Self {
            config,
            cnx_pool,
            quic_cnx_pool,
            reverse_tunnel_connection_retry_max_backoff,
            reverse_tunnel_concurrency,
            _tls_reloader: Arc::new(tls_reloader),
            executor,
        })
    }

    pub async fn connect_to_server<R, W>(
        &self,
        request_id: Uuid,
        remote_cfg: &RemoteAddr,
        duplex_stream: (R, W),
    ) -> anyhow::Result<()>
    where
        R: AsyncRead + Send + 'static,
        W: AsyncWrite + Send + 'static,
    {
        // Connect to server with the correct protocol
        let (ws_rx, ws_tx, response) = match self.config.remote_addr.scheme() {
            TransportScheme::Ws | TransportScheme::Wss => {
                tunnel::transport::websocket::connect(request_id, self, remote_cfg)
                    .await
                    .map(|(r, w, response)| (TunnelReader::Websocket(r), TunnelWriter::Websocket(w), response))?
            }
            TransportScheme::Http | TransportScheme::Https => {
                tunnel::transport::http2::connect(request_id, self, remote_cfg)
                    .await
                    .map(|(r, w, response)| (TunnelReader::Http2(r), TunnelWriter::Http2(w), response))?
            }
            TransportScheme::Quic | TransportScheme::Quics => {
                tunnel::transport::quic::connect(request_id, self, remote_cfg, true)
                    .await
                    .map(|(r, w, response)| (TunnelReader::Quic(r), TunnelWriter::Quic(w), response))?
            }
        };

        debug!("Server response: {response:?}");
        let (local_rx, local_tx) = duplex_stream;
        let (close_tx, close_rx) = oneshot::channel::<()>();

        // Forward local tx to websocket tx
        let ping_frequency = self.config.websocket_ping_frequency;
        self.executor.spawn(
            super::super::transport::io::propagate_local_to_remote(local_rx, ws_tx, close_tx, ping_frequency)
                .instrument(Span::current()),
        );

        // Forward websocket rx to local rx
        let _ = super::super::transport::io::propagate_remote_to_local(local_tx, ws_rx, close_rx, async {}).await;

        Ok(())
    }

    pub async fn run_tunnel(self, tunnel_listener: impl TunnelListener) -> anyhow::Result<()> {
        pin_mut!(tunnel_listener);
        // everybody who connects to the local socket gets their own tunnel
        while let Some(cnx) = tunnel_listener.next().await {
            let (cnx_stream, remote_addr) = match cnx {
                Ok((cnx_stream, remote_addr)) => (cnx_stream, remote_addr),
                Err(err) => {
                    error!("Error accepting connection: {:?}", err);
                    continue;
                }
            };

            let request_id = Uuid::now_v7();
            let span = span!(
                Level::INFO,
                "tunnel",
                id = request_id.to_string(),
                remote = format!("{}:{}", remote_addr.host, remote_addr.port)
            );
            let client = self.clone();
            let tunnel = async move {
                let _ = client
                    .connect_to_server(request_id, &remote_addr, cnx_stream)
                    .await
                    .map_err(|err| error!("{:?}", err));
            }
            .instrument(span);

            self.executor.spawn(tunnel);
        }

        Ok(())
    }

    pub async fn run_reverse_tunnel<C>(self, remote_addr: RemoteAddr, connector: C) -> anyhow::Result<()>
    where
        C: TunnelConnector + Clone + Send + Sync + 'static,
    {
        fn new_reconnect_delay(max_delay: Duration) -> impl FnMut() -> Duration {
            let mut reconnect_delay = Duration::from_secs(1);

            move || -> Duration {
                let mut delay = reconnect_delay;
                // Add jitter of +/- 20% to avoid thundering herd problem
                let jitter = rand::thread_rng().gen_range(0.8..1.2);
                delay = delay.mul_f64(jitter);

                reconnect_delay = min(reconnect_delay * 2, max_delay);
                delay
            }
        }

        // Limit the number of concurrent reverse tunnels
        let semaphore = Arc::new(Semaphore::new(self.reverse_tunnel_concurrency));

        // For QUIC reverse tunnels, keep a single QUIC connection warm and open new streams on it.
        // This reduces “gaps” (DNS+TLS+QUIC handshake) between reverse tunnel sessions and helps
        // avoid stale/half-broken reconnect cycles.
        let shared_quic_cnx: Option<Arc<Mutex<Option<quinn::Connection>>>> = match self.config.remote_addr.scheme() {
            TransportScheme::Quic | TransportScheme::Quics => Some(Arc::new(Mutex::new(None))),
            _ => None,
        };

        loop {
            let permit = match semaphore.clone().acquire_owned().await {
                Ok(p) => p,
                Err(_) => break Ok(()),
            };

            let client = self.clone();
            let connector = connector.clone();
            let remote_addr = remote_addr.clone();
            let shared_quic_cnx = shared_quic_cnx.clone();
            let mut reconnect_delay = new_reconnect_delay(self.reverse_tunnel_connection_retry_max_backoff);

            self.executor.spawn(async move {
                let _permit = permit;
                let request_id = Uuid::now_v7();
                let span = span!(
                    Level::INFO,
                    "tunnel",
                    id = request_id.to_string(),
                    remote = format!("{}:{}", remote_addr.host, remote_addr.port)
                );

                // Connection retry loop for this slot
                let (ws_rx, ws_tx, response) = loop {
                    event!(
                        parent: &span,
                        Level::DEBUG,
                        "Reverse tunnel: Starting connection attempt with scheme {:?}",
                        client.config.remote_addr.scheme()
                    );
                    // Correctly configure tunnel cfg
                    match client.config.remote_addr.scheme() {
                        TransportScheme::Ws | TransportScheme::Wss => {
                            match tunnel::transport::websocket::connect(request_id, &client, &remote_addr)
                                .instrument(span.clone())
                                .await
                            {
                                Ok((r, w, response)) => {
                                    break (TunnelReader::Websocket(r), TunnelWriter::Websocket(w), response);
                                }
                                Err(err) => {
                                    let reconnect_delay = reconnect_delay();
                                    event!(
                                        parent: &span,
                                        Level::ERROR,
                                        "Retrying in {:?}, cannot connect to remote server: {:?}",
                                        reconnect_delay,
                                        err
                                    );
                                    tokio::time::sleep(reconnect_delay).await;
                                    continue;
                                }
                            }
                        }
                        TransportScheme::Http | TransportScheme::Https => {
                            match tunnel::transport::http2::connect(request_id, &client, &remote_addr)
                                .instrument(span.clone())
                                .await
                            {
                                Ok((r, w, response)) => {
                                    break (TunnelReader::Http2(r), TunnelWriter::Http2(w), response);
                                }
                                Err(err) => {
                                    let reconnect_delay = reconnect_delay();
                                    event!(
                                        parent: &span,
                                        Level::ERROR,
                                        "Retrying in {:?}, cannot connect to remote server: {:?}",
                                        reconnect_delay,
                                        err
                                    );
                                    tokio::time::sleep(reconnect_delay).await;
                                    continue;
                                }
                            }
                        }
                        TransportScheme::Quic | TransportScheme::Quics => {
                            event!(
                                parent: &span,
                                Level::DEBUG,
                                "Reverse tunnel: Attempting QUIC stream on shared connection for request {}",
                                request_id
                            );

                            let shared = match &shared_quic_cnx {
                                Some(s) => s.clone(),
                                None => {
                                    let reconnect_delay = reconnect_delay();
                                    event!(
                                        parent: &span,
                                        Level::ERROR,
                                        "Retrying in {:?}, missing shared QUIC connection state",
                                        reconnect_delay
                                    );
                                    tokio::time::sleep(reconnect_delay).await;
                                    continue;
                                }
                            };

                            // Ensure we have a usable QUIC connection we can open streams on.
                            let conn: quinn::Connection = loop {
                                let mut guard = shared.lock().await;
                                if let Some(conn) = guard.as_ref() {
                                    if conn.close_reason().is_none() {
                                        break conn.clone();
                                    }

                                    if let Some(reason) = conn.close_reason() {
                                        event!(
                                            parent: &span,
                                            Level::WARN,
                                            "Shared QUIC connection is closed ({:?}), creating new one",
                                            reason
                                        );
                                    }
                                    *guard = None;
                                }

                                match QuicConnection::new(client.config.clone()).connect().await {
                                    Ok(Some(conn)) => {
                                        *guard = Some(conn.clone());
                                        break conn;
                                    }
                                    Ok(None) => {
                                        let reconnect_delay = reconnect_delay();
                                        event!(
                                            parent: &span,
                                            Level::ERROR,
                                            "Retrying in {:?}, failed to connect to QUIC server (no connection)",
                                            reconnect_delay
                                        );
                                        drop(guard);
                                        tokio::time::sleep(reconnect_delay).await;
                                    }
                                    Err(err) => {
                                        let reconnect_delay = reconnect_delay();
                                        event!(
                                            parent: &span,
                                            Level::ERROR,
                                            "Retrying in {:?}, cannot connect to QUIC server: {:?}",
                                            reconnect_delay,
                                            err
                                        );
                                        drop(guard);
                                        tokio::time::sleep(reconnect_delay).await;
                                    }
                                }
                            };

                            match tunnel::transport::quic::connect_on_connection(
                                request_id,
                                &client,
                                &remote_addr,
                                &conn,
                            )
                            .instrument(span.clone())
                            .await
                            {
                                Ok((r, w, response)) => {
                                    event!(parent: &span, Level::DEBUG, "Reverse tunnel: QUIC stream established");
                                    break (TunnelReader::Quic(r), TunnelWriter::Quic(w), response);
                                }
                                Err(err) => {
                                    // Connection may be half-broken (NAT rebinding, path migration, idle timeout, etc.)
                                    // Drop it so we force a full reconnect next attempt.
                                    *shared.lock().await = None;

                                    let reconnect_delay = reconnect_delay();
                                    event!(
                                        parent: &span,
                                        Level::ERROR,
                                        "Retrying in {:?}, cannot open QUIC stream to remote server: {:?}",
                                        reconnect_delay,
                                        err
                                    );
                                    tokio::time::sleep(reconnect_delay).await;
                                    continue;
                                }
                            }
                        }
                    };
                };

                // Connect to endpoint
                event!(parent: &span, Level::DEBUG, "Server response: {:?}", response);
                let remote = response
                    .headers
                    .get(COOKIE)
                    .and_then(|h| h.to_str().ok())
                    .and_then(|h| jwt_token_to_tunnel(h).ok())
                    .map(|jwt| RemoteAddr {
                        protocol: jwt.claims.p,
                        host: Host::parse(&jwt.claims.r).unwrap_or_else(|_| Host::Domain(String::new())),
                        port: jwt.claims.rp,
                    });

                let (local_rx, local_tx) = match connector.connect(&remote).instrument(span.clone()).await {
                    Ok(s) => s,
                    Err(err) => {
                        event!(parent: &span, Level::ERROR, "Cannot connect to {remote:?}: {err:?}");
                        return;
                    }
                };

                let (close_tx, close_rx) = oneshot::channel::<()>();
                client.executor.spawn({
                    let ping_frequency = client.config.websocket_ping_frequency;
                    super::super::transport::io::propagate_local_to_remote(local_rx, ws_tx, close_tx, ping_frequency)
                        .instrument(span.clone())
                });

                // Forward websocket rx to local rx
                let config = client.config.clone();
                let graceful_shutdown = async move {
                    if let TransportScheme::Quic | TransportScheme::Quics = config.remote_addr.scheme() {
                        // For QUIC, we need to wait a bit before closing the tunnel to allow the client to receive the response
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                };

                let _ = super::super::transport::io::propagate_remote_to_local(
                    local_tx,
                    ws_rx,
                    close_rx,
                    graceful_shutdown,
                )
                .instrument(span.clone())
                .await;
            });
        }
    }
}
