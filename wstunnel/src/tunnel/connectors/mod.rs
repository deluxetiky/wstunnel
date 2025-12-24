use anyhow::anyhow;
use tokio::io::{AsyncRead, AsyncWrite};
use url::Url;

pub use sock5::Socks5TunnelConnector;
pub use tcp::TcpTunnelConnector;
pub use udp::UdpTunnelConnector;

use crate::tunnel::RemoteAddr;

mod sock5;
mod tcp;
mod udp;

pub trait TunnelConnector {
    type Reader: AsyncRead + Send + 'static;
    type Writer: AsyncWrite + Send + 'static;

    fn connect(
        &self,
        remote: &Option<RemoteAddr>,
    ) -> impl std::future::Future<Output = anyhow::Result<(Self::Reader, Self::Writer)>> + Send;

    fn connect_with_http_proxy(
        &self,
        _proxy: &Url,
        _remote: &Option<RemoteAddr>,
    ) -> impl std::future::Future<Output = anyhow::Result<(Self::Reader, Self::Writer)>> + Send {
        async {
            Err(anyhow!(
                "Requested to use HTTP Proxy to connect but it is not supported with this connector"
            ))
        }
    }
}
