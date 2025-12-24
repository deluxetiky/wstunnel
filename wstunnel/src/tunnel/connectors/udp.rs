use std::time::Duration;

use url::Host;

use crate::protocols;
use crate::protocols::dns::DnsResolver;
use crate::protocols::udp::WsUdpSocket;
use crate::somark::SoMark;
use crate::tunnel::RemoteAddr;
use crate::tunnel::connectors::TunnelConnector;

#[derive(Clone)]
pub struct UdpTunnelConnector {
    host: Host,
    port: u16,
    so_mark: SoMark,
    connect_timeout: Duration,
    dns_resolver: DnsResolver,
}

impl UdpTunnelConnector {
    pub fn new(
        host: &Host,
        port: u16,
        so_mark: SoMark,
        connect_timeout: Duration,
        dns_resolver: &DnsResolver,
    ) -> UdpTunnelConnector {
        UdpTunnelConnector {
            host: host.clone(),
            port,
            so_mark,
            connect_timeout,
            dns_resolver: dns_resolver.clone(),
        }
    }
}

impl TunnelConnector for UdpTunnelConnector {
    type Reader = WsUdpSocket;
    type Writer = WsUdpSocket;

    async fn connect(&self, _: &Option<RemoteAddr>) -> anyhow::Result<(Self::Reader, Self::Writer)> {
        let stream =
            protocols::udp::connect(&self.host, self.port, self.connect_timeout, self.so_mark, &self.dns_resolver)
                .await?;

        Ok((stream.clone(), stream))
    }
}
