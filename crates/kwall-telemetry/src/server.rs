//! Lightweight HTTP metrics server serving `/metrics` for Prometheus scraping.

use crate::metrics::TelemetryRegistry;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{error, info};

/// Starts an asynchronous metrics server exposing Prometheus metrics on `GET /metrics`.
pub async fn start_metrics_server(
    addr: SocketAddr,
    registry: Arc<TelemetryRegistry>,
) -> std::io::Result<JoinHandle<()>> {
    let listener = TcpListener::bind(addr).await?;
    info!("KWALL Prometheus metrics server listening on http://{addr}/metrics");

    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((mut socket, _)) => {
                    let registry = registry.clone();
                    tokio::spawn(async move {
                        let mut buf = [0u8; 1024];
                        if let Ok(n) = socket.read(&mut buf).await {
                            let request = String::from_utf8_lossy(&buf[..n]);
                            if request.starts_with("GET /metrics") {
                                let body = registry.render_prometheus();
                                let response = format!(
                                    "HTTP/1.1 200 OK\r\n\
                                     Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n\
                                     Content-Length: {}\r\n\
                                     Connection: close\r\n\r\n{}",
                                    body.len(),
                                    body
                                );
                                let _ = socket.write_all(response.as_bytes()).await;
                            } else {
                                let not_found = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
                                let _ = socket.write_all(not_found.as_bytes()).await;
                            }
                        }
                    });
                }
                Err(err) => {
                    error!("Error accepting metrics connection: {err}");
                    break;
                }
            }
        }
    });

    Ok(handle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    #[tokio::test]
    async fn test_metrics_http_endpoint() {
        let registry = Arc::new(TelemetryRegistry::new());
        registry.record_packet_passed(500);

        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = TcpListener::bind(addr).await.unwrap();
        let bound_addr = listener.local_addr().unwrap();
        drop(listener);

        let _server = start_metrics_server(bound_addr, registry).await.unwrap();

        // Connect and request /metrics
        let mut stream = TcpStream::connect(bound_addr).await.unwrap();
        stream
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .unwrap();

        let mut res = String::new();
        stream.read_to_string(&mut res).await.unwrap();

        assert!(res.contains("HTTP/1.1 200 OK"));
        assert!(res.contains("kwall_packets_processed_total{action=\"pass\"} 1"));
    }
}
