use std::fs::File;
use std::io::{self, BufReader, Cursor, Read};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use futures::{future::join_all, join};
use tokio::net::TcpListener;
use tokio_rustls::{
    rustls::pki_types::{CertificateDer, PrivateKeyDer},
    rustls::ServerConfig as RustlsServerConfig,
    TlsAcceptor,
};

use crate::constants::CERTS_WATCH_DELAY_SECS;
use crate::errors::*;
use crate::{DoH, ServerConfig as HttpServerConfig};

pub fn create_tls_acceptor<P, P2>(certs_path: P, certs_keys_path: P2) -> io::Result<TlsAcceptor>
where
    P: AsRef<Path>,
    P2: AsRef<Path>,
{
    let certs: Vec<CertificateDer<'static>> = {
        let certs_path_str = certs_path.as_ref().display().to_string();
        let mut reader = BufReader::new(File::open(certs_path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("Unable to load the certificates [{certs_path_str}]: {e}"),
            )
        })?);
        rustls_pemfile::certs(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unable to parse the certificates: {e}"),
                )
            })?
    };
    let certs_keys: Vec<PrivateKeyDer<'static>> = {
        let certs_keys_path_str = certs_keys_path.as_ref().display().to_string();
        let encoded_keys = {
            let mut encoded_keys = vec![];
            File::open(certs_keys_path)
                .map_err(|e| {
                    io::Error::new(
                        e.kind(),
                        format!("Unable to load the certificate keys [{certs_keys_path_str}]: {e}"),
                    )
                })?
                .read_to_end(&mut encoded_keys)?;
            encoded_keys
        };
        let mut reader = Cursor::new(encoded_keys);
        let pkcs8_keys = rustls_pemfile::pkcs8_private_keys(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unable to parse the certificates private keys (PKCS8): {e}"),
                )
            })?;
        reader.set_position(0);
        let rsa_keys = rustls_pemfile::rsa_private_keys(&mut reader)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("Unable to parse the certificates private keys (RSA): {e}"),
                )
            })?;
        let mut keys: Vec<PrivateKeyDer<'static>> = pkcs8_keys
            .into_iter()
            .map(PrivateKeyDer::from)
            .collect();
        keys.extend(rsa_keys.into_iter().map(PrivateKeyDer::from));
        if keys.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "No private keys found - Make sure that they are in PKCS#8/PEM format",
            ));
        }
        keys
    };

    let mut server_config = certs_keys
        .into_iter()
        .find_map(|certs_key| {
            RustlsServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs.clone(), certs_key)
                .ok()
        })
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unable to find a valid certificate and key",
            )
        })?;
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

impl DoH {
    async fn start_https_service(
        self,
        tls_acceptor_store: Arc<ArcSwap<Arc<TlsAcceptor>>>,
        listener: TcpListener,
        server_config: Arc<HttpServerConfig>,
    ) -> Result<(), DoHError> {
        while let Ok((raw_stream, client_addr)) = listener.accept().await {
            let current_acceptor = tls_acceptor_store.load();
            if let Ok(stream) = current_acceptor.as_ref().as_ref().accept(raw_stream).await {
                let mut doh = self.clone();
                doh.remote_addr = Some(client_addr);
                doh.client_serve(stream, Arc::clone(&server_config)).await
            }
        }
        Ok(())
    }

    pub(crate) async fn start_with_tls(
        self,
        listeners: Vec<TcpListener>,
        server_config: Arc<HttpServerConfig>,
    ) -> Result<(), DoHError> {
        let certs_path = self
            .globals
            .tls_cert_path
            .as_ref()
            .ok_or_else(|| {
                DoHError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "TLS certificate path not provided",
                ))
            })?
            .clone();
        let certs_keys_path = self
            .globals
            .tls_cert_key_path
            .as_ref()
            .ok_or_else(|| {
                DoHError::Io(std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    "TLS certificate key path not provided",
                ))
            })?
            .clone();
        let initial_acceptor = loop {
            match create_tls_acceptor(&certs_path, &certs_keys_path) {
                Ok(acceptor) => break acceptor,
                Err(e) => {
                    eprintln!("TLS certificates error: {e}");
                    tokio::time::sleep(Duration::from_secs(CERTS_WATCH_DELAY_SECS.into())).await;
                }
            }
        };
        let tls_acceptor_store = Arc::new(ArcSwap::from_pointee(Arc::new(initial_acceptor)));

        let mut https_services = Vec::with_capacity(listeners.len());
        for listener in listeners {
            let doh = self.clone();
            let server_config = Arc::clone(&server_config);
            let tls_acceptor_store = Arc::clone(&tls_acceptor_store);
            https_services.push(tokio::spawn(async move {
                let _ = doh
                    .start_https_service(tls_acceptor_store, listener, server_config)
                    .await;
            }));
        }
        let cert_service = async {
            loop {
                match create_tls_acceptor(&certs_path, &certs_keys_path) {
                    Ok(new_acceptor) => {
                        tls_acceptor_store.store(Arc::new(Arc::new(new_acceptor)));
                    }
                    Err(e) => eprintln!("TLS certificates error: {e}"),
                }
                tokio::time::sleep(Duration::from_secs(CERTS_WATCH_DELAY_SECS.into())).await;
            }
        };
        let https_service = async {
            let _ = join_all(https_services).await;
            Ok::<_, DoHError>(())
        };
        let (https_result, _) = join!(https_service, cert_service);
        https_result
    }
}
