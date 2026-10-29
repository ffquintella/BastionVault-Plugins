//! TLS to the database with rustls on the `ring` provider, per the profile's
//! mode (§5.1): `verify-full` checks the chain and the name, `verify-ca` the
//! chain only, `require` encrypts without authenticating the server (the
//! handshake signatures are still checked), `disable` is plaintext. There is
//! no `prefer`: a mode never falls back to a weaker one.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::WebPkiServerVerifier;
use rustls::crypto::{ring, verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{pem::PemObject, CertificateDer, ServerName, UnixTime};
use rustls::{CertificateError, ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::tls::{ChannelBinding, TlsConnect, TlsStream};

use crate::profile::{Tls, TlsMode};
use crate::wire::{poll_read_watched, Wire};

/// Where trust anchors come from when the profile has no CA bundle.
pub type RootSource = fn() -> Result<Vec<CertificateDer<'static>>, String>;

/// The OS trust store; an empty one is an error, not a silent pass.
pub fn system_roots() -> Result<Vec<CertificateDer<'static>>, String> {
    let loaded = rustls_native_certs::load_native_certs();
    if loaded.certs.is_empty() {
        return Err(format!("no system root certificates could be loaded ({} errors)", loaded.errors.len()));
    }
    Ok(loaded.certs)
}

fn anchors(tls: &Tls, system: RootSource) -> Result<RootCertStore, String> {
    let certs = match &tls.ca_pem {
        Some(pem) => {
            let certs = CertificateDer::pem_slice_iter(pem.as_bytes())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "the profile's tls.ca_pem is not a PEM certificate bundle".to_string())?;
            if certs.is_empty() {
                return Err("the profile's tls.ca_pem holds no certificate".into());
            }
            certs
        }
        None => system()?,
    };
    let mut roots = RootCertStore::empty();
    let (added, _) = roots.add_parsable_certificates(certs);
    if added == 0 {
        return Err("no usable trust anchor for the connection".into());
    }
    Ok(roots)
}

/// The rustls configuration for an encrypted mode. `None` for `disable`.
pub fn client_config(tls: &Tls, system: RootSource) -> Result<Option<Arc<ClientConfig>>, String> {
    let provider = Arc::new(ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("TLS setup: {e}"))?;
    let config = match tls.mode {
        TlsMode::Disable => return Ok(None),
        TlsMode::VerifyFull => builder.with_root_certificates(anchors(tls, system)?).with_no_client_auth(),
        TlsMode::VerifyCa => {
            let inner = WebPkiServerVerifier::builder_with_provider(Arc::new(anchors(tls, system)?), provider)
                .build()
                .map_err(|e| format!("TLS setup: {e}"))?;
            builder.dangerous().with_custom_certificate_verifier(Arc::new(ChainOnly(inner))).with_no_client_auth()
        }
        TlsMode::Require => {
            builder.dangerous().with_custom_certificate_verifier(Arc::new(EncryptOnly(provider))).with_no_client_auth()
        }
    };
    Ok(Some(Arc::new(config)))
}

/// The name presented for SNI and checked by `verify-full`: the profile's
/// `tls.server_name`, else the host it dials.
pub fn server_name(tls: &Tls, host: &str) -> Result<ServerName<'static>, String> {
    let name = tls.server_name.as_deref().unwrap_or(host);
    ServerName::try_from(name.to_string()).map_err(|_| format!("`{name}` is not a valid TLS server name"))
}

/// `verify-ca`: the chain must verify; only a name mismatch is forgiven.
/// webpki checks the chain before the name, so a name error means the
/// chain itself verified.
#[derive(Debug)]
struct ChainOnly(Arc<WebPkiServerVerifier>);

impl ServerCertVerifier for ChainOnly {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        ocsp: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        match self.0.verify_server_cert(end_entity, intermediates, server_name, ocsp, now) {
            Err(rustls::Error::InvalidCertificate(
                CertificateError::NotValidForName | CertificateError::NotValidForNameContext { .. },
            )) => Ok(ServerCertVerified::assertion()),
            other => other,
        }
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls12_signature(m, c, d)
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.0.verify_tls13_signature(m, c, d)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.supported_verify_schemes()
    }
}

/// `require`: no chain or name check, as libpq's `sslmode=require` without
/// a root certificate. The handshake signatures are still verified.
#[derive(Debug)]
struct EncryptOnly(Arc<CryptoProvider>);

impl ServerCertVerifier for EncryptOnly {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// tokio-postgres' TLS hook over rustls, with the [`Wire`] watcher on the
/// decrypted side. No channel binding is offered (SCRAM without `-PLUS`).
#[derive(Clone)]
pub struct RustlsConnect {
    pub config: Arc<ClientConfig>,
    pub name: ServerName<'static>,
    pub wire: Arc<Wire>,
}

impl<S> TlsConnect<S> for RustlsConnect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = RustlsStream<S>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<RustlsStream<S>>> + Send>>;

    fn connect(self, stream: S) -> Self::Future {
        Box::pin(async move {
            let tls = tokio_rustls::TlsConnector::from(self.config).connect(self.name, stream).await?;
            Ok(RustlsStream { inner: tls, wire: self.wire })
        })
    }
}

pub struct RustlsStream<S> {
    inner: tokio_rustls::client::TlsStream<S>,
    wire: Arc<Wire>,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for RustlsStream<S> {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        poll_read_watched(&mut this.inner, &this.wire, cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for RustlsStream<S> {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> TlsStream for RustlsStream<S> {
    fn channel_binding(&self) -> ChannelBinding {
        ChannelBinding::none()
    }
}

#[cfg(test)]
mod tests {
    use rcgen::{generate_simple_self_signed, CertifiedKey};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::ServerConfig;
    use tokio_rustls::TlsAcceptor;

    use super::*;

    fn unrelated_roots() -> Result<Vec<CertificateDer<'static>>, String> {
        let other = generate_simple_self_signed(vec!["unrelated.example".to_string()]).map_err(|e| e.to_string())?;
        Ok(vec![other.cert.der().clone()])
    }

    fn server_for(name: &str) -> (TlsAcceptor, String) {
        let CertifiedKey { cert, signing_key } = generate_simple_self_signed(vec![name.to_string()]).unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
        let config = ServerConfig::builder_with_provider(Arc::new(ring::default_provider()))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key)
            .unwrap();
        (TlsAcceptor::from(Arc::new(config)), cert.pem())
    }

    /// Handshake against a server whose certificate names `cert_name`,
    /// dialling `dial_name`; `trust_it` puts that certificate in `ca_pem`.
    async fn handshake(mode: TlsMode, cert_name: &str, dial_name: &str, trust_it: bool) -> Result<(), String> {
        let (acceptor, cert_pem) = server_for(cert_name);
        let tls = Tls { mode, server_name: None, ca_pem: trust_it.then_some(cert_pem) };
        let config = client_config(&tls, unrelated_roots)?.expect("an encrypted mode");
        let connect = RustlsConnect { config, name: server_name(&tls, dial_name)?, wire: Wire::new(true) };
        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        let (client, _server) = tokio::join!(
            TlsConnect::<tokio::io::DuplexStream>::connect(connect, client_io),
            acceptor.accept(server_io)
        );
        client.map(|_| ()).map_err(|e| e.to_string())
    }

    fn rt() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap()
    }

    #[test]
    fn verify_full_checks_chain_and_name() {
        rt().block_on(async {
            handshake(TlsMode::VerifyFull, "db.internal", "db.internal", true).await.unwrap();
            assert!(handshake(TlsMode::VerifyFull, "db.internal", "other.internal", true).await.is_err());
            assert!(handshake(TlsMode::VerifyFull, "db.internal", "db.internal", false).await.is_err());
        });
    }

    #[test]
    fn verify_ca_checks_the_chain_but_not_the_name() {
        rt().block_on(async {
            handshake(TlsMode::VerifyCa, "db.internal", "other.internal", true).await.unwrap();
            let e = handshake(TlsMode::VerifyCa, "db.internal", "db.internal", false).await.unwrap_err();
            assert!(e.to_lowercase().contains("certificate"), "{e}");
        });
    }

    #[test]
    fn require_encrypts_without_authenticating() {
        rt().block_on(async {
            handshake(TlsMode::Require, "db.internal", "anything.example", false).await.unwrap();
        });
    }

    #[test]
    fn disable_has_no_config_and_bad_bundles_are_refused() {
        let off = Tls { mode: TlsMode::Disable, server_name: None, ca_pem: None };
        assert!(client_config(&off, unrelated_roots).unwrap().is_none());
        let bad = Tls { mode: TlsMode::VerifyFull, server_name: None, ca_pem: Some("not a pem".into()) };
        assert!(client_config(&bad, unrelated_roots).is_err());
        let none: RootSource = || Ok(Vec::new());
        let sys = Tls { mode: TlsMode::VerifyCa, server_name: None, ca_pem: None };
        assert!(client_config(&sys, none).is_err(), "an empty trust store is an error");
    }
}
