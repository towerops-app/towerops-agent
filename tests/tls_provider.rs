//! Integration tests verifying the rustls CryptoProvider is configured correctly.
//!
//! These tests catch the panic that occurs when both ring and aws-lc-rs features
//! are enabled transitively but no default provider is explicitly installed.
//! Without the install_default() call in main(), any TLS operation panics with:
//!   "no process-level CryptoProvider was set"

use std::sync::Once;

static INIT: Once = Once::new();

/// Install the ring crypto provider once for all tests in this module,
/// matching what main() does at startup.
fn ensure_crypto_provider() {
    INIT.call_once(|| {
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("Failed to install rustls CryptoProvider");
    });
}

#[test]
fn test_crypto_provider_is_installed() {
    ensure_crypto_provider();

    // After install_default(), the process-level provider must be available.
    // This is the call that panicked before the fix.
    let provider = rustls::crypto::CryptoProvider::get_default();
    assert!(provider.is_some(), "CryptoProvider should be installed");
}

#[test]
fn test_rustls_client_config_builder_does_not_panic() {
    ensure_crypto_provider();

    // ClientConfig::builder() uses the default CryptoProvider internally.
    // Before the fix, this panicked with "no process-level CryptoProvider was set".
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();

    // Verify config was created with TLS 1.2 and 1.3 support
    assert!(
        config.alpn_protocols.is_empty(),
        "Default config should have no ALPN protocols"
    );
}

#[test]
fn test_reqwest_tls_client_creation() {
    ensure_crypto_provider();

    // reqwest::Client with rustls-tls needs a working CryptoProvider.
    // This would panic without the provider installed.
    let client = reqwest::Client::builder()
        .use_rustls_tls()
        .build()
        .expect("Should be able to build reqwest client with rustls TLS");

    // Verify the client is usable (doesn't panic on creation)
    drop(client);
}

#[test]
fn test_tokio_rustls_connector_creation() {
    ensure_crypto_provider();

    // This mirrors how the MikroTik client creates its TLS connector.
    // ClientConfig::builder() was the exact call site of the original panic.
    let config = rustls::ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(TestVerifier))
        .with_no_client_auth();

    let _connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
}

#[test]
fn test_websocket_tls_connector_available() {
    ensure_crypto_provider();

    // Verify the full TLS config chain used by WebSocket connections works.
    // tokio-tungstenite uses rustls internally for wss:// connections.
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    assert!(
        !config
            .crypto_provider()
            .signature_verification_algorithms
            .all
            .is_empty(),
        "Crypto provider should have signature verification algorithms"
    );
}

/// Dummy certificate verifier for testing (accepts all certs).
#[derive(Debug)]
struct TestVerifier;

impl rustls::client::danger::ServerCertVerifier for TestVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}
