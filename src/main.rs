use std::io::{stdout, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls;
use webpki;
use webpki_roots;

use rustls::Session;

// gemini://drewdevault.com/2020/09/27/Gemini-and-Hugo.gmi
// gemini://gemini.circumlunar.space/software/

pub struct FakeVerifier {}

impl FakeVerifier {
    pub fn new() -> FakeVerifier {
        FakeVerifier {}
    }
}

impl rustls::ServerCertVerifier for FakeVerifier {
    fn verify_server_cert(
        &self,
        roots: &rustls::RootCertStore,
        presented_certs: &[rustls::Certificate],
        dns_name: webpki::DNSNameRef,
        ocsp_response: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        println!("verify cert");
        Ok(rustls::ServerCertVerified::assertion())
    }
}

fn main() {
    let mut config = rustls::ClientConfig::new();
    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    config
        .dangerous()
        .set_certificate_verifier(Arc::new(FakeVerifier::new()));
    let dns_name = webpki::DNSNameRef::try_from_ascii_str("gus.guru").unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
    let mut sock = TcpStream::connect("gus.guru:1965").unwrap();
    let mut tls = rustls::Stream::new(&mut sess, &mut sock);
    tls.write("gus.guru\r\n".as_bytes()).unwrap();
    let ciphersuite = tls.sess.get_negotiated_ciphersuite().unwrap();
    writeln!(
        &mut std::io::stderr(),
        "Current ciphersuite: {:?}",
        ciphersuite.suite
    )
    .unwrap();
    let mut plaintext = Vec::new();
    tls.read_to_end(&mut plaintext).unwrap();
    stdout().write_all(&plaintext).unwrap();
}
