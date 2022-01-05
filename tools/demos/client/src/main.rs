use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::str;
use std::sync::Arc;
use tra::{AttestationReportVerifier, RaX509Cert, EnclaveFields, AttestationReport, Error, verify_cert};
use std::time::{SystemTime, UNIX_EPOCH};

const SERVERADDR: &str = "13.82.110.144:8448";

struct MockVerifier;
impl AttestationReportVerifier for MockVerifier {
    fn verify(_report: &AttestationReport, now: u64) -> Result<EnclaveFields, Error> {
        Ok(EnclaveFields::default())
    }
}

struct ServerAuth {
    outdated_ok: bool,
}

impl ServerAuth {
    fn new(outdated_ok: bool) -> ServerAuth {
        ServerAuth { outdated_ok }
    }
}

impl rustls::ServerCertVerifier for ServerAuth {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _certs: &[rustls::Certificate],
        _hostname: webpki::DNSNameRef,
        _ocsp: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        // This call will automatically verify cert is properly signed
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        match verify_cert(&_certs[0].0, now) {
            Ok(a) => {
                println!("enclave fields: {}", a);
                Ok(rustls::ServerCertVerified::assertion())
            },
            Err(_) => Err(rustls::TLSError::WebPKIError(webpki::Error::ExtensionValueInvalid)),
        }
    }
}

fn make_config() -> rustls::ClientConfig {
    let mut config = rustls::ClientConfig::new();

    config
        .dangerous()
        .set_certificate_verifier(Arc::new(ServerAuth::new(true)));
    config.versions.clear();
    config.versions.push(rustls::ProtocolVersion::TLSv1_2);

    config
}

fn main() {
    println!("Starting ra-client, Connecting to {}", SERVERADDR);

    let client_config = make_config();
    let dns_name = webpki::DNSNameRef::try_from_ascii_str("safematrix").unwrap();
    let mut sess = rustls::ClientSession::new(&Arc::new(client_config), dns_name);

    let mut conn = TcpStream::connect(SERVERADDR).unwrap();
    let mut conn = rustls::Stream::new(&mut sess, &mut conn);

    conn.write_all(b"POST \r / HTTP/1.1 200\r\n Host: 123\r\n\r\nHello world from rustls tlsserver\r\n ").unwrap();

    let mut plaintext = Vec::new();
    match conn.read_to_end(&mut plaintext) {
        Ok(_) => {
            println!("Server replied: {}", str::from_utf8(&plaintext).unwrap());
        }
        Err(ref err) if err.kind() == io::ErrorKind::ConnectionAborted => {
            println!("EOF (tls)");
        }
        Err(e) => println!("Error in read_to_end: {:?}", e),
    }
}
