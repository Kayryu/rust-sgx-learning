#![crate_name = "raserver"]
#![crate_type = "staticlib"]

#![no_std]

#[macro_use]
extern crate sgx_tstd as std;

use sgx_types::*;
use sgx_tcrypto::*;
use std::net::{TcpStream, TcpListener};
use std::sync::Arc;
use std::io::{BufReader, Read, Write};
use std::str;
use std::vec::Vec;
use std::borrow::ToOwned;
use std::string::String;

use log::{info, debug, error};
use tra::{Attestation, SgxCall, Net, RaX509Cert};

#[no_mangle]
pub extern "C" fn run_ra_web_server() -> sgx_status_t {
    env_logger::init();

    let sign_type = sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE;
    let spid: String = "22aa549a2d5e47a2933a753c1cae947c".to_owned();
    let key: String = "B6E792288644E2957A40AF226F5E4DD8".to_owned();

    // generate cert by remote attestation.
    let ecc_handle = SgxEccHandle::new();
    let result = ecc_handle.open();
    let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();
    let ocall = SgxCall {};
    let net = Net::new(spid, key);
    let report = Attestation::create_report(&net, &ocall, sign_type).unwrap();
    let (key_der, cert_der) = RaX509Cert::generate(&report, &prv_k, &pub_k, &ecc_handle);
    result.close();

    let mut cfg = rustls::ServerConfig::new(rustls::NoClientAuth::new());
    let mut certs = Vec::new();
    certs.push(rustls::Certificate(cert_der));
    let privkey = rustls::PrivateKey(key_der);

    cfg.set_single_cert_with_ocsp_and_sct(certs, privkey, vec![], vec![])
        .unwrap();

    let listener = TcpListener::bind("0.0.0.0:8448").unwrap();
    loop {
        match listener.accept() {
            Ok((mut socket, addr)) => {
                info!("new client from {:?}", addr);

                let mut session = rustls::ServerSession::new(&Arc::new(cfg.clone()));
                let mut tls = rustls::Stream::new(&mut session, &mut socket);
                let mut plaintext = [0u8; 1024];
                match tls.read(&mut plaintext) {
                    Ok(_) => {
                        info!("Client said: {}", str::from_utf8(&plaintext).unwrap());

                        let data = b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nHello world from rustls tlsserver\r\n";
                        tls.write(data).unwrap();
                    }
                    Err(e) => {
                        error!("Error in read_to_end: {:?}", e);
                    }
                };
            }
            Err(e) => error!("couldn't get client: {:?}", e),
        }
    }
    sgx_status_t::SGX_SUCCESS
}
