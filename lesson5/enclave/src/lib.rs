#![crate_name = "tlsEnclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]
#![warn(unused_extern_crates)]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use sgx_types::*;
use std::net::{TcpStream, TcpListener};
use std::prelude::v1::*;
use std::sync::Arc;
use std::io::{BufReader, Read, Write};
use std::str;
use std::vec::Vec;
use log::{info, debug, error};

mod attestation;
mod cert;
mod hex;

#[no_mangle]
pub extern "C" fn run_ra_web_server() -> sgx_status_t {
    env_logger::init();

    let sign_type = sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE;

    // generate cert by remote attestation.
    let (mut key_der, cert_der) = attestation::gen_ecc_cert_with_sign_type(sign_type).unwrap();

    let mut cfg = rustls::ServerConfig::new(rustls::NoClientAuth::new());
    let mut certs = Vec::new();
    certs.push(rustls::Certificate(cert_der));
    // TEST key_der[1] = 1;  if private key and public key not equal, set_single_cert_with_ocsp_and_sct will panic.
    // thread '<unnamed>' panicked at 'called `Result::unwrap()` on an `Err` value: General("invalid private key")', src/lib.rs:40:10
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
                let mut plaintext = [0u8; 1024]; //Vec::new();
                match tls.read(&mut plaintext) {
                    Ok(_) => {
                        info!("Client said: {}", str::from_utf8(&plaintext).unwrap());

                        let data = b"HTTP/1.0 200 OK\r\nConnection: close\r\n\r\nHello world from rustls tlsserver\r\n";
                        tls.write(data).unwrap();
                    },
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
