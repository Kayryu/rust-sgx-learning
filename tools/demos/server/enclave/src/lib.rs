// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![crate_name = "raserver"]
#![crate_type = "staticlib"]
#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;

use sgx_types::*;
use std::io::{self, Write};
use std::slice;
use std::string::String;
use std::vec::Vec;

#[no_mangle]
pub extern "C" fn run_ra_web_server() -> sgx_status_t {
    env_logger::init();

    let sign_type = sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE;

    // generate cert by remote attestation.
    let (mut key_der, cert_der) = attestation::gen_ecc_cert_with_sign_type(sign_type).unwrap();

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
                let mut plaintext = [0u8; 1024]; //Vec::new();
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
