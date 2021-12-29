#![allow(dead_code)]
#![allow(unused_assignments)]

mod enclave;
mod ocall;

use sgx_types::*;

use crate::enclave::EnclaveBuilder;
use log::{debug, error, info};
use std::env;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::os::unix::io::{AsRawFd, IntoRawFd};
use std::str;

extern "C" {
    fn run_ra_web_server(eid: sgx_enclave_id_t, retval: *mut sgx_status_t) -> sgx_status_t;
}

fn main() {
    env_logger::init();
    // init enclave
    let enclave = EnclaveBuilder::new().create().unwrap();

    info!("Running as server...");
    let mut retval = sgx_status_t::SGX_SUCCESS;
    let result = unsafe { run_ra_web_server(enclave.eid(), &mut retval) };
    match result {
        sgx_status_t::SGX_SUCCESS => {
            info!("ECALL success!");
        }
        _ => {
            error!("[-] ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }
    info!("[+] Done!");
    enclave.destroy();
}
