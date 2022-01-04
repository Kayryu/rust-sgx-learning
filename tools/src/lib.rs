#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "sgx")]
#[macro_use]
extern crate sgx_tstd as std;

mod certificate;
mod error;
mod attestation;
mod ias;
mod traits;
mod types;

pub use certificate::RaX509Cert;
pub use error::Error;
pub use traits::AttestationReportVerifier;
pub use types::*;
pub use ias::Net;
pub use attestation::Attestation;
pub use sgx_types::sgx_quote_sign_type_t;

use std::prelude::v1::*;

/*
目标，该库既能在sgx中编译，同时也能在native和wasm编译。

主要有两大功能，report相关，证书相关。

其中report生成只能运行在sgx中，因为与sgx的quote相关的。其他的可以三个平台都能运行。

目录结构：
examples
    sgx_server
    verify_client
src
cargo.toml


关于不同平台包重名问题，参考https://github.com/Phala-Network/khala-parachain/blob/main/pallets/phala/Cargo.toml#L41处理。
命令行工具 https://github.com/CGair23/ura/blob/master/cmd_ura/src/main.rs

*/

use sgx_tcrypto::*;
use sgx_types::*;
use std::char;

#[cfg(feature = "sgx")]
pub fn gen_ecc_cert_with_sign_type(spid: String, ias_key: String, sign_type: sgx_quote_sign_type_t) -> Result<(Vec<u8>, Vec<u8>), Error> {
    // Generate Keypair
    let ecc_handle = SgxEccHandle::new();
    let _result = ecc_handle.open();
    let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();

    let net = Net::new(spid, ias_key);
    let report = Attestation::create_report(&net, &into_attition(pub_k), sign_type)?;

    let (key_der, cert_der) = RaX509Cert::<Attestation>::generate(&report, &prv_k, &pub_k, &ecc_handle);
    let _result = ecc_handle.close();
    Ok((key_der, cert_der))
}

#[cfg(not(feature = "sgx"))]
pub fn verify_cert(cert: &[u8], now: u64) -> Result<EnclaveFields, Error> {
    RaX509Cert::<Attestation>::verify(&cert, now)
}

pub(crate) fn into_attition(pub_k: sgx_ec256_public_t) -> [u8; 64] {
    let mut pub_k_gx = pub_k.gx.clone();
    pub_k_gx.reverse();
    let mut pub_k_gy = pub_k.gy.clone();
    pub_k_gy.reverse();
    let mut addition:[u8; 64] = [0u8; 64];
    addition[..32].clone_from_slice(&pub_k_gx);
    addition[32..].clone_from_slice(&pub_k_gy);
    addition
}

pub struct Utils {}

impl Utils {
    fn decode_spid(hex: &str) -> sgx_spid_t {
        let mut spid = sgx_spid_t::default();
        let hex = hex.trim();

        if hex.len() < 16 * 2 {
            println!("Input spid file len ({}) is incorrect!", hex.len());
            return spid;
        }

        let decoded_vec = Self::decode_hex(hex);

        spid.id.copy_from_slice(&decoded_vec[..16]);

        spid
    }

    pub fn decode_hex(hex: &str) -> Vec<u8> {
        let mut r: Vec<u8> = Vec::new();
        let mut chars = hex.chars().enumerate();
        loop {
            let (pos, first) = match chars.next() {
                None => break,
                Some(elt) => elt,
            };
            if first == ' ' {
                continue;
            }
            let (_, second) = match chars.next() {
                None => panic!("pos = {}d", pos),
                Some(elt) => elt,
            };
            r.push((Self::decode_hex_digit(first) << 4) | Self::decode_hex_digit(second));
        }
        r
    }

    fn decode_hex_digit(digit: char) -> u8 {
        match digit {
            '0'..='9' => digit as u8 - '0' as u8,
            'a'..='f' => digit as u8 - 'a' as u8 + 10,
            'A'..='F' => digit as u8 - 'A' as u8 + 10,
            _ => panic!(),
        }
    }
}

#[cfg(test)]
mod tests {
    const c_prv_k: [u8;32] = [44, 227, 141, 100, 114, 207, 218, 155, 139, 188, 37, 197, 185, 21, 193, 87, 88, 54, 231, 73, 151, 162, 195, 83, 151, 147, 6, 48, 26, 47, 10, 226];
    const c_pub_k_gx: [u8;32] = [74, 145, 120, 205, 221, 0, 154, 144, 163, 82, 192, 196, 1, 15, 118, 75, 209, 154, 237, 169, 167, 41, 150, 215, 244, 154, 243, 39, 50, 184, 78, 148];
    const c_pub_k_gy: [u8;32] = [146, 163, 127, 120, 250, 35, 208, 197, 56, 239, 187, 69, 194, 96, 236, 87, 96, 201, 19, 37, 24, 126, 229, 213, 59, 96, 112, 4, 165, 220, 160, 51];


    #[test]
    fn example() {
        // load files
        let spid: String = "22aa549a2d5e47a2933a753c1cae947c".to_string();
        let key: String = "22aa549a2d5e47a2933a753c1cae947c".to_string();
        
        let prv_k: sgx_ec256_private_t = sgx_ec256_private_t {r: c_prv_k.clone()};
        let pub_k: sgx_ec256_public_t = sgx_ec256_public_t { gx: c_pub_k_gx.clone(), gy: c_pub_k_gy.clone()};
    
        // init net
        // let net = Net::new(spid, key);

        // // init ocall
        // let ocall = SgxCall::default();
        // let sign_type = sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE;
        // let pk = [0x00, 0x00];
        // let report = Attestation::create_report(&net, &ocall, &pk, sign_type).unwrap();
        // assert!(Attestation::verify(&report));

        // let cert = RaX509Cert::generate(&report).unwrap();
        // assert!(RaX509Cert::verify(&cert));
    }
}
