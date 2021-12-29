mod cert;
mod error;
// mod attestation;
// mod net;
mod traits;
mod types;

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

// use sgx_tcrypto::SgxEccHandle;
use sgx_types::*;
use std::char;
use std::prelude::v1::*;

// use crate::attestation::Attestation;
// use crate::attestation::SgxCall;
// use crate::net::Net;
// use crate::cert::RaX509Cert;
// use crate::error::Error;

// pub fn gen_ecc_cert_with_sign_type(sign_type: sgx_quote_sign_type_t) -> Result<(Vec<u8>, Vec<u8>), Error> {
//     // Generate Keypair
//     let ecc_handle = SgxEccHandle::new();
//     let _result = ecc_handle.open();
//     let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();

//     // load files
//     let spid: String = "22aa549a2d5e47a2933a753c1cae947c".to_string();
//     let key: String = "22aa549a2d5e47a2933a753c1cae947c".to_string();

//     let ocall = SgxCall {};
//     let net = Net::new(spid, key);
//     let report = Attestation::create_report(&net, &ocall, sign_type)?;

//     let (key_der, cert_der) = RaX509Cert::generate(&report, &prv_k, &pub_k, &ecc_handle);
//     let _result = ecc_handle.close();
//     Ok((key_der, cert_der))
// }

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
    #[test]
    fn example() {
        // load files
        let spid: String = "22aa549a2d5e47a2933a753c1cae947c".to_string();
        let key: String = "22aa549a2d5e47a2933a753c1cae947c".to_string();
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
