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

#![crate_name = "storesample"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_tseal;

use sgx_tseal::SgxSealedData;
use sgx_types::marker::ContiguousMemory;

use sgx_types::*;
use std::string::String;
use std::vec::Vec;
use std::io::{self, Write};
use std::slice;
use std::mem::size_of;

const MAX_SEALED_LOG_BYTE: usize = 10_000;

/// Define ocall apis
#[no_mangle]
extern "C" {
    pub fn save_to_untrusted_db(
        ret_val: *mut sgx_status_t,
        key_pointer: *const u8,
        key_size: u32,
        value_pointer: *const u8,
        value_size: u32,
    ) -> sgx_status_t;

    pub  fn load_from_untrusted_db(
        ret_val: *mut sgx_status_t,
        key_pointer: *const u8,
        key_size: u32,
        value_pointer: *mut u8,
        value_size: u32,
    ) -> sgx_status_t;
}

// struct Sealer {
// }

// impl Sealer {
//     fn seal(data: &[u8]) -> Result<Vec<u8>, sgx_status_t> {

//     }

//     fn unseal(data: &[u8]) -> Result<Vec<u8>, sgx_status_t> {

//     }
// }

fn to_sealed_log_for_slice<T: Copy + ContiguousMemory>(
    sealed_data: &SgxSealedData<[T]>,
    sealed_log: * mut u8,
    sealed_log_size: u32
) -> Option<* mut sgx_sealed_data_t> {
    unsafe {
        sealed_data
            .to_raw_sealed_data_t(
                sealed_log as * mut sgx_sealed_data_t,
                sealed_log_size
            )
    }
}

fn from_sealed_log_for_slice<'a, T: Copy + ContiguousMemory>(
    sealed_log: * mut u8,
    sealed_log_size: u32
) -> Option<SgxSealedData<'a, [T]>> {
    unsafe {
        SgxSealedData::<[T]>::from_raw_sealed_data_t(
            sealed_log as * mut sgx_sealed_data_t,
            sealed_log_size
        )
    }
}

fn seal_item(key: &[u8], value: &[u8]) -> sgx_status_t {
    let extra_data: [u8; 1] = [0x77u8; 1]; // the extra data will append to seal raw data.
    // seal data
    let key_policy = SGX_KEYPOLICY_MRENCLAVE;
    let attribute_mask = sgx_attributes_t {
        flags: TSEAL_DEFAULT_FLAGSMASK,
        xfrm: 0,
    };
    let misc_mask = TSEAL_DEFAULT_MISCMASK;
    let result = SgxSealedData::<[u8]>::seal_data_ex(key_policy, attribute_mask, misc_mask, &extra_data, &value);
    let sealed_data = match result {
        Ok(data) => data,
        Err(e) => return e,
    };

    println!("[SGX] Sealed-data additional data {:?}", sealed_data.get_additional_txt()); 
    println!("[SGX] Sealed-data encrypted data {:?}", sealed_data.get_encrypt_txt()); 
    println!("[SGX] Sealed-data payload size {:?}", sealed_data.get_payload_size()); 
    println!("[SGX] Sealed-data raw sealed data size {:?}", 
    SgxSealedData::<u8>::calc_raw_sealed_data_size(
        sealed_data.get_add_mac_txt_len(),
        sealed_data.get_encrypt_txt_len(),
    )); 

    let mut sealed_log:[u8; MAX_SEALED_LOG_BYTE] = [0u8; MAX_SEALED_LOG_BYTE];
    let sealed_log_ptr = sealed_log.as_mut_ptr() as *mut u8;
    let sealed_log_size = SgxSealedData::<u8>::calc_raw_sealed_data_size(
        sealed_data.get_add_mac_txt_len(),
        sealed_data.get_encrypt_txt_len(),
    ) as u32;
    println!("[SGX] sealed_log_size {}", sealed_log_size);
    let option = to_sealed_log_for_slice(&sealed_data, sealed_log_ptr, sealed_log_size);
    if option.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    // save to db
    let key_ptr = key.as_ptr() as *const u8;
    unsafe {
        save_to_untrusted_db(&mut sgx_status_t::SGX_SUCCESS, key_ptr, key.len() as u32,
            sealed_log_ptr, sealed_log_size as u32);
    }
    return sgx_status_t::SGX_SUCCESS;
}

fn unseal_item(key: &[u8]) -> sgx_status_t {
    // load from db
    let key_ptr = key.as_ptr() as *const u8;

    let mut sealed_view:[u8; MAX_SEALED_LOG_BYTE] = [0u8; MAX_SEALED_LOG_BYTE];
    let sealed_view_ptr = sealed_view.as_mut_ptr() as *mut u8;
    unsafe {
        load_from_untrusted_db(&mut sgx_status_t::SGX_SUCCESS, key_ptr, key.len() as u32,
            sealed_view_ptr, MAX_SEALED_LOG_BYTE as u32);
    }

    // unseal data
    let opt = from_sealed_log_for_slice::<u8>(sealed_view_ptr, MAX_SEALED_LOG_BYTE as u32);
    let sealed_data = match opt {
        Some(sealed_data) => sealed_data,
        None => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };

    let unsealed_data = match sealed_data.unseal_data() {
        Ok(unsealed_data) => unsealed_data,
        Err(e) => return e,
    };

    println!("[SGX] Unseal-data additional data {:?}", unsealed_data.get_additional_txt()); 
    println!("[SGX] Unseal-data decrypted data {:?}", unsealed_data.get_decrypt_txt()); 
    println!("[SGX] Unseal-data payload size {:?}", unsealed_data.get_payload_size()); 
    return sgx_status_t::SGX_SUCCESS;
}

/// implement say_something.
#[no_mangle]
pub extern "C" fn say_something(some_string: *const u8, some_len: usize) -> sgx_status_t {

    let str_slice = unsafe { slice::from_raw_parts(some_string, some_len) };
    let _ = io::stdout().write(str_slice);
    let key: [u8; 2] = [0x32, 0x32];

    let r = seal_item(&key, &str_slice);
    if r != sgx_status_t::SGX_SUCCESS {
        return r;
    }
    
    let r = unseal_item(&key);
    if r != sgx_status_t::SGX_SUCCESS {
        return r;
    }

    // Ocall to normal world for output
    println!("[SGX] {}", "SGX_SUCCESS");

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn verify() -> sgx_status_t {
    let key: [u8; 2] = [0x32, 0x32];
    return unseal_item(&key);
}
