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

extern crate sgx_urts;
extern crate sgx_types;

use sgx_types::*;
use sgx_urts::SgxEnclave;
use std::ptr::copy_nonoverlapping;
use lazy_static::lazy_static;
use std::sync::Mutex;
use std::collections::HashMap;
use std::slice;

type Bytes = Vec<u8>;

static ENCLAVE_FILE: &'static str = "enclave.signed.so";

lazy_static! {
    pub static ref DATABASE: Mutex<HashMap<Bytes, Bytes>> = {
        let db = HashMap::new();
        Mutex::new(db)
    };
}

#[no_mangle]
pub extern "C" fn save_to_untrusted_db(
    key_pointer: *const u8,
    key_size: u32,
    value_pointer: *const u8,
    value_size: u32,
) -> sgx_status_t {
    let db_data = unsafe {
        slice::from_raw_parts(value_pointer, value_size as usize)
    };
    println!("[App] saving sealed data into database via OCALL...");
    let db_key = unsafe {
        slice::from_raw_parts(key_pointer, key_size as usize)
    };

    DATABASE
        .lock()
        .unwrap()
        .insert(
            db_key.to_vec(),
            db_data.to_vec(),
        );

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn load_from_untrusted_db(
    key_pointer: *const u8,
    key_size: u32,
    value_pointer: *mut u8,
    value_size: u32,
) -> sgx_status_t {
    println!("[App] get data from database via OCALL...");
    let db_key = unsafe {
        slice::from_raw_parts(key_pointer, key_size as usize)
    };

    let mut data = DATABASE
        .lock()
        .unwrap()
        [db_key]
        .clone();

    let data_length = data.len() as u32;
    let mut final_bytes_to_copy: Vec<u8> = data_length
        .to_le_bytes()
        .to_vec();

    final_bytes_to_copy.append(&mut data);

    unsafe {
        if value_size < final_bytes_to_copy.len() as u32 {
            return sgx_status_t::SGX_ERROR_OUT_OF_MEMORY;
        }
        copy_nonoverlapping(
            &final_bytes_to_copy[0] as *const u8,
            value_pointer,
            final_bytes_to_copy.len()
        )
    }
    sgx_status_t::SGX_SUCCESS
}


/// Define call apis
extern {
    fn say_something(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                     some_string: *const u8, len: usize) -> sgx_status_t;
}

fn init_enclave() -> SgxResult<SgxEnclave> {
    let mut launch_token: sgx_launch_token_t = [0; 1024];
    let mut launch_token_updated: i32 = 0;
    // call sgx_create_enclave to initialize an enclave instance
    // Debug Support: set 2nd parameter to 1
    let debug = 1;
    let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    SgxEnclave::create(ENCLAVE_FILE,
                       debug,
                       &mut launch_token,
                       &mut launch_token_updated,
                       &mut misc_attr)
}

fn main() {
    let enclave = match init_enclave() {
        Ok(r) => {
            println!("[+] Init Enclave Successful {}!", r.geteid());
            r
        },
        Err(x) => {
            println!("[-] Init Enclave Failed {}!", x.as_str());
            return;
        },
    };

    let input_string = String::from("Sealing SGX Data into an Untrusted Database!\n");
    let mut retval = sgx_status_t::SGX_SUCCESS;

    let result = unsafe {
        say_something(enclave.geteid(),
                      &mut retval,
                      input_string.as_ptr() as * const u8,
                      input_string.len())
    };
    match result {
        sgx_status_t::SGX_SUCCESS => {},
        _ => {
            println!("[-] ECALL Enclave Failed {}!", result.as_str());
            return;
        }
    }

    println!("{:?}", DATABASE.lock());
    println!("[+] say_something success...");
    enclave.destroy();
}
