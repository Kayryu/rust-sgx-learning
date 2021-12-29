use crate::error::Error;
use std::prelude::v1::*;
use chrono::DateTime;
use serde_json::Value;
use itertools::Itertools;

use crate::types::AttestationReport;

use sgx_types::*;


extern "C" {
    pub fn ocall_sgx_init_quote(
        ret_val: *mut sgx_status_t,
        ret_ti: *mut sgx_target_info_t,
        ret_gid: *mut sgx_epid_group_id_t,
    ) -> sgx_status_t;

    pub fn ocall_get_ias_socket(ret_val: *mut sgx_status_t, ret_fd: *mut i32) -> sgx_status_t;

    pub fn ocall_get_quote(
        ret_val: *mut sgx_status_t,
        p_sigrl: *const u8,
        sigrl_len: u32,
        p_report: *const sgx_report_t,
        quote_type: sgx_quote_sign_type_t,
        p_spid: *const sgx_spid_t,
        p_nonce: *const sgx_quote_nonce_t,
        p_qe_report: *mut sgx_report_t,
        p_quote: *mut u8,
        maxlen: u32,
        p_quote_len: *mut u32,
    ) -> sgx_status_t;
}

#[derive(Default)]
pub(crate) struct SgxCall {}

impl SgxCall {
    fn init_quote() -> Result<(sgx_target_info_t, sgx_epid_group_id_t), Error> {
        let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
        let mut ti: sgx_target_info_t = sgx_target_info_t::default();
        let mut eg: sgx_epid_group_id_t = sgx_epid_group_id_t::default();

        let res = unsafe {
            ocall_sgx_init_quote(
                &mut rt as *mut sgx_status_t,
                &mut ti as *mut sgx_target_info_t,
                &mut eg as *mut sgx_epid_group_id_t,
            )
        };

        if res != sgx_status_t::SGX_SUCCESS {
            return Err(Error::SGXError(res));
        }

        if rt != sgx_status_t::SGX_SUCCESS {
            return Err(Error::SGXError(rt));
        }

        return Ok((ti, eg));
    }

    fn ias_socket() -> Result<i32, Error> {
        let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
        let mut ias_sock: i32 = 0;

        let res = unsafe { ocall_get_ias_socket(&mut rt as *mut sgx_status_t, &mut ias_sock as *mut i32) };

        if res != sgx_status_t::SGX_SUCCESS {
            return Err(Error::SGXError(res));
        }

        if rt != sgx_status_t::SGX_SUCCESS {
            return Err(Error::SGXError(rt));
        }
        return Ok(ias_sock)
    }

    fn get_quote(
        quote_type: sgx_quote_sign_type_t,
        sigrl: &[u8],
        report: &sgx_report_t,
        spid: &sgx_spid_t,
        quote_nonce: &sgx_quote_nonce_t,
    ) -> Result<(sgx_report_t, Vec<u8>), Error> {
        let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;

        const RET_QUOTE_BUF_LEN: u32 = 2048;
        let mut qe_report = sgx_report_t::default();
        let mut quote_buf: Vec<u8> = Vec::with_capacity(RET_QUOTE_BUF_LEN as usize);
        let mut quote_len: u32 = 0;

        let (p_sigrl, sigrl_len) = if sigrl.len() == 0 {
            (ptr::null(), 0)
        } else {
            (sigrl_vec.as_ptr(), sigrl.len() as u32)
        };
        // (3) Generate the quote
        // Args:
        //       1. sigrl: ptr + len
        //       2. report: ptr 432bytes
        //       3. linkable: u32, unlinkable=0, linkable=1
        //       4. spid: sgx_spid_t ptr 16bytes
        //       5. sgx_quote_nonce_t ptr 16bytes
        //       6. p_sig_rl + sigrl size ( same to sigrl)
        //       7. [out]p_qe_report need further check
        //       8. [out]p_quote
        //       9. quote_size
        let result = unsafe {
            ocall_get_quote(
                &mut rt as *mut sgx_status_t,
                p_sigrl,
                sigrl_len,
                report as *const sgx_report_t,
                quote_type,
                spid as *const sgx_spid_t,
                quote_nonce as *const sgx_quote_nonce_t,
                &mut qe_report as *mut sgx_report_t,
                quote_buf.as_mut_ptr(),
                RET_QUOTE_BUF_LEN,
                &mut quote_len as *mut u32,
            )
        };

        if result != sgx_status_t::SGX_SUCCESS {
            error!("ocall_get_quote result={}", result);
            return Err(Error::SGXError(result));
        }

        if rt != sgx_status_t::SGX_SUCCESS {
            error!("ocall_get_quote rt={}", rt);
            return Err(Error::SGXError(rt));
        }

        quote_buf.truncate(quote_len as usize);
        return Ok((qe_report, quote_buf));
    }
}

#[derive(Default)]
pub struct Attestation {}

impl Attestation {
    // the funciton only executed in encalve.
    pub fn create_report(
        net: &Net,
        ocall: &SgxCall,
        addition: &[u8],
        quote_type: sgx_quote_sign_type_t,
    ) -> Result<AttestationReport, Error> {
        // Workflow:
        // (1) ocall to get the target_info structure (ti) and epid group id (eg)
        // (1.5) get sigrl
        // (2) call sgx_create_report with ti+data, produce an sgx_report_t
        // (3) ocall to sgx_get_quote to generate (*mut sgx-quote_t, uint32_t)
        let (ti, eg) = ocall::init_quote()?;

        let gid: u32 = u32::from_le_bytes(eg);
        let sigrl: Vec<u8> = net.get_sigrl(gid)?;

        // Fill data into report_data
        let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
        report_data.d[..addition.len()].clone_from_slice(addition);
        let report = rsgx_create_report(&ti, &report_data).map_err(|e| {
            error!("Report creation failed {}", e);
            return Err(Error::SGXError(e));
        })?;

        // generate rand
        let mut quote_nonce = sgx_quote_nonce_t { rand: [0; 16] };
        let mut os_rng = rand::thread_rng();
        os_rng.fill_bytes(&mut quote_nonce.rand);
        let (qe_report, quote_buf) = ocall::get_quote(quote_type, &sigrl, &report, &net.spid, &quote_nonce)?;

        rsgx_verify_report(&qe_report)?;

        if ti.mr_enclave.m != qe_report.body.mr_enclave.m
            || ti.attributes.flags != qe_report.body.attributes.flags
            || ti.attributes.xfrm != qe_report.body.attributes.xfrm
        {
            error!("qe_report does not match current target_info!");
            return Err(Error::SGXError(sgx_status_t::SGX_ERROR_UNEXPECTED));
        }

        Self::defend_replay(&quote_nonce, &qe_report)?;

        let report = net.get_report(quote_buf)?;
        return report;
    }

    // Check qe_report to defend against replay attack
    // The purpose of p_qe_report is for the ISV enclave to confirm the QUOTE
    // it received is not modified by the untrusted SW stack, and not a replay.
    // The implementation in QE is to generate a REPORT targeting the ISV
    // enclave (target info from p_report) , with the lower 32Bytes in
    // report.data = SHA256(p_nonce||p_quote). The ISV enclave can verify the
    // p_qe_report and report.data to confirm the QUOTE has not be modified and
    // is not a replay. It is optional.
    fn defend_replay(quote_nonce: &sgx_quote_nonce_t, qe_report: &sgx_report_t) -> Result<(), Error> {
        let mut rhs_vec: Vec<u8> = quote_nonce.rand.to_vec();
        rhs_vec.extend(&quote_buf);
        let rhs_hash = rsgx_sha256_slice(&rhs_vec[..]).map_err(|e| {
            error!("Sha256 error: {}", e);
            return Err(Error::SGXError(e));
        })?;

        let lhs_hash = &qe_report.body.report_data.d[..32];

        if rhs_hash != lhs_hash {
            error!("Quote is tampered!");
            return Err(Error::SGXError(sgx_status_t::SGX_ERROR_UNEXPECTED));
        }
        Ok(())
    }

    pub fn verify(report: &AttestationReport, pub_k: sgx_ec256_public_t) -> Result<ReportData, Error> {
        let attn_report_raw = report.ra_report;
        // Verify attestation report
        let attn_report: Value = serde_json::from_slice(&attn_report_raw).map_err(|_| Error::InvalidReport)?;

        if let Value::String(time) = &attn_report["timestamp"] {
            let time_fixed = time.clone() + "+0000";
            let ts = DateTime::parse_from_str(&time_fixed, "%Y-%m-%dT%H:%M:%S%.f%z")
                .unwrap()
                .timestamp();
            let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64;
            println!("Time diff = {}", now - ts);
        } else {
            println!("Failed to fetch timestamp from attestation report");
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        }

        // 2. Verify quote status (mandatory field)
        if let Value::String(quote_status) = &attn_report["isvEnclaveQuoteStatus"] {
            println!("isvEnclaveQuoteStatus = {}", quote_status);
            match quote_status.as_ref() {
                "OK" => (),
                "GROUP_OUT_OF_DATE" | "GROUP_REVOKED" | "CONFIGURATION_NEEDED" => {
                    // Verify platformInfoBlob for further info if status not OK
                    if let Value::String(pib) = &attn_report["platformInfoBlob"] {
                        let got_pib = platform_info::from_str(&pib);
                        println!("{:?}", got_pib);
                    } else {
                        println!("Failed to fetch platformInfoBlob from attestation report");
                        return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
                    }
                }
                _ => return Err(sgx_status_t::SGX_ERROR_UNEXPECTED),
            }
        } else {
            println!("Failed to fetch isvEnclaveQuoteStatus from attestation report");
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        }

        // 3. Verify quote body
        if let Value::String(quote_raw) = &attn_report["isvEnclaveQuoteBody"] {
            let quote = base64::decode(&quote_raw).unwrap();
            println!("Quote = {:?}", quote);
            // TODO: lack security check here
            let sgx_quote: sgx_quote_t = unsafe { ptr::read(quote.as_ptr() as *const _) };

            // Borrow of packed field is unsafe in future Rust releases
            // ATTENTION
            // DO SECURITY CHECK ON DEMAND
            // DO SECURITY CHECK ON DEMAND
            // DO SECURITY CHECK ON DEMAND
            unsafe {
                println!("sgx quote version = {}", sgx_quote.version);
                println!("sgx quote signature type = {}", sgx_quote.sign_type);
                println!(
                    "sgx quote report_data = {:02x}",
                    sgx_quote.report_body.report_data.d.iter().format("")
                );
                println!(
                    "sgx quote mr_enclave = {:02x}",
                    sgx_quote.report_body.mr_enclave.m.iter().format("")
                );
                println!(
                    "sgx quote mr_signer = {:02x}",
                    sgx_quote.report_body.mr_signer.m.iter().format("")
                );
            }
            println!("Anticipated public key = {:02x}", pub_k.iter().format(""));
            if sgx_quote.report_body.report_data.d.to_vec() == pub_k.to_vec() {
                println!("ue RA done!");
            }
        } else {
            println!("Failed to fetch isvEnclaveQuoteBody from attestation report");
            return Err(sgx_status_t::SGX_ERROR_UNEXPECTED);
        }

        return Ok(());
    }
}

