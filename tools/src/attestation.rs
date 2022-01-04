use std::prelude::v1::*;
use std::ptr;
use chrono::DateTime;
use serde_json::Value;
use itertools::Itertools;
use log::{info, debug, error, trace};
use std::time::{SystemTime, UNIX_EPOCH};
use rand::RngCore as _;
use std::untrusted::time::SystemTimeEx;
use std::io::BufReader;
use core::convert::TryInto;

use sgx_types::*;
use sgx_tse::{rsgx_verify_report, rsgx_create_report};
use sgx_tcrypto::rsgx_sha256_slice;

use crate::traits::AttestationReportVerifier;
use crate::types::{AttestationReport, EnclaveFeilds, ReportData};
use crate::error::Error;
use crate::ias::Net;

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

    fn get_ias_socket() -> Result<i32, Error> {
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
        let mut quote_buf: [u8; RET_QUOTE_BUF_LEN as usize] = [0; RET_QUOTE_BUF_LEN as usize];
        let mut quote_len: u32 = 0;

        let (p_sigrl, sigrl_len) = if sigrl.len() == 0 {
            (ptr::null(), 0)
        } else {
            (sigrl.as_ptr(), sigrl.len() as u32)
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
            return Err(Error::SGXError(result));
        }

        if rt != sgx_status_t::SGX_SUCCESS {
            return Err(Error::SGXError(rt));
        }

        let mut quote = quote_buf.to_vec();
        quote.truncate(quote_len as usize);
        return Ok((qe_report, quote));
    }
}

pub const IAS_QUOTE_STATUS_LEVEL_1: &[&str] = &["OK"];
pub const IAS_QUOTE_STATUS_LEVEL_2: &[&str] = &["SW_HARDENING_NEEDED"];
pub const IAS_QUOTE_STATUS_LEVEL_3: &[&str] = &[
	"CONFIGURATION_NEEDED",
	"CONFIGURATION_AND_SW_HARDENING_NEEDED",
];
// LEVEL 4 is LEVEL 3 with advisors which not included in whitelist
pub const IAS_QUOTE_STATUS_LEVEL_5: &[&str] = &["GROUP_OUT_OF_DATE"];

#[derive(Default)]
pub struct Attestation {}

impl Attestation {
    // TODO, with rand
    // the funciton only executed in encalve.
    pub fn create_report(
        net: &Net,
        addition: &[u8],
        quote_type: sgx_quote_sign_type_t,
    ) -> Result<AttestationReport, Error> {
        // Workflow:
        // (1) ocall to get the target_info structure (ti) and epid group id (eg)
        // (1.5) get sigrl
        // (2) call sgx_create_report with ti+data, produce an sgx_report_t
        // (3) ocall to sgx_get_quote to generate (*mut sgx-quote_t, uint32_t)
        let (ti, eg) = SgxCall::init_quote()?;

        let gid: u32 = u32::from_le_bytes(eg);
        let fd = SgxCall::get_ias_socket()?;
        let sigrl: Vec<u8> = net.get_sigrl(fd, gid)?;

        // Fill data into report_data
        let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
        report_data.d[..addition.len()].clone_from_slice(addition);
        let report = rsgx_create_report(&ti, &report_data).map_err(|e| {
            error!("Report creation failed {}", e);
            return Error::SGXError(e);
        })?;

        // generate rand. WIP: Even if the public key and random number are fixed, their quote is still different.
        let mut quote_nonce = sgx_quote_nonce_t { rand: [0; 16] };
        let mut os_rng = rand::thread_rng();
        os_rng.fill_bytes(&mut quote_nonce.rand);
        let (qe_report, quote_buf) = SgxCall::get_quote(quote_type, &sigrl, &report, &net.spid, &quote_nonce)?;

        rsgx_verify_report(&qe_report).map_err(|e| Error::SGXError(e))?;

        if ti.mr_enclave.m != qe_report.body.mr_enclave.m
            || ti.attributes.flags != qe_report.body.attributes.flags
            || ti.attributes.xfrm != qe_report.body.attributes.xfrm
        {
            error!("qe_report does not match current target_info!");
            return Err(Error::SGXError(sgx_status_t::SGX_ERROR_UNEXPECTED));
        }

        Self::defend_replay(&quote_nonce, &quote_buf, &qe_report)?;

        let fd = SgxCall::get_ias_socket()?;
        let report = net.get_report(fd, quote_buf)?;
        return Ok(report);
    }

    // Check qe_report to defend against replay attack
    // The purpose of p_qe_report is for the ISV enclave to confirm the QUOTE
    // it received is not modified by the untrusted SW stack, and not a replay.
    // The implementation in QE is to generate a REPORT targeting the ISV
    // enclave (target info from p_report) , with the lower 32Bytes in
    // report.data = SHA256(p_nonce||p_quote). The ISV enclave can verify the
    // p_qe_report and report.data to confirm the QUOTE has not be modified and
    // is not a replay. It is optional.
    fn defend_replay(quote_nonce: &sgx_quote_nonce_t, quote_buf:&[u8], qe_report: &sgx_report_t) -> Result<(), Error> {
        let mut rhs_vec: Vec<u8> = quote_nonce.rand.to_vec();
        rhs_vec.extend(quote_buf);
        let rhs_hash = rsgx_sha256_slice(&rhs_vec[..]).map_err(|e| {
            error!("Sha256 error: {}", e);
            return Error::SGXError(e);
        })?;

        let lhs_hash = &qe_report.body.report_data.d[..32];
        
        debug!("rhs hash = {:02X}", rhs_hash.iter().format(""));
        debug!("report hs= {:02X}", lhs_hash.iter().format(""));

        if rhs_hash != lhs_hash {
            error!("Quote is tampered!");
            return Err(Error::SGXError(sgx_status_t::SGX_ERROR_UNEXPECTED));
        }
        Ok(())
    }

    pub fn verify(report: &AttestationReport, now: u64) -> Result<EnclaveFeilds, Error> {
        // Verify attestation report
        let report_data: ReportData = serde_json::from_slice(&report.ra_report).map_err(|_| Error::InvalidReport)?;

        trace!("attn_report: {:?}", report_data);

        let raw_report_timestamp = report_data.timestamp + "+0000";
        let report_timestamp = chrono::DateTime::parse_from_rfc3339(&raw_report_timestamp)
            .or(Err(Error::InvalidReportTimestamp))?
            .timestamp();
        if (now as i64 - report_timestamp) >= 7200 {
            return Err(Error::OutdatedReport);
        }
    
        let quote = base64::decode(&report_data.isv_enclave_quote_body).map_err(|_| Error::InvalidReportBody)?;
        trace!("Quote = {:?}", quote);
        
        if quote.len() < 436 {
            return Err(Error::InvalidReportBody);
        }

        let sgx_quote: sgx_quote_t = unsafe { ptr::read(quote.as_ptr() as *const _) };

        let mut enclave_field = EnclaveFeilds::default(); 
        enclave_field.version = sgx_quote.version;
        enclave_field.sign_type = sgx_quote.sign_type;
        enclave_field.mr_enclave = sgx_quote.report_body.mr_enclave.m.try_into().map_err(|_| Error::InvalidReportField)?;
        enclave_field.mr_signer = sgx_quote.report_body.mr_signer.m.try_into().map_err(|_| Error::InvalidReportField)?;
        enclave_field.report_data = sgx_quote.report_body.report_data.d.try_into().map_err(|_| Error::InvalidReportField)?;

        return Ok(enclave_field);
    }
}

impl AttestationReportVerifier for Attestation {
    fn verify(report: &AttestationReport, now: u64) -> Result<EnclaveFeilds, Error> {
        Attestation::verify(report, now)
    }
}

