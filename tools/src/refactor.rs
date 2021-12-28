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

enum Error {
    NetError(String),
    SGXError(sgx_status_t),
}

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

struct AttestationReport {
    ra_report: Vec<u8>,
    signature: Vec<u8>,
    cert_raw: Vec<u8>,
}

impl AttestationReport {
    // use for transfer to payload of cert
    pub fn into_payload(self) -> Vec<u8> {
        const separator: &[u8] = [0x7C];
        let mut payload = Vec::new();
        payload.extend(self.ra_report);
        payload.extend(separator);
        payload.extend(self.signature);
        payload.extend(separator);
        payload.extend(self.cert_raw);
        return payload;
    }

    pub fn from_payload(payload: &[u8]) -> Result<Self, Error> {
        let mut iter = payload.split(|x| *x == 0x7C);
        let attn_report_raw = iter.next().unwrap();
        let sig_raw = iter.next().unwrap();
        let sig_cert_raw = iter.next().unwrap();
        Result(Self {
            ra_report: attn_report_raw,
            signature: sig_raw,
            cert_raw: sig_cert_raw,
        })
    }
}

pub const DEV_HOSTNAME: &'static str = "api.trustedservices.intel.com";
pub const SIGRL_SUFFIX: &'static str = "/sgx/dev/attestation/v3/sigrl/";
pub const REPORT_SUFFIX: &'static str = "/sgx/dev/attestation/v3/report";

struct Net {
    pub spid: sgx_spid_t,
    pub isa_key: String,
}

// todo use http_req https://github.com/mesalock-linux/http_req-sgx/blob/5d0f7474c7/examples/request_builder_get.rs

impl Net {
    pub fn new(spid: String, isa_key: String) -> Self {
        let spid = Utils::decode_spid(spid);
        Self { spid, isa_key }
    }

    pub fn get_sigrl(&self, gid: u32) -> Result<Vec<u8>, Error> {
        let request = format!(
            "GET {}{:08x} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key: {}\r\nConnection: Close\r\n\r\n",
            SIGRL_SUFFIX, gid, DEV_HOSTNAME, self.isa_key
        );

        let resp = self.send(request)?;

        // parse http response
        return Ok(Self::parse_response_sigrl(&resp));
    }

    pub fn get_report(&self, quote: Vec<u8>) -> Result<AttestationReport, Error> {
        let encoded_quote = base64::encode(&quote[..]);
        let encoded_json = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", encoded_quote);

        let request = format!("POST {} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key:{}\r\nContent-Length:{}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                            REPORT_SUFFIX,
                            DEV_HOSTNAME,
                            ias_key,
                            encoded_json.len(),
                            encoded_json);

        let resp = self.send(request)?;

        // parse http response
        let (att_report, sig, sig_cert) = Self::parse_response_attn_report(&resp);

        return Ok(AttestationReport {
            ra_report: att_report.as_bytes().to_vec(),
            signature: sig.as_bytes().to_vec(),
            cert_raw: sig_cert.as_bytes().to_vec(),
        });
    }

    fn send(&self, request: String) -> Result<String, Error> {
        let config = self.make_ias_client_config();
        let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).unwrap();
        let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
        let mut sock = TcpStream::new(fd).unwrap();
        let mut tls = rustls::Stream::new(&mut sess, &mut sock);

        let _result = tls.write(request.as_bytes());
        let mut plaintext = Vec::new();
        match tls.read_to_end(&mut plaintext) {
            Ok(_) => (),
            Err(e) => return NetError(),
        }
        let response = String::from_utf8(plaintext.clone()).unwrap();
    }

    fn make_ias_client_config() -> rustls::ClientConfig {
        let mut config = rustls::ClientConfig::new();

        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

        config
    }

    fn parse_response_attn_report(resp: &[u8]) -> (String, String, String) {
        info!("parse_response_attn_report");
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut respp = httparse::Response::new(&mut headers);
        let result = respp.parse(resp);
        debug!("parse result {:?}", result);

        let msg: &'static str;

        match respp.code {
            Some(200) => msg = "OK Operation Successful",
            Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
            Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
            Some(500) => msg = "Internal error occurred",
            Some(503) => {
                msg = "Service is currently not able to process the request (due to
                a temporary overloading or maintenance). This is a
                temporary state – the same request can be repeated after
                some time. "
            }
            _ => {
                println!("DBG:{}", respp.code.unwrap());
                msg = "Unknown error occured"
            }
        }

        debug!("{}", msg);
        let mut len_num: u32 = 0;

        let mut sig = String::new();
        let mut cert = String::new();
        let mut attn_report = String::new();

        for i in 0..respp.headers.len() {
            let h = respp.headers[i];
            //println!("{} : {}", h.name, str::from_utf8(h.value).unwrap());
            match h.name {
                "Content-Length" => {
                    let len_str = String::from_utf8(h.value.to_vec()).unwrap();
                    len_num = len_str.parse::<u32>().unwrap();
                    println!("content length = {}", len_num);
                }
                "X-IASReport-Signature" => sig = str::from_utf8(h.value).unwrap().to_string(),
                "X-IASReport-Signing-Certificate" => cert = str::from_utf8(h.value).unwrap().to_string(),
                _ => (),
            }
        }

        // Remove %0A from cert, and only obtain the signing cert
        cert = cert.replace("%0A", "");
        cert = cert::percent_decode(cert);
        let v: Vec<&str> = cert.split("-----").collect();
        let sig_cert = v[2].to_string();

        if len_num != 0 {
            let header_len = result.unwrap().unwrap();
            let resp_body = &resp[header_len..];
            attn_report = str::from_utf8(resp_body).unwrap().to_string();
            println!("Attestation report: {}", attn_report);
        }

        // len_num == 0
        (attn_report, sig, sig_cert)
    }

    fn parse_response_sigrl(resp: &[u8]) -> Vec<u8> {
        info!("parse_response_sigrl");
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut respp = httparse::Response::new(&mut headers);
        let result = respp.parse(resp);
        debug!("parse result {:?}", result);
        debug!("parse response{:?}", respp);

        let msg: &'static str;

        match respp.code {
            Some(200) => msg = "OK Operation Successful",
            Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
            Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
            Some(500) => msg = "Internal error occurred",
            Some(503) => {
                msg = "Service is currently not able to process the request (due to
                a temporary overloading or maintenance). This is a
                temporary state – the same request can be repeated after
                some time. "
            }
            _ => msg = "Unknown error occured",
        }

        debug!("{}", msg);
        let mut len_num: u32 = 0;

        for i in 0..respp.headers.len() {
            let h = respp.headers[i];
            if h.name == "content-length" {
                let len_str = String::from_utf8(h.value.to_vec()).unwrap();
                len_num = len_str.parse::<u32>().unwrap();
                println!("content length = {}", len_num);
            }
        }

        if len_num != 0 {
            let header_len = result.unwrap().unwrap();
            let resp_body = &resp[header_len..];
            println!("Base64-encoded SigRL: {:?}", resp_body);

            return base64::decode(str::from_utf8(resp_body).unwrap()).unwrap();
        }

        // len_num == 0
        Vec::new()
    }
}

#[derive(Default)]
struct SgxCall {}

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

        return (ti, eg);
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
        let mut quote_buf: Vec<u8> = Vec::with_capacity(RET_QUOTE_BUF_LEN);
        let mut quote_len: u32 = 0;

        let (p_sigrl, sigrl_len) = if sigrl_vec.len() == 0 {
            (ptr::null(), 0)
        } else {
            (sigrl_vec.as_ptr(), sigrl_vec.len() as u32)
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

        quote_buf.trunk(quote_len);
        return Ok(qe_report, quote_buf);
    }
}

struct Attestation {}

impl Attestation {
    pub fn new() {
        Self {}
    }
    // the funciton only executed in encalve.
    pub fn create_report(
        &self,
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
        let (ti, eg) = ocall.init_quote()?;

        let gid: u32 = u32::from_le_bytes(&eg);
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
        let (qe_report, quote_buf) = ocall.get_quote(quote_type, &sigrl, &report, &net.spid, &quote_nonce)?;

        rsgx_verify_report(&qe_report)?;

        if ti.mr_enclave.m != qe_report.body.mr_enclave.m
            || ti.attributes.flags != qe_report.body.attributes.flags
            || ti.attributes.xfrm != qe_report.body.attributes.xfrm
        {
            error!("qe_report does not match current target_info!");
            return Err(SGXError(sgx_status_t::SGX_ERROR_UNEXPECTED));
        }

        self.defend_replay()?;

        let (att_report, sig, cert) = net.get_report(quote_buf)?;
        return Ok(AttestationReport {
            ra_report: att_report.as_bytes().to_vec(),
            signature: sig.as_bytes().to_vec(),
            cert_raw: sig_cert.as_bytes().to_vec(),
        });
    }

    // Check qe_report to defend against replay attack
    // The purpose of p_qe_report is for the ISV enclave to confirm the QUOTE
    // it received is not modified by the untrusted SW stack, and not a replay.
    // The implementation in QE is to generate a REPORT targeting the ISV
    // enclave (target info from p_report) , with the lower 32Bytes in
    // report.data = SHA256(p_nonce||p_quote). The ISV enclave can verify the
    // p_qe_report and report.data to confirm the QUOTE has not be modified and
    // is not a replay. It is optional.
    fn defend_replay(&quote_nonce: sgx_quote_nonce_t, &qe_report: sgx_report_t) -> Result<(), Error> {
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

    pub fn verify(report: &AttestationReport) -> Result<ReportData, Error> {
        let attn_report_raw = report.ra_report;
        // Verify attestation report
        // 1. Check timestamp is within 24H
        let attn_report: Value = serde_json::from_slice(attn_report_raw).unwrap();
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

use std::prelude::v1::*;
use std::str;
use std::time::*;
use std::untrusted::time::SystemTimeEx;

use sgx_tcrypto::*;
use sgx_types::*;

use bit_vec::BitVec;
use chrono::Duration;
use chrono::TimeZone;
use chrono::Utc as TzUtc;
use num_bigint::BigUint;
use yasna::models::ObjectIdentifier;

pub const CERTEXPIRYDAYS: i64 = 90i64;
const ISSUER: &str = "SafeMatrix";
const SUBJECT: &str = "SafeMatrix";

// TODO into bytes
pub const IAS_REPORT_CA: &[u8] = include_bytes!("../../cert/AttestationReportSigningCACert.pem");

// X. 509 certificate
struct RaX509Cert {}

impl RaX509Cert {
    pub fn generate(
        payload: &AttestationReport,
        prv_k: &sgx_ec256_private_t,
        pub_k: &sgx_ec256_public_t,
        ecc_handle: &SgxEccHandle,
    ) -> (Vec<u8>, Vec<u8>) {
        // Generate public key bytes since both DER will use it
        let mut pub_key_bytes: Vec<u8> = vec![4];
        let mut pk_gx = pub_k.gx.clone();
        pk_gx.reverse();
        let mut pk_gy = pub_k.gy.clone();
        pk_gy.reverse();
        pub_key_bytes.extend_from_slice(&pk_gx);
        pub_key_bytes.extend_from_slice(&pk_gy);

        // Generate Certificate DER
        let cert_der = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_sequence(|writer| {
                    // Certificate Version
                    writer.next().write_tagged(yasna::Tag::context(0), |writer| {
                        writer.write_i8(2);
                    });
                    // Certificate Serial Number (unused but required)
                    writer.next().write_u8(1);
                    // Signature Algorithm: ecdsa-with-SHA256
                    writer.next().write_sequence(|writer| {
                        writer
                            .next()
                            .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 4, 3, 2]));
                    });
                    // Issuer: CN=SafeMatrix (unused but required)
                    writer.next().write_sequence(|writer| {
                        writer.next().write_set(|writer| {
                            writer.next().write_sequence(|writer| {
                                writer.next().write_oid(&ObjectIdentifier::from_slice(&[2, 5, 4, 3]));
                                writer.next().write_utf8_string(&ISSUER);
                            });
                        });
                    });
                    // Validity: Issuing/Expiring Time (unused but required)
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                    let issue_ts = TzUtc.timestamp(now.as_secs() as i64, 0);
                    let expire = now + Duration::days(CERTEXPIRYDAYS).to_std().unwrap();
                    let expire_ts = TzUtc.timestamp(expire.as_secs() as i64, 0);
                    writer.next().write_sequence(|writer| {
                        writer
                            .next()
                            .write_utctime(&yasna::models::UTCTime::from_datetime(&issue_ts));
                        writer
                            .next()
                            .write_utctime(&yasna::models::UTCTime::from_datetime(&expire_ts));
                    });
                    // Subject: CN=SafeMatrix (unused but required)
                    writer.next().write_sequence(|writer| {
                        writer.next().write_set(|writer| {
                            writer.next().write_sequence(|writer| {
                                writer.next().write_oid(&ObjectIdentifier::from_slice(&[2, 5, 4, 3]));
                                writer.next().write_utf8_string(&SUBJECT);
                            });
                        });
                    });
                    writer.next().write_sequence(|writer| {
                        // Public Key Algorithm
                        writer.next().write_sequence(|writer| {
                            // id-ecPublicKey
                            writer
                                .next()
                                .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 2, 1]));
                            // prime256v1
                            writer
                                .next()
                                .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 3, 1, 7]));
                        });
                        // Public Key
                        writer.next().write_bitvec(&BitVec::from_bytes(&pub_key_bytes));
                    });
                    // Certificate V3 Extension
                    writer.next().write_tagged(yasna::Tag::context(3), |writer| {
                        writer.write_sequence(|writer| {
                            writer.next().write_sequence(|writer| {
                                writer
                                    .next()
                                    .write_oid(&ObjectIdentifier::from_slice(&[2, 16, 840, 1, 113730, 1, 13]));
                                writer.next().write_bytes(&payload.into_bytes());
                            });
                        });
                    });
                });
                // Signature Algorithm: ecdsa-with-SHA256
                writer.next().write_sequence(|writer| {
                    writer
                        .next()
                        .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 4, 3, 2]));
                });
                // Signature
                let sig = {
                    let tbs = &writer.buf[4..];
                    ecc_handle.ecdsa_sign_slice(tbs, &prv_k).unwrap()
                };
                let sig_der = yasna::construct_der(|writer| {
                    writer.write_sequence(|writer| {
                        let mut sig_x = sig.x.clone();
                        sig_x.reverse();
                        let mut sig_y = sig.y.clone();
                        sig_y.reverse();
                        writer.next().write_biguint(&BigUint::from_slice(&sig_x));
                        writer.next().write_biguint(&BigUint::from_slice(&sig_y));
                    });
                });
                writer.next().write_bitvec(&BitVec::from_bytes(&sig_der));
            });
        });

        // Generate Private Key DER
        let key_der = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_u8(0);
                writer.next().write_sequence(|writer| {
                    writer
                        .next()
                        .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 2, 1]));
                    writer
                        .next()
                        .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 3, 1, 7]));
                });
                let inner_key_der = yasna::construct_der(|writer| {
                    writer.write_sequence(|writer| {
                        writer.next().write_u8(1);
                        let mut prv_k_r = prv_k.r.clone();
                        prv_k_r.reverse();
                        writer.next().write_bytes(&prv_k_r);
                        writer.next().write_tagged(yasna::Tag::context(1), |writer| {
                            writer.write_bitvec(&BitVec::from_bytes(&pub_key_bytes));
                        });
                    });
                });
                writer.next().write_bytes(&inner_key_der);
            });
        });
        (key_der, cert_der)
    }

    pub fn verify(cert: &[u8]) -> Result<ReportData, Error> {
        // Before we reach here, Webpki already verifed the cert is properly signed
        let payload = Self::extract_payload(&cert)?;
        // Extract each field
        let report = AttestationReport::from_payload(payload)?;

        let sig = base64::decode(&sig_raw).unwrap();
        let sig_cert_dec = base64::decode_config(&sig_cert_raw, base64::MIME).unwrap();
        let sig_cert = webpki::EndEntityCert::from(&sig_cert_dec).expect("Bad DER");

        // Load Intel CA
        let mut ias_ca_stripped = IAS_REPORT_CA.to_vec();
        ias_ca_stripped.retain(|&x| x != 0x0d && x != 0x0a);
        let head_len = "-----BEGIN CERTIFICATE-----".len();
        let tail_len = "-----END CERTIFICATE-----".len();
        let full_len = ias_ca_stripped.len();
        let ias_ca_core: &[u8] = &ias_ca_stripped[head_len..full_len - tail_len];
        let ias_cert_dec = base64::decode_config(ias_ca_core, base64::MIME).unwrap();

        let mut ca_reader = BufReader::new(&IAS_REPORT_CA[..]);

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_pem_file(&mut ca_reader).expect("Failed to add CA");

        let trust_anchors: Vec<webpki::TrustAnchor> =
            root_store.roots.iter().map(|cert| cert.to_trust_anchor()).collect();

        let mut chain: Vec<&[u8]> = Vec::new();
        chain.push(&ias_cert_dec);

        let now_func = webpki::Time::try_from(SystemTime::now());

        match sig_cert.verify_is_valid_tls_server_cert(
            SUPPORTED_SIG_ALGS,
            &webpki::TLSServerTrustAnchors(&trust_anchors),
            &chain,
            now_func.unwrap(),
        ) {
            Ok(_) => println!("Cert is good"),
            Err(e) => println!("Cert verification error {:?}", e),
        }

        let report_data = Attestation::verify(report)?;
        return Ok(report_data);
    }

    pub(crate) fn extract_payload(cert_der: &[u8]) -> Result<Vec<u8>, Error> {
        // Search for Public Key prime256v1 OID
        let prime256v1_oid = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
        let mut offset = cert_der
            .windows(prime256v1_oid.len())
            .position(|window| window == prime256v1_oid)
            .unwrap();
        offset += 11; // 10 + TAG (0x03)

        // Obtain Public Key length
        let mut len = cert_der[offset] as usize;
        if len > 0x80 {
            len = (cert_der[offset + 1] as usize) * 0x100 + (cert_der[offset + 2] as usize);
            offset += 2;
        }

        // Obtain Public Key
        offset += 1;
        let pub_k = cert_der[offset + 2..offset + len].to_vec(); // skip "00 04"

        // Search for Netscape Comment OID
        let ns_cmt_oid = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x01, 0x0D];
        let mut offset = cert_der
            .windows(ns_cmt_oid.len())
            .position(|window| window == ns_cmt_oid)
            .unwrap();
        offset += 12; // 11 + TAG (0x04)

        // Obtain Netscape Comment length
        let mut len = cert_der[offset] as usize;
        if len > 0x80 {
            len = (cert_der[offset + 1] as usize) * 0x100 + (cert_der[offset + 2] as usize);
            offset += 2;
        }

        // Obtain Netscape Comment
        offset += 1;
        let payload = cert_der[offset..offset + len].to_vec();

        Ok(payload);
    }
}

pub fn gen_ecc_cert_with_sign_type(sign_type: sgx_quote_sign_type_t) -> Result<(Vec<u8>, Vec<u8>), Error> {
    // Generate Keypair
    let ecc_handle = SgxEccHandle::new();
    let _result = ecc_handle.open();
    let (prv_k, pub_k) = ecc_handle.create_key_pair().unwrap();

    let ocall = SgxCall;
    let net = Net::new();
    let report = Attestation::new().create_report(&net, &ocall, sign_type)?;

    let (key_der, cert_der) = match RaX509Cert::generate(&report, &prv_k, &pub_k, &ecc_handle)?;
    let _result = ecc_handle.close();
    Ok((key_der, cert_der))
}

struct Utils {}

impl Utils {
    fn decode_spid() -> sgx_spid_t {
        unimplemented!();
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn example() {
        // load files
        let spid: String = "22aa549a2d5e47a2933a753c1cae947c";
        let key: String = "22aa549a2d5e47a2933a753c1cae947c";
        // init net
        let net = Net::new(spid, key);

        // init ocall
        let ocall = SgxCall::default();
        let sign_type = sgx_quote_sign_type_t::SGX_LINKABLE_SIGNATURE;
        let report = Attestation::new().create_report(&net, &ocall, sign_type).unwrap();
        assert!(Attestation::verify(&report));

        let cert = RaX509Cert::generate(&report).unwrap();
        assert!(RaX509Cert::verify(&cert));
    }
}
