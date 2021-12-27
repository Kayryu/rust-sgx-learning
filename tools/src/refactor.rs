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
    raw_cert: Vec<u8>
}

pub const DEV_HOSTNAME: &'static str = "api.trustedservices.intel.com";
pub const SIGRL_SUFFIX: &'static str = "/sgx/dev/attestation/v3/sigrl/";
pub const REPORT_SUFFIX: &'static str = "/sgx/dev/attestation/v3/report";

struct Net {
    pub spid: sgx_spid_t,
    pub isa_key: String,
}


impl Net {
    pub fn new(spid: String, isa_key: String) -> Self {
        let spid = Utils::decode_spid(spid);
        Self {
            spid,
            isa_key
        }
    }
    
    pub fn get_sigrl(&self, gid: u32) -> Vec<u8> {
        let request = format!(
            "GET {}{:08x} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key: {}\r\nConnection: Close\r\n\r\n",
            SIGRL_SUFFIX, gid, DEV_HOSTNAME, self.isa_key
        );

        let resp = self.send(request).unwrap();

        // parse http response
    }

    pub fn get_report(&self, quote: Vec<u8>) -> AttestationReport {
        let encoded_quote = base64::encode(&quote[..]);
        let encoded_json = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", encoded_quote);

        let request = format!("POST {} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key:{}\r\nContent-Length:{}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                            REPORT_SUFFIX,
                            DEV_HOSTNAME,
                            ias_key,
                            encoded_json.len(),
                            encoded_json);

        let resp = self.send(request).unwrap();

        // parse http response

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
            Err(e) => {
                return NetError()
            }
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
}

#[derive(Default)]
struct OutCall {

}

impl OutCall {
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

    fn get_quote(quote_type: sgx_quote_sign_type_t, sigrl:&[u8], report: &sgx_report_t, spid:&sgx_spid_t, quote_nonce: &sgx_quote_nonce_t) -> Result<(sgx_report_t, Vec<u8>), Error> {
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

struct Attestation {
    
}

fn as_u32_le(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 0) + ((array[1] as u32) << 8) + ((array[2] as u32) << 16) + ((array[3] as u32) << 24)
}

impl Attestation {
    // the funciton only executed in encalve.
    pub fn create_report(&self, net: &Net, ocall: &OutCall, addition: &[u8], quote_type: sgx_quote_sign_type_t) -> Result<AttestationReport, Error> {
        // Workflow:
        // (1) ocall to get the target_info structure (ti) and epid group id (eg)
        // (1.5) get sigrl
        // (2) call sgx_create_report with ti+data, produce an sgx_report_t
        // (3) ocall to sgx_get_quote to generate (*mut sgx-quote_t, uint32_t)
        let (ti, eg) = ocall.init_quote()?;

        let gid: u32 = as_u32_le(&eg);
        let sigrl: Vec<u8> = net.get_sigrl(gid)?;

        // Fill data into report_data
        let mut report_data: sgx_report_data_t = sgx_report_data_t::default();
        report_data.d[..addition.len()].clone_from_slice(addition);
        let report = match rsgx_create_report(&ti, &report_data).map_err(|e| {
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

        let (attn_report, sig, cert) = net.get_report(quote_buf).unwrap();
        return Ok(AttestationReport{

        })
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

    pub fn verify(report: &AttestationReport) -> bool {
        unimplemented!()
    }
}

// X. 509 certificate
struct SelfCert {
    
}

impl SelfCert {
    pub fn generate(report: &AttestationReport) -> Vec<u8> {
        unimplemented!()
    }

    pub fn verify(cert: &Vec<u8>) -> bool {

    }
}


struct Utils {
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
        let ocall = OutCall::default();


        let report = Attestation::create_report(&net, &ocall).unwrap();
        assert!(Attestation::verify(&report));

        let cert = SelfCert::generate(&report).unwrap()
        assert!(SelfCert::verify(&cert));
    }
}