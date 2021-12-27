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
    SGXERROR(sgx_status_t),
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
    spid: sgx_spid_t,
    key: String,
}


impl Net {
    pub fn new(spid: String, key: String) -> Self {
        let spid = Utils::decode_spid(spid);
        Self {
            spid,
            key
        }
    }
    
    pub fn get_sigrl(&self, gid: u32) -> Vec<u8> {
        let request = format!(
            "GET {}{:08x} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key: {}\r\nConnection: Close\r\n\r\n",
            SIGRL_SUFFIX, gid, DEV_HOSTNAME, self.key
        );

        let self.send(request).unwrap();
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

        self.send(request).unwrap();

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
struct TrustCall {

}

impl TrustCall {
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

        debug!("eg = {:?}", eg);

        if res != sgx_status_t::SGX_SUCCESS {
            return Err(Error::SGXERROR(res));
        }

        if rt != sgx_status_t::SGX_SUCCESS {
            return Err(Error::SGXERROR(rt));
        }

        return (ti, eg);
    }

    fn ias_socket() -> Result<i32, Error> {
        let mut rt: sgx_status_t = sgx_status_t::SGX_ERROR_UNEXPECTED;
        let mut ias_sock: i32 = 0;

        let res = unsafe { ocall_get_ias_socket(&mut rt as *mut sgx_status_t, &mut ias_sock as *mut i32) };

        if res != sgx_status_t::SGX_SUCCESS {
            return Err(Error::SGXERROR(res));
        }

        if rt != sgx_status_t::SGX_SUCCESS {
            return Err(Error::SGXERROR(rt));
        }
    }

    fn get_quote() -> Result<>
}

struct Attestation {
}

impl Attestation {
    fn create_report() -> Result<AttestationReport, Error> {
        unimplemented!()
    }

    fn verify(report: &AttestationReport) -> bool {
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
        let ocall = TrustCall::default();


        let report = Attestation::create_report(&net, &ocall).unwrap();
        assert!(Attestation::verify(&report));

        let cert = SelfCert::generate(&report).unwrap()
        assert!(SelfCert::verify(&cert));
    }
}