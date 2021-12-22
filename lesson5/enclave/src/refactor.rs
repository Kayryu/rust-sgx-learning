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
*/


enum Error {
    NetError,
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


struct Net {
    spid: sgx_spid_t,
    key: String,
}

struct Attestation {
    net: Net
}

impl Attestation {
    fn create_report() -> Result<AttestationReport, Error> {
        unimplemented!()
    }

    fn verify_report(report: &AttestationReport) -> bool {
        unimplemented!()
    }
}



// X. 509 certificate
struct SelfCert {
    
}

impl SelfCert {
    pub fn generate() -> Vec<u8> {
        unimplemented!()
    }

    pub fn verify(cert: &Vec<u8>) -> bool {

    }
}