use sgx_types::sgx_status_t;

pub enum Error {
    NetError(String),
    SGXError(sgx_status_t),
}