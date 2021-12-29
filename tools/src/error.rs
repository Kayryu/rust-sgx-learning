use sgx_types::sgx_status_t;

#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    NetError(String),
    SGXError(sgx_status_t),
    InvalidSelfSignedCert,
    InvalidIASSignature,
    InvalidIASSigningCert,
    InvalidReport,
    InvalidReportPayload,
}
