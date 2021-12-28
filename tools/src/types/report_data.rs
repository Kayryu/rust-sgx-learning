// from https://www.intel.com/content/dam/develop/public/us/en/documents/sgx-attestation-api-spec.pdf

#[derive(Default, Debug, Eq, PartialEq)]
pub struct ReportData {
    /// Representation of unique identifier of the Attestation Verification Report.
    ///
    /// This field is mandatory.
    id: String,
    timestamp: String,
    version: u32,
    isv_enclave_quote_status: String,
    isv_enclave_quote_body: String,
    revocation_reason: u32,
    pse_manifest_status: String,
    pse_manifest_hash: String,
    platform_info_blob: String,
    nonce: String,
    epid_pseudonym: String,
    advisory_url: String,
    advisory_ids: Vec<String>,
}

pub struct EnclaveFeilds {
    mr_enclave: String,
}
