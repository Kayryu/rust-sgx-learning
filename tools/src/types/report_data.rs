// from https://www.intel.com/content/dam/develop/public/us/en/documents/sgx-attestation-api-spec.pdf

pub struct ReportData {
    /// Representation of unique identifier of the Attestation Verification Report.
    /// 
    /// This field is mandatory. 
    id: String,
    ///
    timestamp: String,
    version: u32,
    isvEnclaveQuoteStatus: String,
    isvEnclaveQuoteBody: String,
    revocationReason: u32,
    pseManifestStatus: String,
    pseManifestHash: String,
    platformInfoBlob: String,
    nonce: String,
    epidPseudonym: String,
    advisoryURL: String,
    advisoryIDs: Vec<String>,
}

