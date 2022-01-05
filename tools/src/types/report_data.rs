// from https://www.intel.com/content/dam/develop/public/us/en/documents/sgx-attestation-api-spec.pdf

use itertools::Itertools;
use serde::{self, Deserialize, Serialize};
use std::fmt;
use std::prelude::v1::*;

#[derive(Default, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReportData {
    pub id: String,
    pub timestamp: String,
    pub version: u32,
    pub isv_enclave_quote_status: String,
    pub isv_enclave_quote_body: String,
    #[serde(alias = "advisoryURL")]
    pub advisory_url: Option<String>,
    #[serde(alias = "advisoryIDs")]
    pub advisory_ids: Option<Vec<String>>,
    pub nonce: Option<String>,
    pub epid_pseudonym: Option<String>,
    pub revocation_reason: Option<u32>,
    pub pse_manifest_status: Option<String>,
    pub pse_manifest_hash: Option<String>,
    pub platform_info_blob: Option<String>,
}

#[derive(Default, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EnclaveFields {
    pub version: u16,
    pub sign_type: u16,
    pub report_data: Vec<u8>,
    pub mr_enclave: Vec<u8>,
    pub mr_signer: Vec<u8>,
    pub isv_prod_id: u16,
    pub isv_svn: u16,
    pub isv_enclave_quote_status: String,
}

impl fmt::Display for EnclaveFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{{ version: {}, sign_type: {}, report_data: \"{:02x}\", mr_enclave: \"{:02x}\", mr_signer: \"{:02x}\", isv_prod_id: {}, isv_svn: {}, isv_enclave_quote_status: \"{}\" }}", 
        self.version, self.sign_type, self.report_data.iter().format(""),
        self.mr_enclave.iter().format(""), self.mr_signer.iter().format(""),
        self.isv_prod_id, self.isv_svn, self.isv_enclave_quote_status)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const report_data:&str = "{\"id\":\"251938920532710053530482175012308117351\",\"timestamp\":\"2021-12-31T11:54:53.077742\",\"version\":3,\"epidPseudonym\":\"acJDwkzqp57/UHJDr10/xBxV3K6YmSNTDiaQ+tozR9ulUS4DlNjkqHDhy7K49fdPVt7E/KOugglK5/fsgADjrCSTPR9m5EvQaQlZ2wxoPBzKRUphQlXpHGQP3jLhGeXZ9ruz2N7mD314iz7QuyQn20gXaUf2WNoCIenPJdJ1L4I=\",\"isvEnclaveQuoteStatus\":\"GROUP_OUT_OF_DATE\",\"platformInfoBlob\":\"150200650400060000111102040180060000000000000000000C00000C000000020000000000000BFEBBC8926E89D90F3DC657D85B379E2EBC78D929579F022949112BD23BAF20CFC7C5194C113CF89366CBE5B34BC9C72663565BBEF6D67B073D52EECD779E8B9FCC\",\"isvEnclaveQuoteBody\":\"AgABAP4LAAALAAoAAAAAALbnkiiGROKVekCvIm9eTdgAAAAAAAAAAAAAAAAAAAAAEREDBf+ABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAADcKV0+kloo/ApsyWzAILJwT745uGT8YHhtp01MOMtpMAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAqlEPKrypKbtNc98F0ZJhTkQPNB0LM4V/UPoyqYX4lJBKfc5erTL2Ml8XNh9qqOW1rbilmTKvd8ES6FhTWXKca\"}";

    #[test]
    fn serde_test() {
        let data = serde_json::from_str::<ReportData>(report_data);
        assert!(data.is_ok())
    }
}
