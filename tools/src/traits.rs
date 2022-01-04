use crate::error::Error;
use crate::types::AttestationReport;
use crate::types::EnclaveFields;

pub trait AttestationReportVerifier {
    fn verify(report: &AttestationReport, now: u64) -> Result<EnclaveFields, Error>;
}
