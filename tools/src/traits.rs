use crate::error::Error;
use crate::types::AttestationReport;
use crate::types::EnclaveFeilds;

pub trait AttestationReportVerifier {
    fn verify(report: &AttestationReport, now: u64) -> Result<EnclaveFeilds, Error>;
}
