use crate::error::Error;
use crate::types::AttestationReport;
use crate::types::ReportData;

pub trait AttestationReportVerifier {
    fn verify(report: &AttestationReport, pub_k: &[u8]) -> Result<ReportData, Error>;
}
