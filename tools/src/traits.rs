use crate::error::Error;
use crate::types::AttestationReport;
use crate::types::ReportData;

pub trait AttestationReportVerifier {
    fn verify(report: &AttestationReport) -> Result<ReportData, Error>;
}
