use crate::error::Error;

pub struct AttestationReport {
    ra_report: Vec<u8>,
    signature: Vec<u8>,
    cert_raw: Vec<u8>,
}

impl AttestationReport {
    // use for transfer to payload of cert
    pub fn into_payload(self) -> Vec<u8> {
        const separator: &[u8] = &[0x7Cu8];
        let mut payload = Vec::new();
        payload.extend(self.ra_report);
        payload.extend(separator);
        payload.extend(self.signature);
        payload.extend(separator);
        payload.extend(self.cert_raw);
        return payload;
    }

    pub fn from_payload(payload: &[u8]) -> Result<Self, Error> {
        let mut iter = payload.split(|x| *x == 0x7C);
        let attn_report_raw = iter.next().unwrap();
        let sig_raw = iter.next().unwrap();
        let sig_cert_raw = iter.next().unwrap();
        return Ok(Self {
            ra_report: attn_report_raw.to_vec(),
            signature: sig_raw.to_vec(),
            cert_raw: sig_cert_raw.to_vec(),
        })
    }
}

// TODO test

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::*;

    #[test]
    fn test_report_to_payload() {

    }
}