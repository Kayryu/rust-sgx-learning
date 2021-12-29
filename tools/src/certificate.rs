use std::io::BufReader;
use std::marker;
use std::prelude::v1::*;
use std::str;
use std::time::*;

use sgx_types::*;

use bit_vec::BitVec;
use chrono::Duration;
use chrono::TimeZone;
use chrono::Utc as TzUtc;
use num_bigint::BigUint;

#[cfg(feature = "sgx")]
use yasna::models::ObjectIdentifier;
#[cfg(feature = "sgx")]
use sgx_tcrypto::SgxEccHandle;
#[cfg(feature = "sgx")]
use crate::std::untrusted::time::SystemTimeEx;

use crate::error::Error;
use crate::traits::AttestationReportVerifier;
use crate::types::AttestationReport;
use crate::types::ReportData;

pub const CERTEXPIRYDAYS: i64 = 90i64;
const ISSUER: &str = "SafeMatrix";
const SUBJECT: &str = "SafeMatrix";

// TODO into bytes
pub const IAS_REPORT_CA: &[u8] = include_bytes!("../res/AttestationReportSigningCACert.pem");

type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];
static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
    &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

// X. 509 certificate
pub struct RaX509Cert<V> {
    _marker: marker::PhantomData<V>,
}

impl<V> RaX509Cert<V>
where
    V: AttestationReportVerifier,
{
    #[cfg(feature = "sgx")]
    pub fn generate(
        payload: &AttestationReport,
        prv_k: &sgx_ec256_private_t,
        pub_k: &sgx_ec256_public_t,
        ecc_handle: &SgxEccHandle,
    ) -> (Vec<u8>, Vec<u8>) {
        // Generate public key bytes since both DER will use it
        let mut pub_key_bytes: Vec<u8> = vec![4];
        let mut pk_gx = pub_k.gx.clone();
        pk_gx.reverse();
        let mut pk_gy = pub_k.gy.clone();
        pk_gy.reverse();
        pub_key_bytes.extend_from_slice(&pk_gx);
        pub_key_bytes.extend_from_slice(&pk_gy);

        // Generate Certificate DER
        let cert_der = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_sequence(|writer| {
                    // Certificate Version
                    writer.next().write_tagged(yasna::Tag::context(0), |writer| {
                        writer.write_i8(2);
                    });
                    // Certificate Serial Number (unused but required)
                    writer.next().write_u8(1);
                    // Signature Algorithm: ecdsa-with-SHA256
                    writer.next().write_sequence(|writer| {
                        writer
                            .next()
                            .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 4, 3, 2]));
                    });
                    // Issuer: CN=SafeMatrix (unused but required)
                    writer.next().write_sequence(|writer| {
                        writer.next().write_set(|writer| {
                            writer.next().write_sequence(|writer| {
                                writer.next().write_oid(&ObjectIdentifier::from_slice(&[2, 5, 4, 3]));
                                writer.next().write_utf8_string(&ISSUER);
                            });
                        });
                    });
                    // Validity: Issuing/Expiring Time (unused but required)
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap();
                    let issue_ts = TzUtc.timestamp(now.as_secs() as i64, 0);
                    let expire = now + Duration::days(CERTEXPIRYDAYS).to_std().unwrap();
                    let expire_ts = TzUtc.timestamp(expire.as_secs() as i64, 0);
                    writer.next().write_sequence(|writer| {
                        writer
                            .next()
                            .write_utctime(&yasna::models::UTCTime::from_datetime(&issue_ts));
                        writer
                            .next()
                            .write_utctime(&yasna::models::UTCTime::from_datetime(&expire_ts));
                    });
                    // Subject: CN=SafeMatrix (unused but required)
                    writer.next().write_sequence(|writer| {
                        writer.next().write_set(|writer| {
                            writer.next().write_sequence(|writer| {
                                writer.next().write_oid(&ObjectIdentifier::from_slice(&[2, 5, 4, 3]));
                                writer.next().write_utf8_string(&SUBJECT);
                            });
                        });
                    });
                    writer.next().write_sequence(|writer| {
                        // Public Key Algorithm
                        writer.next().write_sequence(|writer| {
                            // id-ecPublicKey
                            writer
                                .next()
                                .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 2, 1]));
                            // prime256v1
                            writer
                                .next()
                                .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 3, 1, 7]));
                        });
                        // Public Key
                        writer.next().write_bitvec(&BitVec::from_bytes(&pub_key_bytes));
                    });
                    // Certificate V3 Extension
                    writer.next().write_tagged(yasna::Tag::context(3), |writer| {
                        writer.write_sequence(|writer| {
                            writer.next().write_sequence(|writer| {
                                writer
                                    .next()
                                    .write_oid(&ObjectIdentifier::from_slice(&[2, 16, 840, 1, 113730, 1, 13]));
                                writer.next().write_bytes(&payload.clone().into_payload());
                            });
                        });
                    });
                });
                // Signature Algorithm: ecdsa-with-SHA256
                writer.next().write_sequence(|writer| {
                    writer
                        .next()
                        .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 4, 3, 2]));
                });
                // Signature
                let sig = {
                    let tbs = &writer.buf[4..];
                    ecc_handle.ecdsa_sign_slice(tbs, &prv_k).unwrap()
                };
                let sig_der = yasna::construct_der(|writer| {
                    writer.write_sequence(|writer| {
                        let mut sig_x = sig.x.clone();
                        sig_x.reverse();
                        let mut sig_y = sig.y.clone();
                        sig_y.reverse();
                        writer.next().write_biguint(&BigUint::from_slice(&sig_x));
                        writer.next().write_biguint(&BigUint::from_slice(&sig_y));
                    });
                });
                writer.next().write_bitvec(&BitVec::from_bytes(&sig_der));
            });
        });

        // Generate Private Key DER
        let key_der = yasna::construct_der(|writer| {
            writer.write_sequence(|writer| {
                writer.next().write_u8(0);
                writer.next().write_sequence(|writer| {
                    writer
                        .next()
                        .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 2, 1]));
                    writer
                        .next()
                        .write_oid(&ObjectIdentifier::from_slice(&[1, 2, 840, 10045, 3, 1, 7]));
                });
                let inner_key_der = yasna::construct_der(|writer| {
                    writer.write_sequence(|writer| {
                        writer.next().write_u8(1);
                        let mut prv_k_r = prv_k.r.clone();
                        prv_k_r.reverse();
                        writer.next().write_bytes(&prv_k_r);
                        writer.next().write_tagged(yasna::Tag::context(1), |writer| {
                            writer.write_bitvec(&BitVec::from_bytes(&pub_key_bytes));
                        });
                    });
                });
                writer.next().write_bytes(&inner_key_der);
            });
        });
        (key_der, cert_der)
    }

    #[cfg(not(feature = "sgx"))]
    pub fn verify(cert: &[u8], now: u64) -> Result<ReportData, Error> {
        // Before we reach here, Webpki already verifed the cert is properly signed
        let (payload, pub_k) = Self::extract_data(&cert)?;
        // Extract each field
        let report = AttestationReport::from_payload(&payload)?;

        let sig = base64::decode(&report.signature).map_err(|_| Error::InvalidIASSignature)?;
        let sig_cert_dec =
            base64::decode_config(&report.cert_raw, base64::MIME).map_err(|_| Error::InvalidIASSigningCert)?;
        let sig_cert = webpki::EndEntityCert::from(&sig_cert_dec).map_err(|_| Error::InvalidIASSigningCert)?;

        // Load Intel CA
        let mut ias_ca_stripped = IAS_REPORT_CA.to_vec();
        ias_ca_stripped.retain(|&x| x != 0x0d && x != 0x0a);
        let head_len = "-----BEGIN CERTIFICATE-----".len();
        let tail_len = "-----END CERTIFICATE-----".len();
        let full_len = ias_ca_stripped.len();
        let ias_ca_core: &[u8] = &ias_ca_stripped[head_len..full_len - tail_len];
        let ias_cert_dec =
            base64::decode_config(ias_ca_core, base64::MIME).map_err(|_| Error::InvalidIASSigningCert)?;

        let mut ca_reader = BufReader::new(&IAS_REPORT_CA[..]);

        let mut root_store = rustls::RootCertStore::empty();
        root_store
            .add_pem_file(&mut ca_reader)
            .map_err(|_| Error::InvalidIASSigningCert)?;

        let trust_anchors: Vec<webpki::TrustAnchor> =
            root_store.roots.iter().map(|cert| cert.to_trust_anchor()).collect();

        let mut chain: Vec<&[u8]> = Vec::new();
        chain.push(&ias_cert_dec);

        let time_now = webpki::Time::from_seconds_since_unix_epoch(now);
        sig_cert
            .verify_is_valid_tls_server_cert(
                SUPPORTED_SIG_ALGS,
                &webpki::TLSServerTrustAnchors(&trust_anchors),
                &chain,
                time_now,
            )
            .map_err(|_| Error::InvalidIASSigningCert)?;

        // verify attestation report
        let report_data = V::verify(&report)?;

        return Ok(report_data);
    }

    pub(crate) fn extract_data(cert_der: &[u8]) -> Result<(Vec<u8>, Vec<u8>), Error> {
        // Search for Public Key prime256v1 OID
        let prime256v1_oid = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
        let mut offset = cert_der
            .windows(prime256v1_oid.len())
            .position(|window| window == prime256v1_oid)
            .ok_or(Error::InvalidSelfSignedCert)?;
        offset += 11; // 10 + TAG (0x03)

        // Obtain Public Key length
        let mut len = cert_der[offset] as usize;
        if len > 0x80 {
            len = (cert_der[offset + 1] as usize) * 0x100 + (cert_der[offset + 2] as usize);
            offset += 2;
        }

        // Obtain Public Key
        offset += 1;
        let pub_k = cert_der[offset + 2..offset + len].to_vec(); // skip "00 04"

        // Search for Netscape Comment OID
        let ns_cmt_oid = &[0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xF8, 0x42, 0x01, 0x0D];
        let mut offset = cert_der
            .windows(ns_cmt_oid.len())
            .position(|window| window == ns_cmt_oid)
            .ok_or(Error::InvalidSelfSignedCert)?;
        offset += 12; // 11 + TAG (0x04)

        // Obtain Netscape Comment length
        let mut len = cert_der[offset] as usize;
        if len > 0x80 {
            len = (cert_der[offset + 1] as usize) * 0x100 + (cert_der[offset + 2] as usize);
            offset += 2;
        }

        // Obtain Netscape Comment
        offset += 1;
        let payload = cert_der[offset..offset + len].to_vec();

        return Ok((payload, pub_k));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct MockVerifier;
    impl AttestationReportVerifier for MockVerifier {
        fn verify(report: &AttestationReport) -> Result<ReportData, Error> {
            Ok(ReportData::default())
        }
    }

    const valid_cert:&[u8] = b"0\x82\rQ0\x82\x0c\xf7\xa0\x03\x02\x01\x02\x02\x01\x010\n\x06\x08*\x86H\xce=\x04\x03\x020\x151\x130\x11\x06\x03U\x04\x03\x0c\nSafeMatrix0\x1e\x17\r211228142848Z\x17\r220328142848Z0\x151\x130\x11\x06\x03U\x04\x03\x0c\nSafeMatrix0Y0\x13\x06\x07*\x86H\xce=\x02\x01\x06\x08*\x86H\xce=\x03\x01\x07\x03B\0\x04\xe3O\xbaAZVR\xf8\x9c|\xd1\xd1\xcb\xc5\xfe\xbc\xca,\xe0\xc3\x1c\x98n\xe3D!m\x84g\xf89\xc2\xdf+\xd4?\x9f=\xd8g&K(O\x17\x9d\x0b\xbc\xe25\xb5'\xac\xc1O\x08|\x85\xb9\x8b%\xf5\xef\x0e\xa3\x82\x0c60\x82\x0c20\x82\x0c.\x06\t`\x86H\x01\x86\xf8B\x01\r\x04\x82\x0c\x1f{\"id\":\"164449606697837473761035791343288171732\",\"timestamp\":\"2021-12-28T14:28:48.633876\",\"version\":3,\"epidPseudonym\":\"acJDwkzqp57/UHJDr10/xBxV3K6YmSNTDiaQ+tozR9ulUS4DlNjkqHDhy7K49fdPVt7E/KOugglK5/fsgADjrCSTPR9m5EvQaQlZ2wxoPBzKRUphQlXpHGQP3jLhGeXZ9ruz2N7mD314iz7QuyQn20gXaUf2WNoCIenPJdJ1L4I=\",\"isvEnclaveQuoteStatus\":\"GROUP_OUT_OF_DATE\",\"platformInfoBlob\":\"150200650400060000111102040180060000000000000000000C00000C000000020000000000000BFE89DBFE2CB8E8CFB785A484535E6C789FB4198B486E5958D4C8F746388D2705B712A5162B479436B1DCD1367EF9508F27BA641E71A3607ED8457CCA6E58A1AF00\",\"isvEnclaveQuoteBody\":\"AgABAP4LAAALAAoAAAAAALbnkiiGROKVekCvIm9eTdgAAAAAAAAAAAAAAAAAAAAAEREDBf+ABgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAAAHAAAAAAAAANtPLb/I3xWMLWGpHO1TVZvc2PL8KUuzzf/FsFvn957wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADjT7pBWlZS+Jx80dHLxf68yizgwxyYbuNEIW2EZ/g5wt8r1D+fPdhnJksoTxedC7ziNbUnrMFPCHyFuYsl9e8O\"}|aAC/+5vlT5p/eVXWE66d/VHFME+PehsIP55KcrCQIbUh0CPHKobaAYbg+zB5dcSG7olfMNFfRKVLgaOKm2duJZDnFg5cljN6mtYRwGdhk2jD6rIt8zR7gEUB2NXGaUTM+zN+fUYFK5GVsjwI7MiPHG2XcGqi1FwJOiErNaMANShWknJgzdEQZhuiurt5MvfN0I3oQExGZKm1RXZZCwJ4z7vVKsBpk80/EwQMmofQwk9MecklBEZncXVmYKbDRq0dUgXFVNs1YCa34ss+eSdSujoeE9xBVh4VaZ5aMUbUXQU9d6QtBtuuDcgTZoRHLeQJAUrscsTac++a8Q2/J/RfgA==|MIIEoTCCAwmgAwIBAgIJANEHdl0yo7CWMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEUMBIGA1UEBwwLU2FudGEgQ2xhcmExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMTAwLgYDVQQDDCdJbnRlbCBTR1ggQXR0ZXN0YXRpb24gUmVwb3J0IFNpZ25pbmcgQ0EwHhcNMTYxMTIyMDkzNjU4WhcNMjYxMTIwMDkzNjU4WjB7MQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1NhbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjEtMCsGA1UEAwwkSW50ZWwgU0dYIEF0dGVzdGF0aW9uIFJlcG9ydCBTaWduaW5nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAqXot4OZuphR8nudFrAFiaGxxkgma/Es/BA+tbeCTUR106AL1ENcWA4FX3K+E9BBL0/7X5rj5nIgX/R/1ubhkKWw9gfqPG3KeAtIdcv/uTO1yXv50vqaPvE1CRChvzdS/ZEBqQ5oVvLTPZ3VEicQjlytKgN9cLnxbwtuvLUK7eyRPfJW/ksddOzP8VBBniolYnRCD2jrMRZ8nBM2ZWYwnXnwYeOAHV+W9tOhAImwRwKF/95yAsVwd21ryHMJBcGH70qLagZ7Ttyt++qO/6+KAXJuKwZqjRlEtSEz8gZQeFfVYgcwSfo96oSMAzVr7V0L6HSDLRnpb6xxmbPdqNol4tQIDAQABo4GkMIGhMB8GA1UdIwQYMBaAFHhDe3amfrzQr35CN+s1fDuHAVE8MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMGAGA1UdHwRZMFcwVaBToFGGT2h0dHA6Ly90cnVzdGVkc2VydmljZXMuaW50ZWwuY29tL2NvbnRlbnQvQ1JML1NHWC9BdHRlc3RhdGlvblJlcG9ydFNpZ25pbmdDQS5jcmwwDQYJKoZIhvcNAQELBQADggGBAGcIthtcK9IVRz4rRq+ZKE+7k50/OxUsmW8aavOzKb0iCx07YQ9rzi5nU73tME2yGRLzhSViFs/LpFa9lpQL6JL1aQwmDR74TxYGBAIi5f4I5TJoCCEqRHz91kpG6Uvyn2tLmnIdJbPE4vYvWLrtXXfFBSSPD4Afn7+3/XUggAlc7oCTizOfbbtOFlYA4g5KcYgS1J2ZAeMQqbUdZseZCcaZZZn65tdqee8UXZlDvx0+NdO0LR+5pFy+juM0wWbu59MvzcmTXbjsi7HY6zd53Yq5K244fwFHRQ8eOB0IWB+4PfM7FeAApZvlfqlKOlLcZL2uyVmzRkyR5yW72uo9mehX44CiPJ2fse9Y6eQtcfEhMPkmHXI01sN+KwPbpA39+xOsStjhP9N1Y1a2tQAVo+yVgLgV2Hws73Fc0o3wC78qPEA+v2aRs/Be3ZFDgDyghc/1fgU+7C+P6kbqd4poyb6IW8KCJbxfMJvkordNOgOUUxndPHEi/tb/U7uLjLOgPA==0\n\x06\x08*\x86H\xce=\x04\x03\x02\x03H\00E\x02!\0\xf4vZX\xf4_\x8b\xcb\x1dL\xdb\xb4\xf6\xa2\xf0k\xc4\xf2\xf8\xd0K\x1d\xdfb%\xb3@\x0b/\xeb\xdeH\x02 ^\x1c\x7f\x02\x9e\x1b\xd6\xd9Qj\xddAY\0\x80\xd2\\\xae\xa4H\xe8\xe4Do\x8a#wb^\xc9\x88q";

    #[test]
    fn invalid_cert_should_fault() {
        let cert = [0x00u8, 0x01u8];
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let ret = RaX509Cert::<MockVerifier>::verify(&cert, now);
        assert_eq!(ret.err(), Some(Error::InvalidSelfSignedCert));
    }

    #[test]
    fn valid_cert_should_ok() {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let ret = RaX509Cert::<MockVerifier>::verify(valid_cert, now);
        assert_eq!(ret.ok(), Some(ReportData::default()));
    }
}
