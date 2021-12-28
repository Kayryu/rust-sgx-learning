use std::prelude::v1::*;
use std::str;
use std::time::*;
use std::untrusted::time::SystemTimeEx;
use std::io::BufReader;

use sgx_tcrypto::*;
use sgx_types::*;

use bit_vec::BitVec;
use chrono::Duration;
use chrono::TimeZone;
use chrono::Utc as TzUtc;
use num_bigint::BigUint;
use yasna::models::ObjectIdentifier;

pub const CERTEXPIRYDAYS: i64 = 90i64;
const ISSUER: &str = "SafeMatrix";
const SUBJECT: &str = "SafeMatrix";

// TODO into bytes
pub const IAS_REPORT_CA: &[u8] = include_bytes!("../../cert/AttestationReportSigningCACert.pem");

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
pub struct RaX509Cert {}

impl RaX509Cert {
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
                                writer.next().write_bytes(&payload.into_payload());
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

    pub fn verify(cert: &[u8]) -> Result<ReportData, Error> {
        // Before we reach here, Webpki already verifed the cert is properly signed
        let payload = Self::extract_payload(&cert)?;
        // Extract each field
        let report = AttestationReport::from_payload(&payload)?;

        let sig = base64::decode(&sig_raw).unwrap();
        let sig_cert_dec = base64::decode_config(&sig_cert_raw, base64::MIME).unwrap();
        let sig_cert = webpki::EndEntityCert::from(&sig_cert_dec).expect("Bad DER");

        // Load Intel CA
        let mut ias_ca_stripped = IAS_REPORT_CA.to_vec();
        ias_ca_stripped.retain(|&x| x != 0x0d && x != 0x0a);
        let head_len = "-----BEGIN CERTIFICATE-----".len();
        let tail_len = "-----END CERTIFICATE-----".len();
        let full_len = ias_ca_stripped.len();
        let ias_ca_core: &[u8] = &ias_ca_stripped[head_len..full_len - tail_len];
        let ias_cert_dec = base64::decode_config(ias_ca_core, base64::MIME).unwrap();

        let mut ca_reader = BufReader::new(&IAS_REPORT_CA[..]);

        let mut root_store = rustls::RootCertStore::empty();
        root_store.add_pem_file(&mut ca_reader).expect("Failed to add CA");

        let trust_anchors: Vec<webpki::TrustAnchor> =
            root_store.roots.iter().map(|cert| cert.to_trust_anchor()).collect();

        let mut chain: Vec<&[u8]> = Vec::new();
        chain.push(&ias_cert_dec);

        let now_func = webpki::Time::try_from(SystemTime::now());

        match sig_cert.verify_is_valid_tls_server_cert(
            SUPPORTED_SIG_ALGS,
            &webpki::TLSServerTrustAnchors(&trust_anchors),
            &chain,
            now_func.unwrap(),
        ) {
            Ok(_) => println!("Cert is good"),
            Err(e) => println!("Cert verification error {:?}", e),
        }

        let report_data = Attestation::verify(&report)?;
        return Ok(report_data);
    }

    pub(crate) fn extract_payload(cert_der: &[u8]) -> Result<Vec<u8>, Error> {
        // Search for Public Key prime256v1 OID
        let prime256v1_oid = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
        let mut offset = cert_der
            .windows(prime256v1_oid.len())
            .position(|window| window == prime256v1_oid)
            .unwrap();
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
            .unwrap();
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

        return Ok(payload);
    }
}
