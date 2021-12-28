use std::io::Read;
use std::io::Write;
use std::net::TcpStream;
use std::sync::Arc;
use crate::error::Error;
use crate::attestation::Attestation;
use crate::types::AttestationReport;
use crate::Utils;
use crate::attestation::SgxCall;

use sgx_types::sgx_spid_t;

use std::prelude::v1::*;

pub const DEV_HOSTNAME: &'static str = "api.trustedservices.intel.com";
pub const SIGRL_SUFFIX: &'static str = "/sgx/dev/attestation/v3/sigrl/";
pub const REPORT_SUFFIX: &'static str = "/sgx/dev/attestation/v3/report";

pub struct Net {
    pub spid: sgx_spid_t,
    pub ias_key: String,
}

// todo use http_req https://github.com/mesalock-linux/http_req-sgx/blob/5d0f7474c7/examples/request_builder_get.rs

impl Net {
    pub fn new(spid: String, ias_key: String) -> Self {
        let spid = Utils::decode_spid(spid);
        Self { spid, ias_key }
    }

    pub fn get_sigrl(&self, gid: u32) -> Result<Vec<u8>, Error> {
        let request = format!(
            "GET {}{:08x} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key: {}\r\nConnection: Close\r\n\r\n",
            SIGRL_SUFFIX, gid, DEV_HOSTNAME, self.ias_key
        );

        let resp = self.send(request)?;

        // parse http response
        return Ok(Self::parse_response_sigrl(&resp.as_bytes()));
    }

    pub fn get_report(&self, quote: Vec<u8>) -> Result<AttestationReport, Error> {
        let encoded_quote = base64::encode(&quote[..]);
        let encoded_json = format!("{{\"isvEnclaveQuote\":\"{}\"}}\r\n", encoded_quote);

        let request = format!("POST {} HTTP/1.1\r\nHOST: {}\r\nOcp-Apim-Subscription-Key:{}\r\nContent-Length:{}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                            REPORT_SUFFIX,
                            DEV_HOSTNAME,
                            self.ias_key,
                            encoded_json.len(),
                            encoded_json);

        let resp = self.send(request)?;

        // parse http response
        let (att_report, sig, sig_cert) = Self::parse_response_attn_report(&resp.as_bytes());

        return Ok(AttestationReport {
            ra_report: att_report.as_bytes().to_vec(),
            signature: sig.as_bytes().to_vec(),
            cert_raw: sig_cert.as_bytes().to_vec(),
        });
    }

    fn send(&self, request: String) -> Result<String, Error> {

        let fd = 
        let config = Self::make_ias_client_config();
        let dns_name = webpki::DNSNameRef::try_from_ascii_str(DEV_HOSTNAME).unwrap();
        let mut sess = rustls::ClientSession::new(&Arc::new(config), dns_name);
        let mut sock = TcpStream::new(fd).unwrap();
        let mut tls = rustls::Stream::new(&mut sess, &mut sock);

        let _result = tls.write(request.as_bytes());
        let mut plaintext = Vec::new();
        match tls.read_to_end(&mut plaintext) {
            Ok(_) => (),
            Err(e) => return Err(Error::NetError(e.to_string())),
        }
        let response = String::from_utf8(plaintext.clone()).unwrap();
        return Ok(response)
    }

    fn make_ias_client_config() -> rustls::ClientConfig {
        let mut config = rustls::ClientConfig::new();

        config
            .root_store
            .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);

        config
    }

    fn parse_response_attn_report(resp: &[u8]) -> (String, String, String) {
        info!("parse_response_attn_report");
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut respp = httparse::Response::new(&mut headers);
        let result = respp.parse(resp);
        debug!("parse result {:?}", result);

        let msg: &'static str;

        match respp.code {
            Some(200) => msg = "OK Operation Successful",
            Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
            Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
            Some(500) => msg = "Internal error occurred",
            Some(503) => {
                msg = "Service is currently not able to process the request (due to
                a temporary overloading or maintenance). This is a
                temporary state – the same request can be repeated after
                some time. "
            }
            _ => {
                println!("DBG:{}", respp.code.unwrap());
                msg = "Unknown error occured"
            }
        }

        debug!("{}", msg);
        let mut len_num: u32 = 0;

        let mut sig = String::new();
        let mut cert = String::new();
        let mut attn_report = String::new();

        for i in 0..respp.headers.len() {
            let h = respp.headers[i];
            //println!("{} : {}", h.name, str::from_utf8(h.value).unwrap());
            match h.name {
                "Content-Length" => {
                    let len_str = String::from_utf8(h.value.to_vec()).unwrap();
                    len_num = len_str.parse::<u32>().unwrap();
                    println!("content length = {}", len_num);
                }
                "X-IASReport-Signature" => sig = str::from_utf8(h.value).unwrap().to_string(),
                "X-IASReport-Signing-Certificate" => cert = str::from_utf8(h.value).unwrap().to_string(),
                _ => (),
            }
        }

        // Remove %0A from cert, and only obtain the signing cert
        cert = cert.replace("%0A", "");
        cert = cert::percent_decode(cert);
        let v: Vec<&str> = cert.split("-----").collect();
        let sig_cert = v[2].to_string();

        if len_num != 0 {
            let header_len = result.unwrap().unwrap();
            let resp_body = &resp[header_len..];
            attn_report = str::from_utf8(resp_body).unwrap().to_string();
            println!("Attestation report: {}", attn_report);
        }

        // len_num == 0
        (attn_report, sig, sig_cert)
    }

    fn parse_response_sigrl(resp: &[u8]) -> Vec<u8> {
        info!("parse_response_sigrl");
        let mut headers = [httparse::EMPTY_HEADER; 16];
        let mut respp = httparse::Response::new(&mut headers);
        let result = respp.parse(resp);
        debug!("parse result {:?}", result);
        debug!("parse response{:?}", respp);

        let msg: &'static str;

        match respp.code {
            Some(200) => msg = "OK Operation Successful",
            Some(401) => msg = "Unauthorized Failed to authenticate or authorize request.",
            Some(404) => msg = "Not Found GID does not refer to a valid EPID group ID.",
            Some(500) => msg = "Internal error occurred",
            Some(503) => {
                msg = "Service is currently not able to process the request (due to
                a temporary overloading or maintenance). This is a
                temporary state – the same request can be repeated after
                some time. "
            }
            _ => msg = "Unknown error occured",
        }

        debug!("{}", msg);
        let mut len_num: u32 = 0;

        for i in 0..respp.headers.len() {
            let h = respp.headers[i];
            if h.name == "content-length" {
                let len_str = String::from_utf8(h.value.to_vec()).unwrap();
                len_num = len_str.parse::<u32>().unwrap();
                println!("content length = {}", len_num);
            }
        }

        if len_num != 0 {
            let header_len = result.unwrap().unwrap();
            let resp_body = &resp[header_len..];
            println!("Base64-encoded SigRL: {:?}", resp_body);

            return base64::decode(str::from_utf8(resp_body).unwrap()).unwrap();
        }

        // len_num == 0
        Vec::new()
    }
}
