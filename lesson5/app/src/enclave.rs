use sgx_types::*;
use sgx_urts::SgxEnclave;
use log::{info, error};

pub struct EnclaveBuilder<'a> {
    file: &'a str,
    token: [u8; 1024],
    debug: i32,
}

impl<'a> EnclaveBuilder<'a> {
    pub fn new() -> Self {
        // Debug Support: set 2nd parameter to 1
        Self {
            file: "enclave.signed.so",
            token: [0; 1024],
            debug: 1,
        }
    }

    pub fn file(&mut self, file: &'a str) -> &mut Self {
        self.file = file;
        self
    }

    pub fn token(&mut self, token: [u8; 1024]) -> &mut Self {
        self.token = token;
        self
    }

    pub fn debug(&mut self, debug: i32) -> &mut Self {
        self.debug = debug;
        self
    }

    pub fn create(&self) -> SgxResult<Enclave> {
        let mut launch_token: sgx_launch_token_t = [0; 1024];
        let mut launch_token_updated: i32 = 0;
        // call sgx_create_enclave to initialize an enclave instance
        let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
        
        // init enclave
        let enclave = match SgxEnclave::create(self.file,
                                            self.debug,
                                            &mut launch_token,
                                            &mut launch_token_updated,
                                            &mut misc_attr) {
            Ok(r) => {
                info!("[+] Init Enclave Successful {}!", r.geteid());
                r
            },
            Err(x) => {
                error!("[-] Init Enclave Failed {}!", x.as_str());
                return Err(x);
            },
        };
        Ok(Enclave::attach(enclave))
    }
}

#[derive(Clone, Debug, Default)]
pub struct Enclave {
	eid: sgx_enclave_id_t,
	sgx_enclave: SgxEnclave,
}

impl Enclave {
	pub fn attach(sgx_enclave: SgxEnclave) -> Self {
		Enclave { eid: sgx_enclave.geteid(), sgx_enclave }
	}

    pub fn eid(&self) -> sgx_enclave_id_t {
        self.eid
    }

	pub fn destroy(self) {
		self.sgx_enclave.destroy()
	}
}