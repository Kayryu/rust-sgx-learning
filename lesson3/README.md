# Store

## Data Sealing
Enclaves are **essentially stateless**: they are destroyed when the system goes to sleep, when the application exits, and of course when the application explicitly destroys them. When an enclave is destroyed, all of its contents are lost.

To preserve the information that’s stored in an enclave, you must explicitly send it outside the enclave to untrusted memory. Intel SGX provides a capability called data sealing which encrypts enclave data in the enclave using an encryption key that is derived from the CPU. This encrypted data block, also called the sealed data, can only be decrypted, or unsealed, on the same system (and, typically, in the exact same enclave) where it was created. The encryption itself provides assurances of confidentiality, integrity, and authenticity on the data.

There is an important caveat with data sealing that can have significant security implications: enclaves do not authenticate the untrusted application. You must not assume that only your application will load your enclave, or that your ECALLs will be invoked in a specific order. Anyone can load your enclave and execute its ECALLs in any order they choose. Your enclave’s API must not allow the sealing and unsealing capability to leak secrets, or grant unauthorized access to them.

