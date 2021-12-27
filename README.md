
# 环境
* teaclave-sgx-sdk ： v1.1.3


# 资源

* Intel SGX Developer Guide（[2.2版本](https://download.01.org/intel-sgx/linux-2.2/docs/Intel_SGX_Developer_Guide.pdf))
* [Platform Embedded Security Technology Revealed](https://link.springer.com/book/10.1007/978-1-4302-6572-6)。
* Intel SGX [主页](https://software.intel.com/en-us/sgx)
* Intel SGX SDK [主页](https://software.intel.com/en-us/sgx-sdk)
* Intel Open Source 01.org 上的 SGX for linux [主页](https://01.org/intel-softwareguard-extensions) 
* Intel 官方的 [linux-sgx-sdk](https://github.com/intel/linux-sgx)
* Intel 官方的 [linux-sgx-driver](https://github.com/intel/linux-sgx-driver)
* 一份 Remote Attestation 实现 [linux-sgx-remoteattestation](https://github.com/svartkanin/linux-sgx-remoteattestation)
* 一[Intel SGX Explained](https://eprint.iacr.org/2016/086.pdf) 
* [SGX-hardware](https://github.com/ayeks/SGX-hardware) 
* [Intel SGX develop](https://software.intel.com/content/www/us/en/develop/articles/intel-sgx-web-based-training.html)
* [Intel sample code](https://github.com/intel/linux-sgx)


# 如何开发

执行 `env.sh` 脚本，然后跳转到 `sgx-learning` 下的相应目录。  
修改 对应
执行 `make` 命令， 会在`bin`目录下生产`app`可执行文件，执行`app`查看结果。

>> 如果出现ra访问失败，执行`LD_LIBRARY_PATH="/opt/intel/sgx-aesm-service/aesm:$LD_LIBRARY_PATH" nohup /opt/intel/sgx-aesm-service/aesm/aesm_service --no-daemon >/dev/null 2>&1 &`
