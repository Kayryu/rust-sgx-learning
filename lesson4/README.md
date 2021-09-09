# Project

The project files: 

```
|-- app/
|   |-- src/
|       |-- main.rs
|   |-- Cargo.toml
|   |-- build.rs
|-- bin/
|   |-- readme.txt
|-- enclave/
|   |-- src/
|       |-- lib.rs
|   |-- Cargo.toml
|   |-- Enclave.config.xml
|   |-- Enclave.edl
|   |-- Enclave.lds
|   |-- Makefile
|   |-- Xargo.toml
|-- lib/
|   |-- readme.txt
|-- Makefile
|-- README.md

--- buildenv.mk
```

# Build

By default, your project will be compiled in hardware mode. If you wish to compile your project in software/simulation mode, you will need to specify it, either by adding ```SGX_MODE=SW``` before make, or by setting the SGX_MODE variable environment to SW.



https://play.rust-lang.org/?version=stable&mode=debug&edition=2018&gist=ec62dc79f9d18ca5387282fe10de4faf