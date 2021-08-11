# Writing enclaves

## Writing EDL

* For fixed-length array in ECALL/OCALL definition, declare it as an array.  For dynamic-length array, use the keyword `size=` to let the Intel SGX knows how many bytes should be copied.

## ECALL Function Naming

* Add `#[no_mangle]` for every ECALL function.

## Passing/returning arrays

* For dynamic-length array, the only way is to use raw pointers in Rust. There are several functions to get/set data using raw pointers such as [`offset`](https://doc.rust-lang.org/1.9.0/std/primitive.pointer.html#method.offset) method. One can also use [`slice::from_raw_parts`](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html) to convert the array to a slice.

* For Fixed-length array, the above method is acceptable. And according to discussions in [issue 30382](https://github.com/rust-lang/rust/issues/30382) and [issue 31227](https://github.com/rust-lang/rust/issues/31227), thin-pointers (such as fixed-length array) are FFI-safe for now, but undocumented. In the sample codes, we use fixed-length arrays for passing and returning some fixed-length data.

## Why Need EDL File
SGX ensures secret data can only be accessed by codes inside the enclave. To interact with these data from outside the enclave, SGX provides an interface for developers to build communication channels bridging the trusted and untrusted environments.

Two concepts:

* ECALLs (Enclave Calls) refers to entry points into the enclave from the untrusted application.
* OCALLs (Outside Calls) allows enclave functions to call out to the untrusted application and then return to the enclave.

The enclave’s interface is comprised of ECALLs and OCALLs, which are defined in the enclave’s EDL (Enclave Definition Language) file.

Although ECALLs and OCALLs may look like simple function calls, but in order to cooperate with the hardware protection mechanisms, it requires special CPU instructions to work. SGX SDK provides developers with a powerful tool, edger8r. This tool automatically generates proxy functions named after your ECALLs and OCALLs, so that your application can invoke them as it would any other C function.

Edger8r reads EDL file to work.

## EDL File Syntax
In an EDL file, there are two sections, namely, **trusted** and **untrusted**.

```
enclave {
    from "sgx_tstdc.edl" import *;

    trusted {
        /* define ECALLs here. */
        public int my_ecall(int value);
    };

    untrusted {
        /* define OCALLs here. */
        void an_ocall(int p1, int p2);
    };
};
```

The syntax of EDL resembles C, and has additional special keywords.

* public: any ECALL that intends to be invoked by the untrusted application should be declared as public. ECALLs without public keyword are private and can only be invoked by an OCALL.

```
trusted {
        /* define ECALLs here. */
        public int my_ecall(int value); /* public ECALL */
        int ecall_private(int value); /* private ECALL, can only be invoked by OCALLs */
    };
```

As we know, parameters can be passed either by values or by reference. For those passed by value, changes inside ECALLs and OCALLs will not affect the calling function.

However, for those passed by reference (such as a pointer), a developer should explicitly indicate the direction that the parameter is propagating, in order to constrain invalid usage of such parameters and prevent further threats. Special keywords serve this purpose .

```
enclave {
    from "sgx_tstdc.edl" import *;

    trusted {
        /* define ECALLs here. */
        public int my_ecall1([in] int32_t *value);
        public int my_ecall2([out] int32_t *value);
        public int my_ecall3([in, out] int32_t *value);
        public int my_ecall4([in, count=10] int32_t *array);
        public int my_ecall5([in, count=len] int32_t *array, size_t len);
        public int my_ecall6([in, string] char *name);
        public int my_ecall7([in, wstring] wchar_t *unicodename); /* wstring may represent wide string */
    };

    untrusted {
        /* define OCALLs here. */
        void an_ocall(int p1, int p2);
    };
};
```

* in: [in] means the parameter should be passed from the caller to the callee.
* out: [out] means the parameter should be returned from the callee to the caller.
* [in, out] means the parameter can be propogated in both directions.
* count: [count=n] means the number of elements that will be copied to or from this pointer is n. By default, n is set to 1.
* string: [in, string] means you are passing in a NULL-terminated string. Note string can not be combined with the out keyword.