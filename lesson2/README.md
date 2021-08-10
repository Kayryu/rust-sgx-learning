# Writing enclaves

## Writing EDL

* For fixed-length array in ECALL/OCALL definition, declare it as an array.  For dynamic-length array, use the keyword `size=` to let the Intel SGX knows how many bytes should be copied.

## ECALL Function Naming

* Add `#[no_mangle]` for every ECALL function.

## Passing/returning arrays

* For dynamic-length array, the only way is to use raw pointers in Rust. There are several functions to get/set data using raw pointers such as [`offset`](https://doc.rust-lang.org/1.9.0/std/primitive.pointer.html#method.offset) method. One can also use [`slice::from_raw_parts`](https://doc.rust-lang.org/std/slice/fn.from_raw_parts.html) to convert the array to a slice.

* For Fixed-length array, the above method is acceptable. And according to discussions in [issue 30382](https://github.com/rust-lang/rust/issues/30382) and [issue 31227](https://github.com/rust-lang/rust/issues/31227), thin-pointers (such as fixed-length array) are FFI-safe for now, but undocumented. In the sample codes, we use fixed-length arrays for passing and returning some fixed-length data.
