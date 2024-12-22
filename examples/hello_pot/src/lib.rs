// use wasm_bindgen::prelude::*;

#[no_mangle]
pub static REPO: [u8; 42] = *b"https://github.com/proof-of-tests/pot-cli\0";

#[no_mangle]
pub extern "C" fn test(seed: u64) -> u64 {
    seed
}
