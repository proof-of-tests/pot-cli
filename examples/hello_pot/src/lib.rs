// use wasm_bindgen::prelude::*;

#[no_mangle]
pub extern "C" fn test(seed: u64) -> u64 {
    seed
}
