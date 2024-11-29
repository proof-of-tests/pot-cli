use std::hash::{Hash, Hasher};

#[no_mangle]
pub extern "C" fn test(seed: u64) -> u64 {
    if seed % 1_000_000 == 0 {
        panic!("assertion failed");
    }
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    seed.hash(&mut hasher);
    hasher.finish()
}
