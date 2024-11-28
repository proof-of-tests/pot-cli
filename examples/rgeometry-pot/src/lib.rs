use rand::Rng;
use rand::SeedableRng;
use rgeometry::data::polygon::PolygonConvex;
use std::hash::Hash;

#[no_mangle]
pub extern "C" fn test(seed: u64) -> u64 {
    let mut rng = rand::rngs::StdRng::seed_from_u64(seed);
    let n = rng.gen_range(3..=10000);
    let poly: PolygonConvex<i8> = PolygonConvex::random(n, &mut rng);
    use std::hash::Hasher;
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    poly.hash(&mut hasher);
    hasher.finish()
}
