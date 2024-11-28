// HyperLogLog implementation that stores hashes instead of counts. This takes
// up more space, but allows for verification.

use serde::{Deserialize, Serialize};
use std::ops::Neg;

// const BITS: u64 = 6;
// const REGISTERS: usize = 1 << BITS as usize;
// const MASK: u64 = (1 << BITS) - 1;
// const ALPHA: f64 = 0.7213 / (1.0 + 1.079 / REGISTERS as f64);

// mod array_serialization {
//     use super::REGISTERS;
//     use serde::{Deserialize, Deserializer, Serialize, Serializer};

//     pub fn serialize<S>(array: &[u64; REGISTERS], serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         let vec: Vec<u64> = array.to_vec();
//         vec.serialize(serializer)
//     }

//     pub fn deserialize<'de, D>(deserializer: D) -> Result<[u64; REGISTERS], D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         let vec: Vec<u64> = Vec::deserialize(deserializer)?;
//         let mut array = [0; REGISTERS];
//         if vec.len() != REGISTERS {
//             return Err(serde::de::Error::custom("Invalid length for u64 array"));
//         }
//         array.copy_from_slice(&vec);
//         Ok(array)
//     }
// }

#[derive(Clone, Serialize, Deserialize)]
pub struct HyperLogLog {
    pub bits: u64,
    // #[serde(with = "array_serialization")]
    pub seeds: Vec<u64>,
    // #[serde(with = "array_serialization")]
    pub hashes: Vec<u64>,
}

impl HyperLogLog {
    // const REGISTERS: usize = 1 << BITS as usize;
    // const MASK: u64 = (1 << BITS) - 1;
    // const ALPHA: f64 = 0.7213 / (1.0 + 1.079 / Self::REGISTERS as f64);

    pub fn new(bits: u64) -> Self {
        let registers = 1 << bits as usize;
        Self {
            bits,
            seeds: vec![0; registers],
            hashes: vec![u64::MAX; registers],
        }
    }

    pub fn registers(&self) -> usize {
        1 << self.bits as usize
    }

    pub fn mask(&self) -> u64 {
        (1 << self.bits) - 1
    }

    pub fn alpha(&self) -> f64 {
        0.7213 / (1.0 + 1.079 / self.registers() as f64)
    }

    pub fn add(&mut self, seed: u64, hash: u64) {
        let register = (hash & self.mask()) as usize;
        if self.hashes[register] > hash {
            self.hashes[register] = hash;
            self.seeds[register] = seed;
        }
    }

    pub fn count(&self) -> u64 {
        (self.alpha() * self.registers() as f64 * self.registers() as f64
            / self
                .hashes
                .iter()
                .map(|r| 2.0_f64.powi((r.leading_zeros() as i32).saturating_add(1).neg()))
                .sum::<f64>())
        .round() as u64
    }
}
