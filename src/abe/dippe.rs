//! Decentralized inner-product predicate encryption.

use crate::mat::*;
use rabe_bn::*;
use rand::prelude::*;

/// Dippe system parameters
pub struct Dippe {
    assumption_size: usize,
    g1_a: G1Matrix,
    g1_ua: G1Matrix,
}

impl Dippe {
    pub fn new<R: CryptoRng + RngCore>(rand: &mut R, assumption_size: usize) -> Self {
        let a = FrMatrix::from_random(rand, assumption_size + 1, assumption_size);
        let ut = FrMatrix::from_random(rand, assumption_size + 1, assumption_size + 1);
        let uta = ut * a.clone();

        let g1_a = a * G1::one();
        let g1_ua = uta * G1::one();

        Self {
            assumption_size,
            g1_a,
            g1_ua,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_dippe() {
        let _ = Dippe::new(&mut rand::thread_rng(), 2);
    }
}
