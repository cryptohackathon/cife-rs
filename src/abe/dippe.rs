//! Decentralized inner-product predicate encryption.

use std::fmt;

use crate::mat::*;

use rabe_bn::*;
use rand::prelude::*;

/// Dippe system parameters
pub struct Dippe {
    assumption_size: usize,
    g1_a: G1Matrix,
    g1_ua: G1Matrix,
}

impl fmt::Debug for Dippe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Dippe")
            .field("assumption_size", &self.assumption_size)
            .finish()
    }
}

/// Public key of a DIPPE authority.
///
/// A key-pair is generated with [Dippe::generate_key_pair]
pub struct PublicKey {
    g2_sigma: G2,
    g1_w_a: G1Matrix,
    gt_alpha_a: GtVector,
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("assumption_size", &self.gt_alpha_a.dims().0)
            .finish()
    }
}

/// Private key of a DIPPE authority.
///
/// A key-pair is generated with [Dippe::generate_key_pair]
pub struct PrivateKey {
    sigma: Fr,
    alpha: FrVector,
    w: FrMatrix,
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PrivateKey")
            .field("assumption_size", &(self.alpha.dims().0 - 1))
            .finish()
    }
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

    /// Generate the key-pair for a DIPPE authority
    pub fn generate_key_pair<R: CryptoRng + RngCore>(
        &self,
        rand: &mut R,
    ) -> (PublicKey, PrivateKey) {
        let privkey = PrivateKey {
            sigma: rand.gen(),
            alpha: FrVector::from_random(rand, self.assumption_size + 1, 1),
            w: FrVector::from_random(rand, self.assumption_size + 1, self.assumption_size + 1),
        };

        let wt = privkey.w.transposed();

        let gt_a = self.g1_a.pair_with_g2();
        let gt_a_t = gt_a.transposed();

        let pubkey = PublicKey {
            g2_sigma: G2::one() * privkey.sigma.clone(),
            g1_w_a: wt * self.g1_a.clone(),
            gt_alpha_a: gt_a_t * privkey.alpha.clone(),
        };

        (pubkey, privkey)
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
