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
/// A key-pair is generated with [`Dippe::generate_key_pair`]
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
/// A key-pair is generated with [`Dippe::generate_key_pair`]
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

/// A policy vector used to encrypt.
///
/// A `PolicyVector` can be created manually, or through the methods provided by [`Dippe`], one of:
/// - [`Dippe::create_conjunction_policy_vector`] to require conjunction of attributes,
pub struct PolicyVector(pub FrVector);

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

    /// Creates a [`PolicyVector`] based on a conjunction policy of attributes.
    ///
    /// A message encrypted with the resulting [`PolicyVector`] will be decryptable if the decryptor
    /// has *all* the attributes passed as `pattern` to this method.
    pub fn create_conjunction_policy_vector<R: CryptoRng + RngCore>(
        &self,
        rand: &mut R,
        attribute_count: usize,
        pattern: &[usize],
    ) -> PolicyVector {
        let mut result = FrVector::zeroes(attribute_count + 1, 1);

        for &el in pattern {
            assert!(
                el < attribute_count,
                "Attribute in pattern larger than attribute count."
            );

            result[el] = rand.gen();
            result[attribute_count] = result[attribute_count] - result[el];
        }

        PolicyVector(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_dippe_conjunction_policy() {
        let mut rng = rand::thread_rng();
        let rng = &mut rng;

        let d = Dippe::new(rng, 2);

        let attr_num = 4;

        let policies: &[&[usize]] = &[&[], &[1, 2]];

        for policy_template in policies {
            let pol = d.create_conjunction_policy_vector(rng, attr_num, policy_template);

            assert_eq!(pol.0.dims(), (attr_num + 1, 1));

            let mut sum = Fr::zero();
            for el in &pol.0 {
                sum = sum + el.clone();
            }
            assert!(sum.is_zero());
        }
    }

    #[test]
    #[should_panic]
    fn generate_invalid_dippe_conjunction_policy() {
        let mut rng = rand::thread_rng();
        let rng = &mut rng;

        let d = Dippe::new(rng, 2);

        let attr_num = 4;
        let _ = d.create_conjunction_policy_vector(rng, attr_num, &[7]);
    }
}
