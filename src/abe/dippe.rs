//! Decentralized inner-product predicate encryption.

use std::fmt;

use crate::mat::*;

use bitvec::prelude::*;
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

impl PolicyVector {
    pub fn len(&self) -> usize {
        assert_eq!(self.0.dims().1, 1, "PolicyVector is not a vector");
        self.0.dims().0
    }
}

/// A slice of a decryption key, issued by an authority.
///
/// Internally, this consists of a key slice group element and the index of the attribute this
/// slice corresponds to.
#[derive(Clone)]
pub struct UserPrivateKeyPart {
    inner: G2,
    idx: usize,
    attrs: usize,
}

///
#[derive(Clone)]
pub struct UserPrivateKeySlice {
    sum: G2,
    missing: BitVec,
}

impl UserPrivateKeySlice {
    pub fn is_complete(&self) -> bool {
        !self.missing.any()
    }

    pub fn missing(&self) -> Vec<usize> {
        let mut missing = vec![];
        for (i, bit) in self.missing.iter().enumerate() {
            if *bit {
                missing.push(i);
            }
        }
        missing
    }
}

/// A slice of a decryption key, issued by an authority.
#[derive(Clone)]
pub struct UserPrivateKey(G2);

impl core::iter::FromIterator<UserPrivateKeyPart> for Result<UserPrivateKeySlice, anyhow::Error> {
    fn from_iter<T>(parts: T) -> Result<UserPrivateKeySlice, anyhow::Error>
    where
        T: IntoIterator<Item = UserPrivateKeyPart>,
    {
        let mut upks = None;

        for part in parts {
            let upks = if let Some(upks) = upks.as_mut() {
                upks
            } else {
                upks = Some(UserPrivateKeySlice {
                    sum: G2::zero(),
                    missing: bitvec!(1; part.attrs),
                });
                upks.as_mut().unwrap()
            };

            if part.attrs != upks.missing.len() {
                return Err(anyhow::anyhow!(
                    "Key parts with distinct attribute set sizes"
                ));
            }

            if !upks.missing[part.idx] {
                return Err(anyhow::anyhow!(
                    "Overlapping key parts at attribute {}",
                    part.idx
                ));
            }

            *upks.missing.get_mut(part.idx).unwrap() = false;
            upks.sum = upks.sum + part.inner;
        }

        upks.ok_or(anyhow::anyhow!("no parts in iterator"))
    }
}

impl std::convert::TryFrom<UserPrivateKeySlice> for UserPrivateKey {
    type Error = anyhow::Error;

    fn try_from(upks: UserPrivateKeySlice) -> Result<UserPrivateKey, Self::Error> {
        if upks.is_complete() {
            Ok(UserPrivateKey(upks.sum))
        } else {
            let missing = upks.missing();
            Err(anyhow::anyhow!(
                "incomplete UserPrivateKeySlice: missing {:?}",
                missing
            ))
        }
    }
}

/// A CipherText bound, used to encrypt against said policy.
///
/// The `CipherText` is constructed from [`Dippe::encrypt`]
pub struct CipherText {
    c0: G1Vector,
    ci: G1Matrix,
    c_prime: Gt,
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

    /// Creates the `msg` with a given [`PolicyVector`].
    pub fn encrypt<R: CryptoRng + RngCore>(
        &self,
        rng: &mut R,
        policy: &PolicyVector,
        msg: Gt,
        authorities: &[&PublicKey],
    ) -> CipherText {
        assert_eq!(
            policy.len(),
            authorities.len(),
            "matching authorities and policies"
        );

        let mut ci = G1Matrix::zeroes(policy.0.dims().0, self.assumption_size + 1);

        let s = FrVector::from_random(rng, self.assumption_size, 1);

        // fe_mat_G1_mul_vec(&(cipher->C0), &(dippe->g1_A), &s);
        let c0 = self.g1_a.clone() * s.clone();
        assert_eq!(c0.dims(), (self.assumption_size + 1, 1));

        for (m, (&authority, &policy_x)) in authorities.iter().zip(&policy.0).enumerate() {
            let g1_was = authority.g1_w_a.clone() * s.clone();

            let mut g1_x_ua_s = G1Vector::zeroes(self.assumption_size + 1, 1);

            for i in 0..(self.assumption_size + 1) {
                for k in 0..self.assumption_size {
                    g1_x_ua_s[i] = g1_x_ua_s[i] + self.g1_ua[(i, k)].clone() * s[k].clone();
                }
                g1_x_ua_s[i] = g1_x_ua_s[i] * policy_x;
            }

            for i in 0..(self.assumption_size + 1) {
                ci[(m, i)] = g1_x_ua_s[i];
                ci[(m, i)] = ci[(m, i)] + g1_was[i];
            }
        }

        let mut c_prime = Gt::one();
        for authority in authorities {
            for k in 0..self.assumption_size {
                c_prime = c_prime * authority.gt_alpha_a[k].clone().pow(s[k]);
            }
        }

        c_prime = c_prime * msg;

        CipherText { c0, ci, c_prime }
    }

    /// Given the set of *all* authorities and one secret authority key,
    pub fn generate_user_private_key_part(
        &self,
        private_authority_key: PrivateKey,
        authorities: &[PublicKey],
        pv: PolicyVector,
    ) -> UserPrivateKeyPart {
        todo!()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::TryFrom;

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

    #[test]
    fn key_parts() {
        let part1 = UserPrivateKeyPart {
            inner: G2::one(),
            idx: 0,
            attrs: 3,
        };
        let part2 = UserPrivateKeyPart {
            inner: G2::one(),
            idx: 1,
            attrs: 3,
        };
        let part3 = UserPrivateKeyPart {
            inner: G2::one(),
            idx: 2,
            attrs: 3,
        };
        let partx = UserPrivateKeyPart {
            inner: G2::one(),
            idx: 5,
            attrs: 6,
        };

        // parts, can_collect, is_complete
        let part_tests = vec![
            // tests collectable but not finishable.
            (vec![part1.clone(), part3.clone()], true, false),
            (vec![part1.clone(), part2.clone()], true, false),
            (vec![part1.clone(), part2.clone()], true, false),
            // tests overlap
            (vec![part2.clone(), part2.clone()], false, false),
            // Distinct set sizes
            (vec![part2.clone(), partx.clone()], false, false),
            // no parts -> not collectable
            (vec![], false, false),
            // test complete key
            (
                vec![part2.clone(), part1.clone(), part3.clone()],
                true,
                true,
            ),
            // Finally something that should work.
            (vec![part1, part2, part3], true, true),
        ];

        for (i, (parts, collectable, is_complete)) in part_tests.into_iter().enumerate() {
            let collection: Result<UserPrivateKeySlice, _> = parts.into_iter().collect();
            let collection = match collection {
                Ok(collection) => {
                    assert!(
                        collectable,
                        "Test {} is not collectable but expected collectable.",
                        i
                    );
                    collection
                }
                Err(err) => {
                    assert!(!collectable, "Test {}: {}", i, err);
                    continue;
                }
            };
            let upk: Result<UserPrivateKey, _> = UserPrivateKey::try_from(collection.clone());
            let _upk = if let Ok(upk) = upk {
                assert!(is_complete);
                assert!(collection.missing().is_empty());
                upk
            } else {
                assert!(!is_complete);
                assert!(!collection.missing().is_empty());
                continue;
            };
        }
    }
}
