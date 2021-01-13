//! Decentralized inner-product predicate encryption.
//!
//! This PE scheme is an implementation of DIPPE, an IPPE based scheme by
//! [Yan Michalevsky and Marc Joye, 2018](https://eprint.iacr.org/2018/753).
//!
//! This predicate encryption scheme allows a user to decrypt a ciphertext when their attribute
//! vector *v* is orthogonal to the predicate vector *x*, i.e. their *inner product* equals zero.
//!
//! The paper suggests several applications of this idea.
//! Currently, only the conjunction policy is implemented, although the vectors can also be
//! manually constructed.
//! The conjunction policy allows Carol to decrypt a message when her [`UserPrivateKey`] consists
//! of a superset of the [`CipherText`]'s [`AttributeVector`].
//! For example, if Carol has the attributes `[0, 1, 3, 4]`, she can decrypt a cipher text that has
//! been encrypted with `[0, 3, 4]`, but not one encrypted with `[0, 2, 4]`.
//!
//! # Usage
//!
//! In general, using the scheme consists of the following steps:
//! 1. **Setup**: Generate either a randomized [`Dippe`] through [`Dippe::randomized`], or a
//!    deterministic one based on a public common reference string through [`Dippe::new`].
//!    This is the global system setup for your application.
//!
//!    These methods also require to choose the security parameter *k* for the *k*-lin assumption.
//!
//! 2. **Generate authority keys**: Generate authority keys for all authorities that will hand out
//!    attributes to end users.
//!
//!    For every authority, call [`Dippe::generate_key_pair`].  The resulting  public keys are used
//!    for encryption against a policy, the private keys are used to generate [`UserPrivateKey`]s.
//!
//!    From here, encryption and user key generation can be done concurrently, as long as the
//!    set of attributes stays the same.
//!
//! 3. **Generate user keys**: as an authority use [`Dippe::generate_user_private_key_part`] for
//!    every attribute that the authority hands out.
//!    The authorities return the generated keys to the respective users.
//!
//!    **Encrypt**: Use [`Dippe::encrypt`] to produce a [`CipherText`] from a [`rabe_bn::Gt`] plain
//!    text.  This method requires passing the authority public keys together with the
//!    [`PolicyVector`] policy.
//!
//!    **Decrypt**: Constructed from an iterator of [`UserPrivateKeyPart`]s, the holder of the
//!    [`UserPrivateKey`] can use the [`Dippe::decrypt`] method to recover the original [`rabe_bn::Gt`]
//!    element.
//!
//! # Example with conjunctive attribute policy
//!
//! ```rust
//! use std::convert::TryFrom;
//!
//! use cife_rs::abe::dippe::*;
//! use rabe_bn::Gt;
//!
//! let mut rng = rand::thread_rng();
//! let dippe = Dippe::new(b"my application name", 2);
//!
//! // We declare two authorities.
//! // Alice will be responsible for the even-indexed attributes,
//! // while Bob takes care of the odd-indexed attributes.
//! let (alice_pub, alice_priv) = dippe.generate_key_pair(&mut rng);
//! let (bob_pub, bob_priv) = dippe.generate_key_pair(&mut rng);
//!
//! // Our system has five attributes, numbered 0 through 4
//! let attributes = 5;
//! // The attribute vector, in fact an implementation detail, is one element longer than the
//! // attribute count.
//! let vec_len = attributes + 1;
//!
//! // Carol will request attributes 0, 1, 3 and 4.
//! let carol_policy = &[0, 1, 3, 4];
//!
//! // We encrypt with this, and try carol will attempt the decryption.
//! // As you may notice, [0, 1, 4] is a subset of Carol's policy vector.
//! // Since we encrypt with the *conjunction* policy, this means that Carol will be able to
//! // decrypt, as long as her policy vector is indeed a superset of the conjunction policy.
//! let encryption_policy = dippe.create_conjunction_policy_vector(&mut rng, attributes, &[0, 1, 4]);
//!
//! // These arrays define what attributes are "owned"/attributed by what authorities.
//! // In this example, even attributes are handed out by Alice, uneven by Bob.
//! let pks = [
//!     &alice_pub, &bob_pub, &alice_pub, &bob_pub, &alice_pub, &bob_pub,
//! ];
//! let priv_keys = [
//!     &alice_priv,
//!     &bob_priv,
//!     &alice_priv,
//!     &bob_priv,
//!     &alice_priv,
//!     &bob_priv,
//! ];
//!
//! // The message that we send is very simple: it's the number 1.
//! let msg = Gt::one();
//! // Encrypt yields a `CipherText` object, which implements serde's traits for easy transport.
//! let ciphertext = dippe.encrypt(&mut rng, &encryption_policy, msg, &pks);
//! let ciphertext_serialized = serde_json::to_string(&ciphertext).expect("serialized json");
//!
//! // Now, Carol will request her private key.
//! // She needs to talk with every authority, and request a KeyPart for every attribute.
//! let mut usks = Vec::with_capacity(vec_len);
//! let user_policy = dippe.create_attribute_vector(attributes, carol_policy);
//! let gid = b"Carol";
//! for j in 0..vec_len {
//!     usks.push(dippe.generate_user_private_key_part(
//!         priv_keys[j],
//!         j,
//!         &pks,
//!         gid,
//!         &user_policy,
//!     ));
//! }
//! // After having requested all the KeyParts (those requests can be batched!), she needs to
//! // aggregate them into a `UserPrivateKey` for use in decryption.
//! let upk: Result<UserPrivateKeySlice, _> = usks.into_iter().collect();
//! let upk = UserPrivateKey::try_from(upk.unwrap()).unwrap();
//!
//! // Finally, Carol can deserialize and decrypt the ciphertext.
//! let ciphertext = serde_json::from_str(&ciphertext_serialized).expect("correct json");
//! let recovered = dippe.decrypt(&upk, ciphertext, &user_policy, gid);
//! assert_eq!(Vec::<u8>::from(recovered), Vec::from(msg));
//! ```

use std::fmt;

use crate::mat::*;

use bitvec::prelude::*;
use rabe_bn::*;
use rand::prelude::*;
use sha2::{Digest, Sha256};

/// Dippe system parameters
///
/// For usage and example code, see the [`dippe`][crate::abe::dippe] module-level documentation.
#[derive(serde::Deserialize, serde::Serialize)]
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
#[derive(Clone, serde::Deserialize, serde::Serialize)]
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
#[derive(Clone, serde::Deserialize, serde::Serialize)]
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
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyVector(pub FrVector);

impl PolicyVector {
    pub fn len(&self) -> usize {
        assert_eq!(self.0.dims().1, 1, "PolicyVector is not a vector");
        self.0.dims().0
    }
}

/// An attribute vector used to decrypt.
///
/// An `AttributeVector` can be created manually, or through the method provided by [`Dippe`]:
/// - [`Dippe::create_attribute_vector`] to require conjunction of attributes,
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct AttributeVector(pub FrVector);

impl AttributeVector {
    pub fn len(&self) -> usize {
        assert_eq!(self.0.dims().1, 1, "AttributeVector is not a vector");
        self.0.dims().0
    }
}

impl fmt::Display for AttributeVector {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        for _i in 0..self.len() {
            write!(f, "XXX ")?;
        }
        Ok(())
    }
}

/// A partial decryption key, issued by an authority, for one single attribute.
///
/// Internally, this consists of a group vector and the index of the attribute this
/// slice corresponds to.
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct UserPrivateKeyPart {
    inner: G2Vector,
    idx: usize,
    attrs: usize,
}

impl UserPrivateKeyPart {
    #[doc(hidden)]
    // Method for doc test, k=2
    pub fn new_ones(idx: usize, attrs: usize) -> Self {
        UserPrivateKeyPart {
            inner: G2Vector::ones(2, 1),
            idx,
            attrs,
        }
    }
}

/// A composition of [`UserPrivateKeyPart`]s.
///
/// When the KeySlice is complete ([`UserPrivateKeySlice::is_complete`]), it can be converted via
/// `try_from` to a [`UserPrivateKey`] and ultimately be used in [`Dippe::decrypt`] decryption
/// operations.
///
/// # Example
///
/// ```rust
/// # use cife_rs::abe::dippe::*;
/// use std::convert::TryFrom;
/// let part1: UserPrivateKeyPart /* retrieve from authority */;
/// let part2: UserPrivateKeyPart /* retrieve from (possibly different) authority */;
/// # let part1 = UserPrivateKeyPart::new_ones(0, 2);
/// # let part2 = UserPrivateKeyPart::new_ones(1, 2);
/// let parts = vec![part1, part2];
/// let collection: Result<UserPrivateKeySlice, _> = parts.into_iter().collect();
/// let collection = collection.expect("distinct and compatible key parts");
/// let private_key = UserPrivateKey::try_from(collection).expect("complete key");
/// ```
#[derive(Clone)]
pub struct UserPrivateKeySlice {
    sum: G2Vector,
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
#[derive(Clone, serde::Deserialize, serde::Serialize)]
pub struct UserPrivateKey(G2Vector);

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
                let dims = part.inner.dims();
                upks = Some(UserPrivateKeySlice {
                    sum: G2Vector::zeroes(dims.0, dims.1),
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
            // XXX should be move-out-move-in, possibly abusing the Option.
            upks.sum = upks.sum.clone() + part.inner;
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
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct CipherText {
    c0: G1Vector,
    ci: G1Matrix,
    c_prime: Gt,
}

impl Dippe {
    /// Constructs a new random DIPPE system
    pub fn randomized<R: CryptoRng + RngCore>(rand: &mut R, assumption_size: usize) -> Self {
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

    /// Deterministally constructs a DIPPE system based on a seed.
    ///
    /// ```rust
    /// # use cife_rs::abe::dippe::Dippe;
    /// let dippe = Dippe::new(b"my application name", 2);
    ///
    /// // ... and on another system, the same seed always yields the same system parameters.
    /// let dippe2 = Dippe::new(b"my application name", 2);
    /// ```
    pub fn new(seed: &[u8], assumption_size: usize) -> Self {
        use tiny_keccak::{Hasher, Xof};

        let mut shake = tiny_keccak::Shake::v256();
        shake.update(seed);

        let mut a = FrMatrix::zeroes(assumption_size + 1, assumption_size);

        let mut buf = [0u8; 64];
        for i in 0..a.dims().0 {
            for j in 0..a.dims().1 {
                shake.squeeze(&mut buf);
                a[(i, j)] = Fr::interpret(&buf);
            }
        }

        let mut ut = FrMatrix::zeroes(assumption_size + 1, assumption_size + 1);

        for i in 0..ut.dims().0 {
            for j in 0..ut.dims().1 {
                shake.squeeze(&mut buf);
                ut[(i, j)] = Fr::interpret(&buf);
            }
        }

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

    /// Defines the attribute vector for key generation.
    pub fn create_attribute_vector(
        &self,
        attribute_count: usize,
        pattern: &[usize],
    ) -> AttributeVector {
        let mut result = FrVector::zeroes(attribute_count + 1, 1);
        for &el in pattern {
            assert!(el < attribute_count);
            result[el] = Fr::one();
        }

        result[attribute_count] = Fr::one();

        AttributeVector(result)
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
    /// generates a [`UserPrivateKeyPart`] for a specific set of attributes.
    pub fn generate_user_private_key_part(
        &self,
        private_authority_key: &PrivateKey,
        authority_index: usize,
        authorities: &[&PublicKey],
        gid: &[u8],
        av: &AttributeVector,
    ) -> UserPrivateKeyPart {
        assert!(av.len() == authorities.len());
        assert!(authority_index < authorities.len());
        let av_str = av.to_string();

        let mut µ = G2Vector::zeroes(self.assumption_size + 1, 1);

        for j in 0..authorities.len() {
            let mut yσ = authorities[j].g2_sigma.clone() * private_authority_key.sigma.clone();
            yσ.normalize();
            // XXX cifer uses hex encoding of the reduced x and y coordinates, cfr. ECP2_BN254_toOctet
            let yσ = serde_json::to_string(&yσ).expect("serialized G2 point");

            for i in 0..(self.assumption_size + 1) {
                let mut hash = Sha256::new();
                hash.update(i.to_string());
                hash.update("|");
                hash.update(&yσ);
                hash.update("|");
                hash.update(gid);
                hash.update("|");
                hash.update(&av_str);

                if j < authority_index {
                    µ[i] = µ[i] + G2::hash_to_group(hash);
                } else if j > authority_index {
                    µ[i] = µ[i] - G2::hash_to_group(hash);
                }
            }
        }

        // g2^h (k+1 x 1)
        let mut g2_h = G2Vector::zeroes(self.assumption_size + 1, 1);
        for i in 0..(self.assumption_size + 1) {
            let mut hash = Sha256::new();
            hash.update(i.to_string());
            hash.update("|");
            hash.update(gid);
            hash.update("|");
            hash.update(&av_str);

            g2_h[i] = G2::hash_to_group(hash);
        }

        let mut k_i = G2Vector::zeroes(self.assumption_size + 1, 1);
        for i in 0..(self.assumption_size + 1) {
            for k in 0..(self.assumption_size + 1) {
                k_i[i] = k_i[i] + g2_h[k] * private_authority_key.w[(i, k)].clone();
            }
            // add vi
            k_i[i] = k_i[i] * av.0[authority_index];
            // negate
            k_i[i] = -k_i[i];
            // add alpha
            k_i[i] = k_i[i] + G2::one() * private_authority_key.alpha[i];
            // add mue
            k_i[i] = k_i[i] + µ[i];
        }

        UserPrivateKeyPart {
            inner: k_i,
            idx: authority_index,
            attrs: authorities.len(),
        }
    }

    /// Decrypt a given Ciphertext
    // XXX consider moving the AV in the UPK,
    //     this gives extra insurance over the |upk| shares.
    pub fn decrypt(
        &self,
        upk: &UserPrivateKey,
        c: CipherText,
        av: &AttributeVector,
        gid: &[u8],
    ) -> Gt {
        let av_str = av.to_string();

        // c0_k
        let mut c0_k = Gt::one();
        for i in 0..(self.assumption_size + 1) {
            c0_k = c0_k * pairing(c.c0[i], upk.0[i]);
        }

        // ci_H
        let mut ci_h = Gt::one();
        for i in 0..(self.assumption_size + 1) {
            let mut ci_vi = G1::zero();
            for j in 0..av.len() {
                ci_vi = ci_vi + c.ci[(j, i)] * av.0[j];
            }
            let mut hash = Sha256::new();
            hash.update(i.to_string());
            hash.update("|");
            hash.update(gid);
            hash.update("|");
            hash.update(&av_str);

            let g2_h = G2::hash_to_group(hash);
            ci_h = ci_h * pairing(ci_vi, g2_h);
        }

        c.c_prime * (c0_k * ci_h).inverse()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::convert::TryFrom;

    #[test]
    fn deterministic_dippe_domain_separation() {
        let dippe1 = Dippe::new(b"foo bar", 2);
        let dippe2 = Dippe::new(b"foo bat", 2);

        for i in 0..dippe1.g1_ua.dims().0 {
            for j in 0..dippe1.g1_ua.dims().1 {
                assert!(dippe1.g1_ua[(i, j)] != dippe2.g1_ua[(i, j)]);
            }
        }

        for i in 0..dippe1.g1_a.dims().0 {
            for j in 0..dippe1.g1_a.dims().1 {
                assert!(dippe1.g1_a[(i, j)] != dippe2.g1_a[(i, j)]);
            }
        }
    }

    #[test]
    fn generate_dippe_conjunction_policy() {
        let mut rng = rand::thread_rng();
        let rng = &mut rng;

        let d = Dippe::randomized(rng, 2);

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

        let d = Dippe::randomized(rng, 2);

        let attr_num = 4;
        let _ = d.create_conjunction_policy_vector(rng, attr_num, &[7]);
    }

    #[test]
    fn key_parts() {
        let part1 = UserPrivateKeyPart {
            inner: G2Vector::ones(2, 1),
            idx: 0,
            attrs: 3,
        };
        let part2 = UserPrivateKeyPart {
            inner: G2Vector::ones(2, 1),
            idx: 1,
            attrs: 3,
        };
        let part3 = UserPrivateKeyPart {
            inner: G2Vector::ones(2, 1),
            idx: 2,
            attrs: 3,
        };
        let partx = UserPrivateKeyPart {
            inner: G2Vector::ones(2, 1),
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

    #[test]
    fn conjunction_policy_vector_inner_products() {
        let attribs = 5;
        let policy = &[0, 1, 4];
        let users: &[(&[usize], bool)] = &[
            (&[0, 1, 3, 4], true),    // "11011" - valid
            (&[0, 1, 2, 3, 4], true), // "11111" - valid
            (&[1, 4], false),         // "01001" - invalid
            (&[0, 1, 3], false),      // "11010" - invalid
        ];

        let mut rng = rand::thread_rng();
        let rng = &mut rng;

        let d = Dippe::randomized(rng, 2);

        let pv = d.create_conjunction_policy_vector(rng, attribs, policy);

        for &(user, valid) in users {
            let pv = pv.clone();
            let av = d.create_attribute_vector(attribs, user);
            assert_eq!(av.0.dims(), pv.0.dims());
            assert_eq!(av.0.dims(), (attribs + 1, 1));

            let ip = av.0.transposed() * pv.0;
            assert_eq!(ip.dims(), (1, 1));
            if valid {
                assert!(ip[0].is_zero());
            } else {
                assert!(!ip[0].is_zero());
            }
        }
    }
}
