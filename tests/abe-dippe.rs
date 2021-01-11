use std::convert::TryFrom;

use cife_rs::abe::dippe::*;
use rabe_bn::*;

#[test]
fn end_to_end_conjunction() {
    let mut rng = rand::thread_rng();
    let dippe = Dippe::new(&mut rng, 2);

    let (alice_pub, alice_priv) = dippe.generate_key_pair(&mut rng);
    let (bob_pub, bob_priv) = dippe.generate_key_pair(&mut rng);

    let attributes = 5;
    let vec_len = attributes + 1;

    let test_policies: &[(&[usize], bool)] = &[
        (&[0, 1, 3, 4], true),    // "11011" - valid
        (&[0, 1, 2, 3, 4], true), // "11111" - valid
        (&[1, 4], false),         // "01001" - invalid
        (&[0, 1, 3], false),      // "11010" - invalid
    ];

    // We encrypt with this, and try decryptions with four users with the above attributes.
    let test_pol_vec = dippe.create_conjunction_policy_vector(&mut rng, attributes, &[0, 1, 4]);

    // These arrays define what attributes are "owned"/attributed by what authorities.
    // In this example, even attributes are handed out by Alice, uneven by Bob.
    let pks = [
        &alice_pub, &bob_pub, &alice_pub, &bob_pub, &alice_pub, &bob_pub,
    ];
    let priv_keys = [
        &alice_priv,
        &bob_priv,
        &alice_priv,
        &bob_priv,
        &alice_priv,
        &bob_priv,
    ];

    assert_eq!(pks.len(), vec_len);
    assert_eq!(test_pol_vec.len(), vec_len);

    let msg = Gt::one();
    let ciphertext = dippe.encrypt(&mut rng, &test_pol_vec, msg, &pks);

    // Every test policy gets a test user
    for (i, &(policy, valid)) in test_policies.into_iter().enumerate() {
        let mut usks = Vec::with_capacity(vec_len);
        let user_policy = dippe.create_attribute_vector(attributes, policy);
        let gid = format!("TESTGID{}", i);
        for j in 0..vec_len {
            usks.push(dippe.generate_user_private_key_part(
                priv_keys[j],
                j,
                &pks,
                gid.as_bytes(),
                &user_policy,
            ));
        }
        let upk: Result<UserPrivateKeySlice, _> = usks.into_iter().collect();
        let upk = UserPrivateKey::try_from(upk.unwrap()).unwrap();

        let recovered = dippe.decrypt(&upk, ciphertext.clone(), &user_policy, gid.as_bytes());

        if valid {
            assert_eq!(Vec::<u8>::from(recovered), Vec::from(msg));
        } else {
            assert_ne!(Vec::<u8>::from(recovered), Vec::from(msg));
        }
    }
}
