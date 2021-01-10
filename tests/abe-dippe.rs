use cife_rs::abe::dippe::*;
use rabe_bn::*;

#[test]
fn end_to_end_conjunction() {
    let mut rng = rand::thread_rng();
    let dippe = Dippe::new(&mut rng, 2);

    let (alice_pub, _alice_priv) = dippe.generate_key_pair(&mut rng);
    let (bob_pub, _bob_priv) = dippe.generate_key_pair(&mut rng);

    let attributes = 5;
    let _vec_len = attributes + 1;

    let test_policies: &[(&[usize], bool)] = &[
        (&[0, 1, 3, 4], true),    // "11011" - valid
        (&[0, 1, 2, 3, 4], true), // "11111" - valid
        (&[1, 4], false),         // "01001" - invalid
        (&[0, 1, 3], false),      // "11010" - invalid
    ];

    let test_pol_vec = dippe.create_conjunction_policy_vector(&mut rng, attributes, &[0, 1, 4]);

    let pks = [
        &alice_pub, &bob_pub, &alice_pub, &bob_pub, &alice_pub, &bob_pub,
    ];
    assert_eq!(pks.len(), _vec_len);
    assert_eq!(test_pol_vec.len(), _vec_len);

    let msg = Gt::one();
    let ciphertext = dippe.encrypt(&mut rng, &test_pol_vec, msg, &pks);
}
