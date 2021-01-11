use cife_rs::abe::dippe::*;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use rabe_bn::*;

fn dippe_setup(c: &mut Criterion) {
    let mut group = c.benchmark_group("Dippe::new");
    for k in [2, 3].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(k), k, |b, &k| {
            let mut rng = rand::thread_rng();
            b.iter(move || black_box(Dippe::new(&mut rng, k)));
        });
    }
    group.finish();

    let mut group = c.benchmark_group("Dippe::generate_key_pair");
    for k in [2, 3].iter() {
        group.bench_with_input(BenchmarkId::from_parameter(k), k, |b, &k| {
            let mut rng = rand::thread_rng();
            let dippe = Dippe::new(&mut rng, k);
            b.iter(move || black_box(dippe.generate_key_pair(&mut rng)));
        });
    }
    group.finish();

    let mut group = c.benchmark_group("Dippe::encrypt");
    for k in [2, 3].iter() {
        for attributes in (2..7).map(|x| 1 << x) {
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("k={}, |attr|={}", k, attributes)),
                k,
                |b, &k| {
                    let mut rng = rand::thread_rng();
                    let dippe = Dippe::new(&mut rng, k);
                    let msg = Gt::one();
                    let (public, _private) = dippe.generate_key_pair(&mut rng);

                    let test_pol_vec =
                        dippe.create_conjunction_policy_vector(&mut rng, attributes, &[0, 1, 3]);

                    let pks: Vec<_> = (0..(attributes + 1)).map(|_| &public).collect();

                    b.iter(move || {
                        black_box(dippe.encrypt(&mut rng, &test_pol_vec, msg.clone(), &pks))
                    });
                },
            );
        }
    }
    group.finish();

    let mut group = c.benchmark_group("Dippe::gen_user_key_share");
    for k in [2, 3].iter() {
        for attributes in (2..6).map(|x| 1 << x) {
            group.bench_with_input(
                BenchmarkId::from_parameter(format!("k={}, |attr|={}", k, attributes)),
                &(*k, attributes),
                |b, &(k, attributes)| {
                    let mut rng = rand::thread_rng();
                    let dippe = Dippe::new(&mut rng, k);
                    let msg = Gt::one();
                    let (public_alice, _private_alice) = dippe.generate_key_pair(&mut rng);
                    let (public_bob, private_bob) = dippe.generate_key_pair(&mut rng);

                    let pks: Vec<_> = (0..(attributes + 1)).map(|_| &public_bob).collect();

                    let carol_attributes = dippe.create_attribute_vector(attributes, &[0, 1, 3]);

                    b.iter(move || {
                        black_box(dippe.generate_user_private_key_part(
                            &private_bob,
                            1,
                            &pks,
                            b"carol",
                            &carol_attributes,
                        ))
                    });
                },
            );
        }
    }
    group.finish();
}

criterion_group!(dippe, dippe_setup);
criterion_main!(dippe);
