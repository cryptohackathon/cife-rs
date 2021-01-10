use cife_rs::abe::dippe::*;
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};

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
}

criterion_group!(dippe, dippe_setup);
criterion_main!(dippe);
