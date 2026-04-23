//! StateTree insertion + proof-generation throughput.

use codex_core::namespace::Namespace;
use codex_crypto::Blake3Hasher;
use codex_state::StateTree;
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

fn key(tag: u64) -> [u8; 32] {
    let mut h = Blake3Hasher::new();
    h.update(&tag.to_le_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

fn populate(n: u64) -> StateTree {
    let ns = Namespace::new("bench.ns").unwrap();
    let mut t = StateTree::new();
    for i in 0..n {
        t.insert(ns.clone(), key(i), b"v".to_vec());
    }
    t
}

fn bench_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_insert");
    for n in [100u64, 1_000, 10_000] {
        group.bench_with_input(BenchmarkId::from_parameter(n), &n, |b, &n| {
            b.iter(|| {
                let _ = populate(n);
            });
        });
    }
    group.finish();
}

fn bench_existence_proof(c: &mut Criterion) {
    let mut group = c.benchmark_group("state_existence_proof");
    for n in [1_000u64, 10_000] {
        let t = populate(n);
        let ns = Namespace::new("bench.ns").unwrap();
        let k = key(n / 2);
        group.bench_with_input(BenchmarkId::from_parameter(n), &k, |b, _| {
            b.iter(|| {
                let _ = t.existence_proof(&ns, &k).unwrap();
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_insert, bench_existence_proof);
criterion_main!(benches);
