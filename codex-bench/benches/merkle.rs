//! Merkle compute / proof benchmarks.
//!
//! Validates §3 light-client verify target (≤ 20 ms ARMv7). On a dev
//! machine we expect fold_path on 2^20 leaves to run in microseconds.

use codex_state::merkle::{compute_root, compute_siblings, fold_path, node_hash};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};

fn random_leaves(n: usize) -> Vec<[u8; 32]> {
    (0..n)
        .map(|i| {
            let mut h = [0u8; 32];
            // Deterministic but non-trivial leaf content: blake3 of index.
            let hh = codex_crypto::Blake3Hasher::new()
                .update(&(i as u64).to_le_bytes())
                .finalize();
            h.copy_from_slice(hh.as_bytes());
            h
        })
        .collect()
}

fn bench_compute_root(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_compute_root");
    for n in [100usize, 1_000, 10_000] {
        let leaves = random_leaves(n);
        group.bench_with_input(BenchmarkId::from_parameter(n), &leaves, |b, l| {
            b.iter(|| {
                let _ = compute_root(l);
            });
        });
    }
    group.finish();
}

fn bench_proof_fold(c: &mut Criterion) {
    let mut group = c.benchmark_group("merkle_fold_path");
    for n in [1_000usize, 10_000, 100_000] {
        let leaves = random_leaves(n);
        let idx = n / 2;
        let siblings = compute_siblings(&leaves, idx).unwrap();
        let leaf = leaves[idx];
        group.bench_with_input(BenchmarkId::from_parameter(n), &siblings, |b, s| {
            b.iter(|| {
                let _ = fold_path(leaf, s);
            });
        });
    }
    group.finish();
}

fn bench_node_hash(c: &mut Criterion) {
    c.bench_function("merkle_node_hash", |b| {
        let l = [0xabu8; 32];
        let r = [0xcdu8; 32];
        b.iter(|| node_hash(&l, &r));
    });
}

criterion_group!(
    benches,
    bench_compute_root,
    bench_proof_fold,
    bench_node_hash
);
criterion_main!(benches);
