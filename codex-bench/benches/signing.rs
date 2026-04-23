//! Event signing + verification throughput.
//!
//! Validates §3 goal: full node sustained ≥ 1000 evt/s signing and
//! verification. Targets single-thread on commodity CPU.

use codex_core::event::EventPayload;
use codex_core::namespace::Namespace;
use codex_crypto::{PeerId, SigningKey};
use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand_core::OsRng;

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_sign");
    for body_len in [0usize, 64, 256, 4096] {
        group.bench_with_input(BenchmarkId::from_parameter(body_len), &body_len, |b, &n| {
            let sk = SigningKey::generate(&mut OsRng);
            let peer = PeerId::from_verifying_key(&sk.verifying_key());
            let body = vec![0xabu8; n];
            let payload = EventPayload {
                version: 1,
                namespace: Namespace::new("bench.ns").unwrap(),
                claimant: peer,
                nonce: 1,
                body,
                timestamp: 1,
            };
            b.iter(|| {
                let _ = payload.clone().sign(&sk);
            });
        });
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("event_verify");
    for body_len in [0usize, 64, 256, 4096] {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        let peer = PeerId::from_verifying_key(&vk);
        let payload = EventPayload {
            version: 1,
            namespace: Namespace::new("bench.ns").unwrap(),
            claimant: peer,
            nonce: 1,
            body: vec![0xcdu8; body_len],
            timestamp: 1,
        };
        let event = payload.sign(&sk);
        group.bench_with_input(BenchmarkId::from_parameter(body_len), &body_len, |b, _| {
            b.iter(|| {
                event.verify_with_key(&vk).unwrap();
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_sign, bench_verify);
criterion_main!(benches);
