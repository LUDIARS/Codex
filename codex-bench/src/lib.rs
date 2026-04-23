//! Benchmarks for Codex.
//!
//! Run with `cargo bench -p codex-bench`. Criterion drops HTML reports
//! into `target/criterion`. Used to validate the M1 numeric targets
//! (SPV verify ≤ 20 ms on ARMv7, merkle compute throughput) and to
//! track regressions.

// Intentionally empty — all benchmark code lives in `benches/`.
