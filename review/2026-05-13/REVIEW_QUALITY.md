# 品質レビュー — Codex

**評価: A**

## CI / lint

- **CI ジョブ 5 種**: test (Ubuntu/Windows/macOS) / fmt / clippy / bench-compile / demo (`.github/workflows/ci.yml:16-72`)。 `RUSTFLAGS: -D warnings` + clippy `-D warnings` で 警告 = エラー扱い。 demo は `timeout-minutes: 3` で実走 sanity を担保。
- **permissions: contents: read** が宣言済 (`.github/workflows/ci.yml:9-11`)。 最小権限の徹底は他 LUDIARS リポより一歩前。
- `rust-cache@v2` 投入で各 job キャッシュ済、 OS マトリクス並走でも待ち時間が短い。

## テスト密度

- **unit test カバレッジ**: 7 crate × 各 src/*.rs 末尾 `mod tests` で 100+ assertions。
  - `codex-crypto`: PeerId 不変性 / hex round-trip / domain tag 不重複 / postcard serde round-trip
  - `codex-core`: Event sign↔verify / 改竄検出 / serde compact 64-byte sig
  - `codex-state`: merkle 多 sizes (1/2/3/4/5/7/8/15/16/17/33 leaves) / proof tamper detection / world-first 強制 / atomic rollback
  - `codex-consensus`: equivocation true/false 系 / committee size guard / staged changes mature ordering
- **integration test**: `codex-consensus/tests/{committee_flow,session}.rs`, `codex-node/tests/pipeline.rs`, `codex-light/tests/spv.rs`, `codex-sync/tests/two_node_sync.rs`。 sync 系まで揃う。
- **bench**: `codex-bench/benches/{merkle,signing,state_tree}.rs` (criterion)。 CI は `--no-run` で compile-check のみ、 regression tracking 自動化は未設定。

## コードベース衛生

- **doc コメント密度が高い**。 各 module 先頭に `# Design references` で `docs/DESIGN.md §X.Y` を参照、 実装意図がコード単独で読める。 例: `codex-state/src/proof.rs:1-19` の adjacency 保証の説明、 `codex-state/src/state.rs:1-12` の v0 limitation 自覚。
- **エラー型が thiserror**。 `LightError` (`codex-light/src/lib.rs:29-51`)、 `NamespaceError` (`codex-core/src/namespace.rs:86-100`)、 `ProofError` 等。 panic-free path が原則、 expect/unwrap は dry-run 後の正当化込み。
- **`no_std` 互換志向**。 `codex-crypto/src/lib.rs:14` で `use core::fmt`、 ただし `std::error::Error` 実装 (`:148`) と `hex::encode` が std 依存で純 no_std には未到達。 README §設計目標 6 と実装の差分は微小。
- **panic 箇所が限定**。 grep 不要のレベルで `expect()` は dry-run 整合性に基づく invariant ("nonce just verified fresh", "handler existence verified") のみ。

## 弱み

- **README ステータスが古い** (`README.md:39-42` で「設計段階」「初稿 DESIGN 版 0.1」、 現状は DESIGN 0.10 + M0-M9 merge 済)。 ドキュメンテーション更新漏れ。
- **CLAUDE.md 不在**。 他 LUDIARS リポでは CLAUDE.md にエージェント向けガイドを置くが Codex には無い。 自動レビューや /impl コマンドの取っ掛かりが乏しい。
- **`codex-net/src/wire.rs` の wire schema が clippy 通過のみ**。 binary format の versioning / forward-compat policy がコメント化されていない。
- **fuzz harness 未配置**。 DESIGN §13 で `cargo-fuzz` を計画するが `fuzz/` ディレクトリ無し。 Event decode / merkle proof verify は ad-hoc test に頼る。

## file:line 索引

- CI 全体: `.github/workflows/ci.yml:1-72`
- README ステータス: `README.md:39-42`
- doc コメント例: `codex-state/src/merkle.rs:1-19`, `codex-state/src/proof.rs:1-19`
- panic invariant: `codex-state/src/stf.rs:194`, `codex-state/src/stf.rs:201`
