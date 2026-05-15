# Codex レビュー総括 — 2026-05-13

- 対象: `E:/Document/Ars/Codex` (commit `59114a9`)
- レビュア: 自動レビュー (LUDIARS/Codex)
- 背景: Ethereum-like 検証台帳。 PoA + light client + namespace handler が骨格。 M0–M9 まで一通り着地、初稿 DESIGN 0.10 と整合した実装が `codex-core` から `codex-ffi` まで揃っている。

## 評価サマリ

| カテゴリ | 評価 | 一言 |
|---|---|---|
| 設計 | **A** | DESIGN 0.10 と実装の対応が緊密、Ethereum からの取捨選択が一貫 |
| 脆弱性 | **B** | 署名 / nonce / 同名 chain / equivocation の基本は固い。 残ハザードは light client checkpoint 信頼 + namespace serde |
| 実装 | **B** | rust-idiomatic、 STF が atomic rollback で良好。 一部 `clone()` 多用と nonce 無制限成長が将来の負債 |
| 不足機能 | **C** | codex-net / codex-rpc / codex-cli が未着手、`codex.system` event は schema のみ。 §15 既知の未決を踏襲 |
| 品質 | **A** | CI 3 OS + clippy `-D warnings` + bench-compile + fmt、テスト密度高い (`world_first_is_enforced` 等の意図テスト充実) |

**weighted_score: 81 / 100** (A=90, B=78, B=78, C=65, A=92 を 設計 25% / 脆弱性 25% / 実装 20% / 不足 15% / 品質 15% で加重)

## 主要所見

1. **設計と実装の整合性が異常に高い**。 DESIGN §5.4.3 の `state_root_commit(count, root)` まで実装されており、 leaf-count を root にバインドして adjacency 詐称を塞ぐ防衛 (`codex-state/src/merkle.rs:40`) は他 LUDIARS リポより一歩進んだ品質。
2. **PoA 信頼境界** が薄い。 `LightClient::new` (`codex-light/src/lib.rs:62`) は `ProducerAuthority` を渡されるだけで、genesis trust / checkpoint rotation / 複数 full node からの cross-check (DESIGN §8.4) は未実装。
3. **NonceTracker が無制限 HashMap**。 `codex-state/src/nonce.rs:22` は `HashMap<(PeerId, Namespace), HashSet<u64>>` を full-history 保持し、 §5.7 pruning なし。 10⁸ scale 想定では実運用前にビットセット圧縮 / persistence への対応必須。
4. **`Namespace` の serde 非validate**: `codex-core/src/namespace.rs:198` でテストが「deserialize 時 validation 通らない」と明示。 wire 入力経路では STF 経由で検証されるが、 raw deserialization で `codex.system.*` 偽装 namespace が流入可能 (現状は §5.6.3 で event 受理拒否、 ただし v1+ 注意点)。
5. **`codex-net` / `codex-rpc` / `codex-cli` 未実装** が最大の残骸。 M0–M9 はコアアルゴリズムまでで、 ネットワーク I/O が `codex-sync` 内 transport 抽象で代用されている (実 QUIC 未配線)。

詳細は同階層の `REVIEW_DESIGN.md` / `REVIEW_VULNERABILITY.md` / `REVIEW_IMPLEMENTATION.md` / `REVIEW_MISSING_FEATURES.md` / `REVIEW_QUALITY.md` を参照。
