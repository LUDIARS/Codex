# 不足機能レビュー — Codex

**評価: C** (M0-M9 のコアアルゴリズムは揃うが、 ネットワーク / RPC / system event handler が空)

## DESIGN にあって実装に無い

1. **`codex-net` (DESIGN §11 crate list)** — 該当ディレクトリは `Cargo.toml + error.rs + frame.rs + lib.rs + wire.rs` で型骨格のみ、 実 QUIC 接続 / gossipsub は未配線。 README §7 で謳う「synergos-net 流用」のフックポイントが無く、 現状は同一プロセス内 `SessionNode` を直結する想定。
2. **`codex-rpc` crate** — DESIGN §11 で名前は挙がるが crate ディレクトリ自体が存在しない。 light client → full node の SPV pull が DESIGN §8.3 で push subscription 込みで設計されているが、 wire protocol も `submit_event` RPC も無い。
3. **`codex-cli` crate** — 同様に未作成。 README §11 の crate 構成と齟齬。 demo (`codex-demo/src/main.rs`) で代用されているが、 運用向け CLI ではない。
4. **`codex.system.Checkpoint` event handler (DESIGN §6.6)** — body struct (`codex-consensus/src/committee.rs` 周辺) は議論されているが、 「session → domain への submit」「cross-chain verification 2 SPV + 3 sig」を実装した API が無い。 Tessera 連携の核心機能。
5. **`codex.system.ValidatorSetChange` / `ValidatorSlash` 適用ループ** — schema (`ValidatorSetChangeBody`, `EquivocationProof`, `StagedChanges`, `apply_change_to_set`) は揃うが、 これを Stf に handler 登録して event-driven に適用する経路が未配線。 committee mode が `M6` で merge されているが、 governance event を流す統合 test (`codex-consensus/tests/committee_flow.rs`) が現状の体系では schema 単位の test に留まる可能性。
6. **State pruning (DESIGN §5.7 Hot/Warm/Cold 3 層)** — `StateTree` は Vec ベース in-memory のみ、 checkpoint trigger / disk watermark / cold archive 機構なし。 10⁸ entries 想定の前段で必須機能。
7. **NonceTracker の bitset 圧縮 / persistence (DESIGN §5.2.2 末尾)** — `HashSet<u64>` の単純実装、 §15 で言及される高水位 + fixed window がない。
8. **Light client checkpoint trust bootstrap (DESIGN §8.4 / §15)** — bundled key 配布 / rotation / PKI 検討は未決のまま実装なし。
9. **Adaptive pull / zstd header 圧縮 / parallel header fetch (DESIGN §7.4 新興網最適化)** — codex-sync の transport.rs で抽象されているが具体実装無し。
10. **Mempool audit log (DESIGN §5.8.2)** — `received_at` も `MempoolEntry` も無い (`codex-consensus/src/mempool.rs`)。
11. **`codex.system` event reject (DESIGN §5.6.3 v0 要件)** — `Namespace::is_system()` (`codex-core/src/namespace.rs:43`) は判定だけ、 STF 側に `is_system() ⇒ reject` のガードが無い (v0 では handler 未登録による reject に頼っており、 明示拒否ではない)。

## ロードマップとの齟齬

- 設計 M3 / M4 / M5 / M8 まで commit で merge 済 (git log) だが、 README ステータスは「設計段階 (2026-04-23 開始)。 初稿 DESIGN 版 0.1」のまま。 commit が 2 週間ほど進んでいるのに README 更新漏れ。
- DESIGN §14 のマイルストーン表に対し、 実装側 `codex-node` (M3) / `codex-light` (M5) は in-process verifier で satisfaction、 ネットワーク M4 sync の 2 full node 間 state_root 一致テストが `codex-sync/tests/two_node_sync.rs` で存在するが、 これも transport 抽象上の simulation である可能性が高い。

## 利用側との接続

- Tessera / Curare 用 reference handler (`codex-domain-examples/{asset_ledger,game_rights}.rs`) は実装 sample のみ。 Tessera 側に `tessera-codex-client` (DESIGN §1.4) を立てる予定だが、 wire formats が固まっていないため client crate が建てられない。
- Actio attendance / Schedula 用 namespace は domain-examples に未追加、 LUDIARS 横断台帳という前提と乖離。

## file:line 索引

- 空 crate: `codex-net/src/lib.rs`, `codex-sync/src/transport.rs`
- system event handler 不在: `codex-state/src/handler.rs` (system namespace 用 register 無し)
- README ステータス: `README.md:39-42`
