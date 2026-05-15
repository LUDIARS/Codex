# 設計レビュー — Codex

**評価: A**

## 強み

- **DESIGN 0.10 と実装の対応が逐条的**。 §5.4.2 leaf/internal domain separation は `codex-crypto/src/lib.rs:26-39` の `dom::LEAF/INTERNAL/BLOCK_SIG/EVENT_SIG/CHAIN_ID/STATE_ROOT` に一対一でマップ。 16-byte tag 長を test (`codex-crypto/src/lib.rs:223`) で固定し、 「全 tag は distinct」を `domain_separation_tags_are_distinct` で保証。
- **Ethereum からの取捨選択が一貫**。 DESIGN §16 のマトリクスと実装スコープが乖離なし: MPT 不採用 → sorted-key binary merkle (`codex-state/src/merkle.rs`)、 RLP 不採用 → postcard、 EVM 不採用 → `NamespaceHandler` trait (`codex-state/src/handler.rs`)。
- **Light-client first** が型でも担保。 `LightClient` は header のみ持ち (`codex-light/src/lib.rs:54-59`)、 state proof は `verify_existence` を rewrap するだけ (`codex-light/src/lib.rs:118-129`)。 DESIGN §8.1 の "header + merkle path" 設計と完全一致。
- **DESIGN §5.4.3 の "leaf-count を state_root に commit" が実装済**。 `state_root_commit(leaf_count, merkle_root)` (`codex-state/src/merkle.rs:40`) で adjacency 詐称 (non-existence proof で隣接2 leaf を捏造) を構造的に塞ぐ。 これは DESIGN ドラフトに後追いで追加された防衛で、 実装が正しく追従しているのは好印象。
- **per-chain block interval** が DESIGN §6.1.1 で 4 段階定義され、 `SessionProducer` は `allow_empty` フラグ (`codex-consensus/src/producer.rs:64-77`) で heartbeat vs idle を切替可能。

## 弱み・改善点

- **`codex.system.*` namespace の予約は仕様だけで実装が無い**。 DESIGN §5.6.3 / §6.6 / §6.7 で `codex.system.Checkpoint` / `ValidatorSetChange` / `ValidatorSlash` を event として規定するが、 `codex-consensus/src/committee.rs:428-456` で body schema は定義されるものの、 STF の handler 登録は §5.6.3 通り "event 受理は拒否 (v0)" のままで、 system event を流す経路が無い。 v0 範囲では正しい挙動だが、 README ステータス「設計段階」と git log の M6 (committee mode) との整合性で言うと、 system handler skeleton が無いと M6 が機能的に未完。
- **Checkpoint 形式 (DESIGN §6.6) は body 型のみ実装、 cross-chain verifier API (§6.6.4 の "2 SPV + 3 signature") が存在しない**。 利用側 (Tessera) から見ると検証手順がコードで参照できる場所がない。
- **§15 で `Ethereum RLP 互換は追求するか` を未決**。 codex-ffi は cbindgen で C API を出すが、 外部 verifier 言語多様性のための非 Rust serializer 互換は未検討のまま。 LUDIARS 内で完結なら無視可能だが、 README §1.4 が「第三者が暗号的に検証」を謳う以上は中期的に決着必要。

## file:line 索引

- 設計→実装マップ: `docs/DESIGN.md:9-17` (変更履歴) と `codex-*/src/*.rs` 各 module doc コメントの `# Design references` セクション
- domain tag 定義: `codex-crypto/src/lib.rs:26-39`
- state_root commitment: `codex-state/src/merkle.rs:40-46`, `codex-state/src/state.rs:103-110`
- light client: `codex-light/src/lib.rs:54-163`
- system namespace 予約: `codex-core/src/namespace.rs:22`, `codex-core/src/namespace.rs:43-45`
