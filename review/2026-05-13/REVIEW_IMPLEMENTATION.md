# 実装レビュー — Codex

**評価: B**

## 強み

- **STF atomic rollback の実装が綺麗**。 `Stf::apply_block` (`codex-state/src/stf.rs:109-129`) は `state.clone()` + `nonces.clone()` を scratch にして全 event の validate + apply が成功した時のみ実体に書き戻す。 `failed_event_leaves_state_unchanged` テスト (`codex-state/src/stf.rs:472-497`) で `[good, bad]` block が完全 reject されることを担保。
- **producer ↔ verifier の tip 同期**。 `SessionNode::produce` と `ingest_block` で双方の `ChainTip::advance` を呼ぶ (`codex-node/src/node.rs:185-211`)、 ProducerRole が Producer の場合に producer 内蔵 tip も sync。 split-brain 防止が単一 process でも明示的。
- **テストが意図テスト**。 `world_first_is_enforced` (`codex-state/src/stf.rs:376-399`) は DESIGN §2.4 の「世界唯一性」 を文字どおりテスト、 `proofs_resolve_post_apply` (`codex-state/src/stf.rs:536-555`) は existence + non-existence を applied root に対して検証、 等。 リグレッション検出力が高い。
- **`Event::event_hash` と `signing_hash` の区別**。 同じ `dom::EVENT_SIG` tag だが入力が異なる (`codex-core/src/event.rs:98-103`)、 `signing_hash_differs_from_event_hash` テスト (`codex-core/src/event.rs:178-187`) で明示。 leaf 計算と署名計算の入れ違いを防ぐ。

## 弱み

1. **`clone()` の多用**。 `Stf::apply_block` で毎ブロック `StateTree::clone()` + `NonceTracker::clone()` (`codex-state/src/stf.rs:118-119`)。 10⁸ entries scale では memcpy コスト爆発、 DESIGN §13 「P50 < 20 ms」目標達成は v0 用 toy 実装に留まる。 ベンチマーク `codex-bench/benches/state_tree.rs` がどれだけ pessimistic を見ているか要確認。
2. **`raw_merkle_root()` を毎 `root()` で全 leaf re-hash**。 `StateTree::root` は `root_cache` を持つが、 cache miss (insert/remove 直後) で全 leaf を rebuild する (`codex-state/src/state.rs:103-119`)。 10⁶ leaves で >100ms オーダ。 incremental merkle (sparse cached) 実装は M4+ で確実に要件。 コメント (`codex-state/src/state.rs:1-12`) はこの限界を自覚しているのは良い。
3. **`HandlerRegistry::get` の panic 経路**。 `apply_to_scratch` で apply 時 `.expect()` (`codex-state/src/stf.rs:201`) を打つ。 validate と apply の間に handler を取り外す race は v0 では起こらないが、 panic-free path にしたほうが将来安心 (validate 結果に handler 参照を持ち越す)。
4. **`SessionNode` の Producer/Follower 分岐に `producer_sk: SigningKey` を `clone()` (`codex-node/src/node.rs:75`)**。 `ed25519_dalek::SigningKey` の `clone` は secret key 全体を memcpy。 メモリ上に多重存在する secret は zeroize の意味で好ましくない。 一度 `Arc<SigningKey>` 化するだけで十分。
5. **`BlockHeader::block_hash` は postcard(BlockHeader 全体)**。 producer signature + attestations が変わる度 hash も変わる、 これは BFT 上正しい (`block_hash_depends_on_attestations` テスト) が、 committee mode で attestation を漸進的に集める運用では block_hash が attestation 追加のたびに変化し、 mempool / store dedup key として不安定。 DESIGN §5.3 は明示しないが運用注意。

## 機能横断

- **`codex-domain-examples` は asset_ledger / game_rights のみ**。 LUDIARS 全 28 リポと突合すると Actio 出席 / Schedula 予約 / Memoria が unaddressed。 README の "想定ユースケース" に対し reference handler の coverage が薄い。
- **`codex-ffi/src/lib.rs`** は cbindgen で C ABI を出す scaffold。 README §11 の Unity / Godot / iOS 連携を実 binding まで通すには Tessera 側のホスト実装が必要、 現状 Codex 単体ではループバック止まり (実機モバイル test は未)。
- **`codex-bench`** は merkle / signing / state_tree の 3 ベンチ、 CI で `--no-run` のみ走らせる構成 (`.github/workflows/ci.yml:52-62`)。 perf regression を機械検出する harness は未着手 (criterion-compare action は別 PR 想定)。

## file:line 索引

- atomic STF: `codex-state/src/stf.rs:109-177`
- clone コスト: `codex-state/src/stf.rs:118`, `codex-node/src/node.rs:75`
- merkle re-hash: `codex-state/src/state.rs:103-119`
- panic path: `codex-state/src/stf.rs:201`
