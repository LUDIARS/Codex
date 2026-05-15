# AUTOFIX — Codex 2026-05-13

**autofix_count: 0** (ルール: ソースコード修正禁止、 列挙のみ)

以下は将来 PR で対応すべき候補 (本セッションでは適用しない):

## ドキュメンテーション

1. **`README.md:39-42` ステータス更新** — 「設計段階」「DESIGN 版 0.1」を「M0-M9 実装完了。 DESIGN 版 0.10、 codex-net / codex-rpc / codex-cli は未着手」に書き換え。
2. **`CLAUDE.md` 新設** — エージェント向けガイド。 他 LUDIARS リポと整合させる。

## 脆弱性 (低リスク〜中リスク)

3. **`Namespace` deserialize で validate** — `codex-core/src/namespace.rs:198-208` のテストが「validation 通らない」を docs 化しているが、 `Deserialize` 実装で `try_from` 経由にする (transparent → newtype wrapper) ことで wire 入力経路を塞ぐ。
4. **`Stf::apply_to_scratch` の `.expect("handler existence verified")`** — validate 結果と一緒に handler 参照を carry over し panic-free path にする (`codex-state/src/stf.rs:199-201`)。
5. **`SigningKey` の clone を `Arc<SigningKey>` 化** — `codex-node/src/node.rs:75` 等。 secret material をプロセスメモリ上に多重保持しない。

## 実装

6. **NonceTracker の bitset 圧縮** — `HashMap<(PeerId, Namespace), HashSet<u64>>` を window + roaring bitmap で置換。 §5.2.2 末尾と §5.7 のスケール目標に必要。
7. **MempoolEntry に `received_at` 追加** — DESIGN §5.8.2 audit log 要件。 `codex-consensus/src/mempool.rs:24-55` の `InMemoryMempool` を拡張。
8. **`codex.system.*` の明示 reject** — `Stf::validate_event` 入口で `event.payload.namespace.is_system()` を見て v0 では一律 `UnknownNamespace`。 §5.6.3 の v0 要件遵守を明示化。
9. **`StateTree::root` incremental merkle 化** — M4+ で persistent merkle に置き換え。 v0 でも `root_cache` invalidate を局所 path 更新に変える。

## 不足機能 (フェーズ分離 PR 推奨)

10. **`codex-net` の QUIC + gossipsub 実装**
11. **`codex-rpc` crate 作成 + light client / full node 間 protocol 定義**
12. **`codex.system.Checkpoint` handler 実装** (Tessera 連携の前提)
13. **`codex.system.ValidatorSetChange` / `ValidatorSlash` の STF 接続**
14. **State pruning (Hot/Warm/Cold 3 層) の最低限 (snapshot + cold archive 出力)**
15. **Light client checkpoint trust bootstrap (bundled key + rotation)**

## 品質

16. **`fuzz/` ディレクトリ + cargo-fuzz target 追加** (Event decode / ExistenceProof / NonExistenceProof)
17. **bench regression tracking** (criterion-compare-action) を CI に追加。
