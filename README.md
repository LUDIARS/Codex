# Codex

**検証可能な署名済イベント台帳** — モバイル軽量クライアント前提、Ethereum の検証モデルから必要最小を抽出した LUDIARS 横断インフラ。

> *codex* (ラテン語): 板を綴じた書物。ローマの **codex rescriptus** は擦り直して再書き込みできるが、消された内容は復元可能 — 追記型 + 検証可能という Codex の性格と重なる。

## 何をするもの

「**誰が、いつ、どの権利 / 状態変化を確定させたか**」を、第三者が暗号的に検証できる形で記録する汎用台帳。

### 想定ユースケース

| ドメイン | イベント例 | 利用側 |
|---|---|---|
| ゲーム権利 | kill confirm / pickup 優先権 / 勝敗 | Tessera |
| アセット所有 | 作品の譲渡・ライセンス・改変履歴 | Curare |
| 出席・確定 | 授業出席・予約確定 | Actio / Schedula |
| 汎用契約 | 合意記録・多者間承認 | (将来) |

**Codex 自体はゲーム専用ではない**。LUDIARS 全サービスから呼ばれる基盤。

## Ethereum からの借り物

- **Merkle 検証** (state root / events root)
- **ブロック header チェーン** (prev_hash で連結)
- **署名済イベント** (≈ transaction)
- **Light client SPV** (header + merkle proof)
- **Account abstraction** (PeerId = ed25519 ベース)

## Ethereum から切り捨てたもの

- **通貨・gas・経済インセンティブ** — 不要
- **EVM / smart contract** — validation は右別の hardcoded rule
- **PoW / PoS consensus** — session-scoped は single signer、長期は federated committee (PoA 系)
- **uncle block / reorg 耐性** — 署名者が 1 ブロック確定 finality を保証

詳細: [docs/DESIGN.md](docs/DESIGN.md)

## ステータス

設計段階 (2026-04-23 開始)。初稿 DESIGN 版 0.1。
