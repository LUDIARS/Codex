# Codex 設計書

> 版: 0.10 — 2026-04-23
> 著者: kazmit299
> ステータス: 設計ドラフト (実装未着手)
>
> **変更履歴**
> - 0.10 (2026-04-23) — 設計思想との整合性検証 (§2.4)。per-chain block interval (§6.1.1)、producer ordering 規則 (§5.8)、state pruning 戦略 (§5.7) を追記。M0 実装着手の gate を通過
> - 0.9 (2026-04-23) — B3 確定: Committee validator 変更は `ValidatorSetChange` event + `effective_at_height` による予告制。`ValidatorSlash` event + equivocation proof による即時除名を別枠で定義。size < 3 変更は reject
> - 0.8 (2026-04-23) — B2 確定: Session → domain chain checkpoint は `codex.system.Checkpoint` event として domain chain に submit。L2 rollup 相当、fraud proof 不要 (署名検証のみで finality)。v0 は final checkpoint のみ
> - 0.7 (2026-04-23) — B1 確定: Namespace handler は full node binary にコンパイル済、static config で有効化。動的登録は v1+ 持ち越し。`codex.system` namespace を予約
> - 0.6 (2026-04-23) — **A3 改訂**: Synergos には synergos-crypto crate が存在せず crypto が synergos-net に埋込済のため、facade 方針を撤回。`codex-crypto` は ed25519-dalek + blake3 を直接依存する独立実装に変更。PeerId を `[u8; 20]` binary として §5.1 に正式定義
> - 0.5 (2026-04-23) — A4 確定: Merkle tree は sorted-key binary (v0)、leaf/internal は domain-separation tag 必須、ExistenceProof と NonExistenceProof を正式定義
> - 0.4 (2026-04-23) — A3 確定: `codex-crypto` は `synergos-crypto` のファサード crate として存在、domain separation 定数のみ独自定義
> - 0.3 (2026-04-23) — A2 確定: nonce は (claimant, namespace) で一意のみ要求、厳密連番 enforce せず gap 許容
> - 0.2 (2026-04-23) — A1 確定: Event から `parent` フィールドを削除。DAG 依存は namespace body に委譲
> - 0.1 (2026-04-23) — 初稿

---

## 1. プロジェクト概観

### 1.1 命名

**Codex** — ラテン語で「板を綴じた書物」。ローマの *codex rescriptus* (パリンプセスト) は上書きしても擦り跡から元の内容を読み取れるため、**追記型でありながら過去も検証可能** という Codex の性質そのもの。

### 1.2 目的

第三者が暗号的に検証可能な形で **署名済イベント** と **状態遷移** を記録する汎用台帳。Tessera のゲーム権利、Curare のアセット所有、Actio の出席確定、その他 LUDIARS 横断の「誰がいつ何を確定させたか」を統一的に扱う。

### 1.3 参照モデル — Ethereum からの抽出

Ethereum の「検証可能性」に関する構造だけを取り、「経済・実行・分散合意」を削ぎ落としたもの。

| Ethereum | Codex | 備考 |
|---|---|---|
| Account (address) | PeerId (`blake3(ed25519_pub)`) | Synergos と共通 |
| Transaction | **Event** (署名済 claim) | 署名者 = claimant |
| Block (header + body) | **Block** (header + events) | 同様 |
| Merkle Patricia Trie | **Merkle tree** (簡略版、後述) | MPT 実装コスト回避 |
| Block header chain | prev_hash で連結 | 同じ |
| PoS / PoW consensus | **PoA 系** (fixed signer + optional committee) | ゲーム/組織運用に合致 |
| EVM | **無し** — validation は right 別 hardcoded rule | |
| Gas | **無し** — rate limit per account | |
| Light client (LES) | **Light mode** — header + SPV proof | モバイル主軸 |
| Finality: Casper FFG | **Single-block finality** (single signer) / **threshold finality** (committee mode) | 実質 instant |

### 1.4 他プロジェクトとの関係

```
┌─────────────────────────────────────────────────┐
│ Tessera  Curare  Actio  Schedula  ...           │  ← 利用側 (domain apps)
│ (署名済イベントを投げる / 検証する)              │
├─────────────────────────────────────────────────┤
│ Codex                                            │  ← 本プロジェクト
│ (Event / Block / State / Light client)           │
├─────────────────────────────────────────────────┤
│ Synergos net / crypto                            │  ← 下層基盤 (再利用)
│ (QUIC, ed25519 Identity, blake3)                 │
└─────────────────────────────────────────────────┘
```

- **Synergos** の ed25519 Identity・blake3・QUIC 転送を流用
- **Tessera** は Codex クライアント (`tessera-codex-client` 予定) 経由で利用
- Codex 自体は **ドメイン非依存**。右の語彙 (`RightType`) は namespace 付き string

### 1.5 設計原則

1. **Verification first** — 第三者が header + proof で検証できることが最優先
2. **Light-client first** — full node 前提にしない。モバイル軽量クライアントが一等市民
3. **Simple consensus** — PoA 系で finality は単純。将来 committee mode でも BFT 級に留める
4. **Domain agnostic** — ゲーム固有ロジックを core に入れない
5. **Re-use Synergos** — 暗号・転送は Synergos の基盤に相乗り、新規実装は検証層のみ

## 2. スコープ

### 2.1 In scope

- 署名済 Event 受理 / 検証 / 追記
- Block 生成 / 署名 / 伝播
- State root 計算 (merkle tree、簡易 MPT)
- Light client SPV (header + proof の提供 / 検証)
- Session-scoped chain (ephemeral) と domain-scoped chain (long-lived) の両対応
- Session → domain への checkpoint (L2 rollup 風)
- PoA single signer と federated committee の 2 モード
- 新興網・モバイル前提の sync プロトコル

### 2.2 Out of scope

- **暗号通貨・経済インセンティブ** (gas / token)
- **Turing-complete な smart contract** (EVM 級)
- **Public permissionless consensus** (PoW / PoS / 公開 validator 公募)
- **ドメイン固有 validation rule** の core 実装 (利用側 crate の責務)
- **Reorg / fork resolution** (single/committee signer モデルにより理論的に発生しない)

### 2.3 ターゲット環境

- モバイル優先 (iOS / Android)、低スペック機を想定
- 新興網 (RTT 400 ms、loss 15%、帯域 256 kbps) で light client が動作すること
- full node はサーバ (LUDIARS infra 上) 想定。自宅ホストも可能

### 2.4 設計思想との整合性検証 — 世界唯一性基盤として

Codex の究極目的: **「世界に 1 人だけの偉業」を暗号的に保証し、それを個性として称賛するゲーム体験の基盤**。

#### 2.4.1 設計者提示の 4 原則

1. **人数規模は大**: LUDIARS 全ユーザ規模、潜在的 10⁶–10⁸ users
2. **通信頻度は低**: ユーザ 1 人あたり 1 achievement/月オーダ。トラフィック性質は burst 的でなく疎
3. **ローカル中心 + 世界規模ネット**: 各デバイスは local storage を持ち、global full node network に参加
4. **体験としての唯一性**: 「誰か 1 人が最初にやった」事実を改竄不能に記録、本人の個性として表示される

#### 2.4.2 世界唯一性を実現する運用モデル

単一の achievement について以下を満たす運用ルール:

1. **単一の canonical domain chain**: 1 つの achievement カテゴリは 1 つの domain chain で管理 (例: `ludiars-achievements` chain)
2. **単一の namespace key**: achievement ID (`ludiars.first.summit_of_fuji` 等) は namespace + key の一意対応
3. **First-to-commit wins**: block apply 順で最初に `validate()` 成功した event が勝者、以降の重複は reject
4. **Producer ordering 規則**: 同一 block 内の並行 claim は **mempool 受信順 FCFS** (§5.8 参照)

これらを満たすことで、claim が chain に取り込まれた瞬間にその achievement の所有者が不可逆確定する。

#### 2.4.3 "First to commit" vs "First to act" の semantics

**v0 の保証: "first to commit"** — 最初に signed event を chain に取り込ませた者が勝者。ネット遅延・producer ordering の影響を受ける。

**"First to act"** (実際の行為時刻順) が必要な場合、namespace handler 側で:
- event body に self-claimed actor timestamp
- 認定機関の signed attestation (witness timestamp)
- handler が attestation 付き timestamp で ordering 上書き

これは **namespace の責務**であり Codex core は不関与。v0 で標準 handler は first-to-commit 一本。

#### 2.4.4 要件 × 設計の適合マトリクス

| 要件 | 現行設計の該当 | 判定 |
|---|---|---|
| 大人数 (10⁸) 対応 | per-key state、SPV proof log N | ✓ pruning 前提 (§5.7) |
| 低頻度通信 | 任意時刻 event submit、offline 耐性 (A2 §5.2.2) | ✓ |
| ローカルで世界規模参加 | light client + global full nodes + SPV (§8) | ✓ |
| 世界唯一性 | first-to-commit + namespace uniqueness 判定 | ✓ §2.4.2 運用で成立 |
| 重複不能な事実 | append-only chain + 署名 + merkle | ✓ |
| 低頻度と block interval | **500 ms 固定は過剰**、achievement 用には長 interval が適切 | per-chain 化 §6.1.1 で対応 |
| state の長期成長 | full node 25 GB/10⁸ entries、pruning が必要 | §5.7 で対応 |
| 並行 claim の公平性 | FCFS + mempool audit | §5.8 で明文化 |
| Tessera 権利実装の基盤 | session chain → checkpoint → domain chain (B2 §6.6) | ✓ |

#### 2.4.5 結論

**現行設計は世界唯一性基盤として実装に耐える**。v0.10 で以下 3 点を拡張:

- **§5.7 State pruning 戦略**: 10⁸ entries スケールで full node ディスク / メモリを現実的に維持
- **§5.8 Producer ordering 規則**: 並行 claim の FCFS + mempool audit、公平性とトレーサビリティ
- **§6.1.1 per-chain block interval**: achievement chain は長 interval (1–10 分)、session chain は 500 ms 維持

これらは設計反転ではなく **拡張**。M0 での `codex-core` / `codex-crypto` 型定義には影響せず、即時着手可能。

## 3. 設計目標 (優先度順)

1. **Light client の検証時間 P50 < 20 ms** — モバイル端末で block header + merkle proof を受け取ってから検証完了まで
2. **署名済 Event の受理スループット ≥ 1000 evt/s / full node** — ゲーム / アセット移転で十分
3. **Block finality ≤ 500 ms (session mode)** — ゲーム内 authoritative query に間に合う
4. **State proof サイズ ≤ 1 KB** — 新興網でもモバイルに配送可能
5. **初期同期 (fast sync) ≤ 3 s** — app 起動時にドメイン最新状態を取得
6. **コア crate は `no_std` 互換** — embedded / Wasm / mobile FFI 対応
7. **ドメイン非依存 API** — RightType は利用側が注入

## 4. アーキテクチャ層構造

```
┌──────────────────────────────────────────────────────┐
│ 8. RPC / gossip            (codex-net)               │  network wire
├──────────────────────────────────────────────────────┤
│ 7. Sync protocols           (codex-sync)             │  full/fast/light
├──────────────────────────────────────────────────────┤
│ 6. Light client             (codex-light)            │  SPV, header-only
├──────────────────────────────────────────────────────┤
│ 5. Consensus / block producer (codex-consensus)      │  PoA/committee
├──────────────────────────────────────────────────────┤
│ 4. State transition         (codex-state)            │  merkle tree, apply
├──────────────────────────────────────────────────────┤
│ 3. Block / Event / Header   (codex-core)             │  core types
├──────────────────────────────────────────────────────┤
│ 2. Crypto (ed25519, blake3) (codex-crypto = Synergos) │  re-use
├──────────────────────────────────────────────────────┤
│ 1. Transport (QUIC)         (synergos-net)           │  re-use
└──────────────────────────────────────────────────────┘
```

## 5. データモデル

### 5.1 Identity と Account

```rust
/// 20-byte binary PeerId. blake3(ed25519_public_key)[..20]
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct PeerId(pub [u8; 20]);

impl PeerId {
    /// Ed25519 公開鍵 32 byte → blake3 → 先頭 20 byte を PeerId とする
    pub fn from_public_key(pubkey: &[u8; 32]) -> Self {
        let h = blake3::hash(pubkey);
        let mut out = [0u8; 20];
        out.copy_from_slice(&h.as_bytes()[..20]);
        Self(out)
    }

    /// 表示用 hex (40 文字)。Synergos の PeerId String と bit-level で一致
    pub fn to_hex(&self) -> String { hex::encode(self.0) }
}
```

- **長さ**: 20 byte (160 bit)。Ethereum address や Bitcoin P2PKH と同等の衝突耐性
- **Synergos 互換**: Synergos の `PeerId(String)` は同じ 20 byte を hex 化したもの。**byte-level で一致**、表現だけが異なる (Synergos = 40 字 hex / Codex = `[u8; 20]`)
- 変換は `to_hex()` / `from_hex()` で相互運用可能。将来 `ludiars-crypto` 共通化の素地
- **Account 抽象は使わない**: 状態は PeerId 単位ではなく **(namespace, key) 単位** (§5.4)。権利の集合として state を管理する
- 署名は常に ed25519、peer の秘密鍵で

### 5.2 Event

```rust
struct Event {
    version:     u8,
    namespace:   Namespace,          // "tessera.game", "curare.asset", ...
    claimant:    PeerId,
    nonce:       u64,                // per-(claimant, namespace) 単調増加
    body:        EventBody,          // namespace 別のペイロード (bytes)
    timestamp:   u64,                // claimant 側の unix ms (参考値)
    sig:         Ed25519Signature,   // 上記全てへの署名
}

struct Namespace(String);  // "<owner>.<topic>" ドット区切り、ASCII
struct EventHash(Blake3Hash);  // event canonical serialization の blake3
```

- **nonce**: replay protection。peer が namespace 別に **単調増加させる SHOULD、厳密連番 NOT required** (詳細 §5.2.2)。
- **body**: namespace で schema が決まる。Codex core は不透明バイト列として扱う。

#### 5.2.1 因果依存の表現 — `body` に埋め込む

core Event に `parent` フィールドは **持たない**。DAG 的因果依存が必要な namespace は、自 schema の `body` 内に依存 hash を埋め込む:

```
# 例: tessera.game の "pickup requires trigger" を表す body
{
  "kind": "pickup",
  "item_id": "...",
  "requires": [ <EventHash of prior trigger> ],
  ...
}
```

namespace handler の `validate()` が state 参照で依存成立を確認する。core はこの依存を関知しない。

**この分離の利得**:
- light client SPV が **線形 merkle walk** (O(log N)) で完結 — DAG walk 不要
- block ordering が canonical total order に閉じ、STF 決定性が単純化
- 大半の namespace は依存を使わない — core schema から排除するのが妥当
- Ethereum も tx 自体に parent は持たず、block 内順序で依存を表現している — 参照モデルと整合

#### 5.2.2 nonce セマンティクス

**正規ルール**:

- nonce は `(claimant, namespace)` 内で **ユニーク** (必須、enforce)
- 単調増加は **推奨だが必須ではない** (gap 許容)
- クライアントは常に `last_submitted + 1` を送信することが推奨 (単純な実装)
- サーバは重複 (既知 nonce の再使用) のみ拒否、ギャップは受理

```rust
// validate() の nonce 判定
fn validate_nonce(evt: &Event, seen: &NonceStore) -> Result<(), ValidationError> {
    if seen.contains(evt.claimant, &evt.namespace, evt.nonce) {
        return Err(ValidationError::DuplicateNonce);
    }
    Ok(())
}
```

**この選択の帰結**:

| 観点 | 内容 |
|---|---|
| **replay 保護** | ユニーク性で十分。同じ nonce を 2 度受理しない限り replay 不能 |
| **offline resilience** | モバイル offline 中に 3,4,5 作成 → 4 が伝送消失 → 3,5 受理可、4 は retry で後追い可。Ethereum strict なら 5 も blocked |
| **out-of-order 到達** | 5 が 3 より先に届いても受理。順序が意味を持つ処理は namespace handler の責務 |
| **ストレージコスト** | server は `(claimant, ns)` ごとの nonce 集合を保持。fixed window (直近 N 個の範囲をビットセット) + 高水位超過は拒否、でメモリ有界化可能 |
| **Ethereum との違い** | ETH は strict sequential (gas ordering 維持のため)。Codex は gas 無し、strict は過剰制約 |

**運用ガイドライン**:

- クライアント SDK は内部で `last_submitted` を persist、起動時に復元して +1 で再開
- long-offline 復帰時は単調 +1 を続けるだけ。サーバ側で gap は無害
- peer が複数端末から同時に署名する場合は nonce レンジ分割 (例: 端末 A は `[0, 10^18)`、端末 B は `[10^18, 2·10^18)`) をアプリ層で運用

### 5.3 Block

```rust
struct BlockHeader {
    version:         u8,
    chain_id:        ChainId,          // 32 byte。session chain or domain chain ID
    height:          u64,
    prev_hash:       BlockHash,
    events_root:     Blake3Hash,       // merkle root of events in this block
    state_root:      Blake3Hash,       // merkle root of state after applying
    timestamp:       u64,              // signer 側 unix ms
    producer:        PeerId,
    producer_sig:    Ed25519Signature, // header 全体の署名
    // committee mode 時のみ:
    attestations:    Vec<Attestation>, // 他署名者の承認
}

struct Block {
    header: BlockHeader,
    events: Vec<Event>,
}

struct Attestation {
    signer: PeerId,
    sig:    Ed25519Signature,  // header 全体への署名
}
```

- `chain_id`: この chain を識別。session chain は session 開始時に生成、domain chain は配置時に固定。
- `events` は block body。header と分離することで light client は header のみで済む。

### 5.4 State

状態 = **(namespace, key_hash) → Value** の map。

```rust
type StateKey = (Namespace, Blake3Hash);  // namespace + right-specific key hash
type StateValue = Bytes;                   // namespace で schema 定義

struct StateTree {
    root: Blake3Hash,
    // 実装: sorted-key binary merkle (v0)
}
```

#### 5.4.1 Merkle tree の選定 — sorted-key binary (v0 確定)

- **v0 採用**: sorted-key binary merkle tree
- **v1 候補 (将来)**: Sparse Merkle Tree / Verkle tree — proof 定数化が必要になった時点で評価

**v0 で sorted-key binary を選ぶ理由**:

- 実装が単純 (~300 行)、fuzzing 容易
- proof サイズ = `log₂ N × 32 B`。10⁶ leaves でも 640 B、**光クライアント予算 1 KB に余裕で収まる**
- 非存在証明が **隣接 leaf 2 つの proof** で済む (sorted なので adjacency が意味を持つ)
- Ethereum MPT (radix-16 Patricia) は branch/extension node が proof path に混ざり **2-3 倍大きい**。モバイルでは不利

#### 5.4.2 Leaf と internal の符号化 (domain separation 必須)

`codex-crypto` の domain-separation tag (§11.1) を常に prefix する。

```rust
// leaf: 存在する key-value
fn leaf_hash(ns: &Namespace, key_hash: &Blake3Hash, value: &[u8]) -> Blake3Hash {
    blake3(
        dom::LEAF             //  "LUDIARS-CDX-L001"  (16 B)
        ‖ ns.as_bytes_len_prefixed()
        ‖ key_hash            //  32 B
        ‖ value_len_varint()
        ‖ value
    )
}

// internal node
fn node_hash(left: &Blake3Hash, right: &Blake3Hash) -> Blake3Hash {
    blake3(
        dom::INTERNAL         //  "LUDIARS-CDX-N001"  (16 B)
        ‖ left  ‖ right       //  32 + 32 B
    )
}
```

**この符号化が避ける攻撃**:

- **Second-preimage / length-extension** — tag prefix + 長さ前置で内容を改竄して同一 hash を生成不能
- **Namespace collision** — 同じ `key_hash` が別 namespace で別 value を持っても衝突しない
- **Leaf ↔ internal 混同** — tag が異なるため、leaf hash を internal node として使い回せない

#### 5.4.3 Proof 構造

```rust
/// 存在証明: key が値 V で state に入っていることを証明
struct ExistenceProof {
    namespace:   Namespace,
    key_hash:    Blake3Hash,
    value:       Bytes,
    siblings:    Vec<(Direction, Blake3Hash)>,  // root までの sibling hash 列、Direction ∈ {Left, Right}
    block_header: BlockHeader,                  // state_root を含む
}

/// 非存在証明: key が state に入っていないことを証明
struct NonExistenceProof {
    queried_key: (Namespace, Blake3Hash),

    /// 隣接する 2 leaf の存在証明 (sorted key 上で queried_key を挟む)
    /// 先頭/末尾の特殊ケースは Option で左右どちらかのみ可能
    left_neighbor:  Option<ExistenceProof>,
    right_neighbor: Option<ExistenceProof>,
}

enum Direction { Left, Right }
```

**検証手順** (ExistenceProof):

1. `leaf = leaf_hash(namespace, key_hash, value)` を再計算
2. `siblings` を direction に従って折り畳み → `computed_root`
3. `assert computed_root == block_header.state_root`
4. `block_header.producer_sig` を検証 + checkpoint まで header chain を連結

**検証手順** (NonExistenceProof):

1. `left_neighbor` / `right_neighbor` それぞれを ExistenceProof として検証
2. `left.key_hash < queried_key < right.key_hash` が sorted 順で成立することを確認
3. さらに「2 leaves が sorted-key tree 上で adjacent」であることを siblings の構造から確認

### 5.5 State transition function (STF)

```
state_t+1 = apply(state_t, block)
  for event in block.events (in order):
    validate(event, state)  → must pass
    state = apply_event(state, event)
  return state
```

- `validate`: 署名検証、nonce ユニーク性 (§5.2.2)、namespace 手続きの事前条件
- `apply_event`: namespace 登録済の handler を呼び state を変異
- **決定論必須**: 同一 (state_t, block) は必ず同じ state_{t+1} を出す → state_root が全 participant で一致

namespace handler は **Codex core には入れず、利用側 crate が register する** (§9.1)。登録方式の詳細は §5.6。

### 5.6 Namespace 登録モデル (v0 確定、v1+ 拡張)

#### 5.6.1 v0 基本形: binary 組込 + static config

- **Handler ロジック は full node binary にコンパイル済** (Rust の NamespaceHandler trait 実装)
- 起動時に **static config** (TOML) から有効化 namespace set を読み込む
- 同じ binary でも運用環境ごとに異なる config で稼働可能 (Tessera 用 / Curare 用 / テスト用 等)

```toml
# codex-node.toml の抜粋
[namespaces]
enabled = [
  "tessera.game",
  "curare.asset",
  "actio.attendance",
  "codex.system",   # 予約、§5.6.3
]

[namespaces."tessera.game"]
# handler 固有パラメタ (rate limit, match duration 等)
max_match_duration_s = 1800
```

- Cargo feature flag で handler crate を条件 include 可能: 例えば `codex-node --features "domain-tessera,domain-curare"` でビルド
- handler 未登録の namespace が event で飛んできたら `ValidationError::UnknownNamespace` を返して reject

#### 5.6.2 動的登録は v0 スコープ外

Codex v0 は **動的 handler 追加機構を実装しない**。

- WASM / eBPF / dynamic loader は §2.2 out of scope に該当 (EVM 相当の複雑性)
- 新しい namespace 追加 = Rust 実装 → binary rebuild → config 追記 → deploy というサイクル
- このサイクルは Ethereum の hard fork (prepackaged upgrade) と等価の運用モデル

これは「LUDIARS 横断で使える汎用台帳」というポジションと矛盾しないか — しない。**実装は集中管理、運用は分散** (各サービスが自分の codex-node インスタンスを走らせる、namespace 有効化を config で選ぶ) で十分。

#### 5.6.3 `codex.system` namespace 予約

将来の system-level 操作 (handler 有効化トグル、validator set 変更、checkpoint 発行 等) のため **`codex.system`** を reserved namespace とする:

- v0: **定義のみ、event 受理は拒否** (unknown namespace 扱い)
- v1+: 特権 event を流すための namespace として使用。validate は committee / session signer 検証付き

利用側 namespace は `codex.system` プレフィクスを名乗れない (validation で reject)。

#### 5.6.4 v1+ での動的拡張余地 (設計保留)

将来検討する dynamic activation の形:

- `codex.system.RegisterNamespace { target_namespace, handler_version, config }` event
- signer = committee (多数決) or session producer
- handler 本体は binary 済、config でアクティベート切替のみ
- binary に未入の handler は依然として deploy 必須 (動的コードロードは採用しない)

これも v0 では実装しない。§15 に残置。

### 5.7 State pruning 戦略 (10⁸ scale 対応)

world-first achievement のような append-only な unique-key 記録は、**chain 稼働期間に比例して state が成長する**。10⁸ entries × 256 B ≈ **25 GB/node** が上限目安。full node の SSD を食い潰さず、light client の state proof を log 爆発させない設計が要る。

#### 5.7.1 State の不変性 (pruning 可能範囲の限定)

「偉業の記録」は **原則削除不可**。よって pruning の対象は以下に限定:

| pruning 可能 | 対象 | 判断基準 |
|---|---|---|
| ✓ 可 | **履歴 block body** (events 本文) | checkpoint 済み以降、かつ関連全 state が最新 state_root に畳み込み済 |
| ✓ 可 | **古い state snapshot** | 現時点 state_root のみで SPV 可能、snapshot は archive 行き |
| ✗ 不可 | **現在 state のエントリ** | world-first の所有事実は永続 |
| ✗ 不可 | **block header chain** | verification chain 連結性が切れる |

#### 5.7.2 3 層保持モデル

full node は以下 3 層で state / 履歴を持つ:

| 層 | 内容 | 保持期間 | メディア |
|---|---|---|---|
| **Hot** | 最新 state tree + 直近 N (= 1000) block | 常時 | in-memory + SSD |
| **Warm** | checkpoint 以降の block body + state snapshot | 数週間–数ヶ月 | SSD / HDD |
| **Cold** | 歴史的 block body + state snapshot | 無期限 | 外部 archive (S3 / R2 / 自社ストレージ) |

light client は **Hot 層のみを問合せ対象** にする (proof 生成は現 state_root ベース)。cold 層への access は audit / debug のみ。

#### 5.7.3 Pruning トリガ

以下のいずれかで cold 層へ移送:

- **Checkpoint 完了**: session → domain chain への checkpoint (§6.6) が 2 段先まで安定したら、対象 session の body を warm → cold
- **Disk watermark**: Hot 層が閾値を超えたら、古い block body から warm → cold へ順次退避
- **Manual**: 運用が archive ツールで手動退避

#### 5.7.4 Proof 生成への影響

state proof (§5.4.3) は **現時点 state_root に対する merkle path** を返すため、古い block body が cold に落ちていても影響しない。historical state (「block N 時点でこの key の値は?」) は cold 層を参照する必要があるが、これは audit 系 tool の責務。

#### 5.7.5 Storage コスト試算

典型シナリオ (10⁸ achievement entries、1 block/分、365 日):

| 層 | 容量 |
|---|---|
| Hot state tree | ~25 GB (10⁸ × 256 B) |
| Hot block headers | ~150 MB (525k blocks × 300 B) |
| Warm block body (30 日) | ~1 GB (event 間引き 0.1/s) |
| Cold archive (年率) | ~12 GB/年 |

full node の SSD 要件は **Hot 層 30 GB + warm 30 GB = 60 GB**、cold は別ディスクに逃がせる。

### 5.8 Producer ordering 規則 — 並行 claim の公平性

複数 claimant が同一 achievement を並行 claim した場合、**producer が block 内で event を並べる順** が勝者を決める。ここに規律がないと producer が arbitrage できる。

#### 5.8.1 v0 規則: Mempool 受信時刻 FCFS

producer は mempool に到着した event を **受信時刻昇順 (first-come-first-serve)** で block に取り込む:

```rust
impl Producer {
    fn compose_block(&mut self, mempool: &Mempool) -> Block {
        let mut events = mempool.ordered_by_received_at();  // 昇順
        // Rate limit enforcement, dedup, etc.
        let events = events.filter(|e| self.validate_precondition(e));
        Block { header: ..., events }
    }
}
```

#### 5.8.2 Mempool audit log

producer は **mempool log** を full node ローカルに記録する:

```rust
struct MempoolEntry {
    event_hash: EventHash,
    received_at: u64,           // producer の unix ms
    included_in_block: Option<BlockHash>,
    rejected_reason: Option<ValidationError>,
}
```

- 公開はしない (巨大になるため) が、第三者が producer の公正さを疑った場合に開示可能
- audit 要求に対して producer は mempool log snapshot を提供 (cold archive 行き)

#### 5.8.3 FCFS の限界と mitigations

FCFS は完璧ではない:

- **Network latency**: 地理的に producer 近傍の claimant が有利
- **Mempool を飛ばす**: claimant が複数 full node に並列送信することで到達時刻を早められる
- **Producer の不正**: 受信時刻記録を改竄する可能性

**v0 での受容**: LUDIARS の producer は運営管理下 (PoA)。完全な fairness は追求せず、**audit 可能性**で代替。

**v1+ 検討**:
- **Fair ordering consensus** (Chainlink FSS / Aequitas): 複数 validator が受信順を共有、median 採択
- **Time-locked commit-reveal**: 複数 claimant が hash commit を並列 submit、一定時刻後に reveal で勝者決定 (この実装は namespace handler level でも可)

#### 5.8.4 並行確率と現実対応

世界唯一の偉業に対する並行 claim は 非常に稀 (1 人が取れば以降の挑戦者は event reject される)。衝突窓は **最初の claimant が submit → block 取り込み** の数秒–数十秒のみ。この窓内の同時到達は:

- 通知系 (SNS バイラル等) で複数ユーザが同日に達成 → 到達時刻秒単位で差
- 同タイミング自動化 bot → namespace handler で rate limit により排除
- 偶発的同時 → FCFS で決定、結果は audit 可能

**結論**: v0 FCFS で実用上十分。不満があれば v1 で fair ordering consensus に昇格。

## 6. Consensus と block production

### 6.1 Session mode (single signer)

- 1 つの `producer` が全 block を署名
- producer = game server (authoritative) or arbiter (mesh、Tessera §5.5.3)
- Finality は **single-block**: signer の署名があれば確定
- Block 生成間隔: **per-chain 設定**、§6.1.1 参照
- Throughput: producer 能力に依存、~10k evt/s 目安

#### 6.1.1 Per-chain block interval

Block 生成間隔は **chain 種別ごとに独立設定**。固定値にすると低頻度 chain で空 block が氾濫し header chain が肥大する (light client sync コスト増)。

| chain 種別 | 典型 interval | 根拠 |
|---|---|---|
| **Session chain** (Tessera の match セッション) | 500 ms | tick loop 追随、game response の authoritativeness |
| **Domain chain — 高頻度** (match stats 集約) | 2–5 s | bursty な checkpoint 群を吸収 |
| **Domain chain — 低頻度** (world-first achievements, 出席記録) | 1–10 分 | 1 evt/s 未満の性質に対応、header chain 成長率を抑制 |
| **Domain chain — 極低頻度** (組織契約、長期 attestation) | 1 時間 | 日次オーダの event に対応 |

chain config は genesis block の extension field または config file で固定し、chain 中で変更しない。

**空 block の扱い**:

- 空 block は生成せず、**event が 1 件以上 mempool にある時のみ block 生成**
- ただし `max_idle_interval` (例: 24h) を超えて新 block 未生成なら **heartbeat block** (空 events + prev_hash 連結のみ) を発行、chain tip の liveness を保証
- heartbeat は light client が "chain is alive" を検知するための最小シグナル

**Light client 影響**:

- 低頻度 chain は header chain が短い → fast sync が高速
- heartbeat block も 1 block 扱いで検証コストは同じ
- `max_idle_interval` を超えた沈黙は full node 障害 / chain 停止を示す

**典型運用**:

- 世界唯一 achievement chain → 5 分 interval、event 到達時即 block、idle 時は 24h heartbeat
- Tessera session chain → 500 ms 固定、match 中のみ稼働、match 終了で checkpoint → chain 破棄

### 6.2 Committee mode (federated, DPoS-lite)

- 固定の `validators: Vec<PeerId>` が署名権を持つ (N=3〜9 典型)
- 各 block は **round-robin で producer が proposer** になり block を提案
- `floor(2N/3) + 1` の attestation で finality
- Finality: typically 1-2 block 後 (~1 s)
- 用途: リーグ戦・cross-match leaderboard・組織記録など、single-signer に委ねられない場面

### 6.3 Finality まとめ

| mode | finality | 用途 |
|---|---|---|
| session | 1 block (signer 署名時) | ゲーム中の権利、即時 authoritative query |
| committee | 1–2 block (2/3 attestation) | リーグ戦、組織的確定 |
| checkpoint | session → committee chain への anchor | 長期保存、audit trail |

### 6.4 Signer 選出とローテーション

- **session**: game session 開始時に producer を決定 (Tessera §5.5.3: server or arbiter=PeerId 最小)
- **committee**: 事前設定の固定 set。変更手順は §6.7 参照 (予告制 `ValidatorSetChange` + 即時除名 `ValidatorSlash`)
- **fail-over**: producer 応答 timeout (3s) → committee の場合は next round の proposer がスキップ役目を引き継ぐ / session の場合は利用側が新 session 開始

### 6.5 Byzantine signer の扱い

- session mode: signer は信頼前提 (利用側の選出責任)。疑義あれば **新 session + 旧 chain 破棄**
- committee mode: signer が 2 つの block に署名 (equivocation) → proof が他 signer から提出された時点で set から除名
- Codex core に slashing 経済は無いため、除名は運用レベル

### 6.6 Session → domain chain checkpoint

Session chain (ephemeral、match 中のみ稼働) の最終状態を **domain chain (long-lived) に anchor** する仕組み。L2 rollup の state commitment と同じ構造。

#### 6.6.1 形式: `codex.system.Checkpoint` event

Checkpoint は独自 header 拡張ではなく、**domain chain 上の通常 event** として実装する:

```rust
// codex.system.Checkpoint の body (postcard serialize)
pub struct CheckpointBody {
    /// session chain の ID (後述 §6.6.2 で deterministic に導出)
    pub session_chain_id: ChainId,

    /// session chain の最終 block height
    pub final_height: u64,

    /// session chain の最終 state_root
    pub final_state_root: Blake3Hash,

    /// session chain の最終 header の hash (chain tip 確定)
    pub final_header_hash: Blake3Hash,

    /// session producer の PeerId
    pub producer: PeerId,

    /// final_header_hash への producer 署名 (session mode)
    /// committee mode では attestations: Vec<Attestation> を body に持つ
    pub producer_attestation: Ed25519Signature,
}
```

この event を **session producer 自身が `claimant`** として domain chain に submit する。domain chain の STF が通常通り validate + apply → ブロック確定で checkpoint が anchor される。

#### 6.6.2 session_chain_id の導出

session chain は ephemeral なので genesis を都度作るが、ID は deterministic に:

```
session_chain_id = blake3(
    dom::CHAIN_ID         // 予約 tag
    ‖ domain_chain_id     // 親 domain chain
    ‖ session_start_ms    // u64
    ‖ producer_peer_id    // 20 byte
)
```

- 誰でも同じ入力から同じ ID を再計算可能 = verifiable
- 同 producer が同じ timestamp で 2 session は作れない (ID 衝突) = misuse 防止

#### 6.6.3 Fraud proof は不要

Ethereum の optimistic rollup は fraud proof で state 妥当性を検証するが、Codex は以下により **署名検証のみで finality** が取れる:

- **session mode**: producer は authoritative / arbiter (Tessera §5.5.3)。検証済 signer の署名があれば state_root は正当
- **mesh rollback 連携**: Tessera mesh プロファイルでは全 peer が決定論 sim で同一 state に到達している前提。producer は代表として署名するだけ
- **committee mode**: N/2+1 の attestation が body に含まれるため、多数決で妥当性が担保される

したがって challenge window / fraud proof 機構は v0 で実装しない。

#### 6.6.4 Checkpoint の検証 (cross-chain trace)

「この event が session S に含まれ、S は domain chain D に checkpoint された」を証明する手順:

```
1. target_event → session chain の ExistenceProof (§5.4.3)
   → session の final_header_hash まで連結可能を確認
2. session final_header_hash → CheckpointBody に含まれる値と一致
3. Checkpoint event → domain chain の ExistenceProof
   → trusted domain header まで連結可能
4. 全署名 (target_event.sig, session_producer_attestation, domain_header_sig)
   を検証
```

→ **cross-chain verification は 2 回の SPV + 署名 3 段** で完結。light client が 1 RTT で取得できる情報量で十分。

#### 6.6.5 v0 の制約と v1+ への展望

- **v0**: final checkpoint のみ (session 終了時の 1 回)
- **v1+ で検討**: interim checkpoint (定期的な進行中 state commit、長時間 session 向け) / multi-hop checkpoint (session → intermediate chain → domain chain) / zk 圧縮

### 6.7 Committee validator 変更プロトコル

committee mode (§6.2) の validator set 変更には 2 つの経路を設ける。**計画変更は予告制 (`ValidatorSetChange`)、punitive 除名は equivocation proof による即時 (`ValidatorSlash`)**。

#### 6.7.1 `codex.system.ValidatorSetChange` — 予告制の計画変更

```rust
pub struct ValidatorSetChangeBody {
    pub change_type:        ChangeType,
    pub effective_at_height: u64,     // 現 height + N_ANNOUNCE_MIN (v0: 8) 以上必須
    pub rationale:          Option<String>,  // ログ向け、validation 無視
    pub attestations:       Vec<Attestation>, // 現 committee の N/2+1 署名
}

pub enum ChangeType {
    Add(PeerId),
    Remove(PeerId),
    Replace { old: PeerId, new: PeerId },
}
```

**検証規則**:
1. attestations は **現 committee** の member 署名のみ受理、N/2+1 以上必要
2. `effective_at_height >= current_height + 8` (予告猶予期間)
3. 適用後の committee size が **3 以上** を維持すること (§6.7.3)
4. 同一 PeerId に対する未解決の Change 予告が存在しない (衝突防止)

**適用タイミング**: block apply 時、`block.height == effective_at_height` に到達した最初の block で committee set 更新。その block までの attestation は旧 set で検証、次 block からは新 set。

**典型運用**: 運営が "来月から validator X を新規追加" のようなガバナンス操作。Byzantine 疑惑中も予告期間内に別措置を取れる余裕がある。

#### 6.7.2 `codex.system.ValidatorSlash` — equivocation による即時除名

```rust
pub struct ValidatorSlashBody {
    pub offender: PeerId,
    pub evidence: EquivocationProof,
}

pub struct EquivocationProof {
    pub header_a: BlockHeader,  // 同じ chain_id + height
    pub sig_a:    Ed25519Signature,
    pub header_b: BlockHeader,  // header_a と異なる header_hash
    pub sig_b:    Ed25519Signature,
}
```

**検証規則**:
1. `header_a.chain_id == header_b.chain_id && header_a.height == header_b.height`
2. `blake3(header_a) != blake3(header_b)` (実際に異なる内容)
3. `sig_a` / `sig_b` が **両方とも offender の公開鍵で検証成功**
4. offender が現 committee に属している
5. 適用後の committee size が **3 以上** を維持すること (維持できない場合は slash 保留、ガバナンス経由の別措置へ誘導)

**提出権限**: **任意の full node が提出可能**。自動化できる (node が equivocation を観測したら proof を組んで slash event を自動 submit)。

**適用タイミング**: 提出 block 適用と同時に即時除名。予告なし。

**経済的 slashing は無し**: LUDIARS 運用の committee は経済 stake を持たないため、除名のみでペナルティとする。

#### 6.7.3 Committee size guard (size < 3 禁止)

どちらの event でも、適用後の size が 3 未満になる変更は validate で reject する。

**理由**: BFT の 2/3 + 1 は最小 3 から成立する (`2/3 * 3 = 2`, `+1 = 3 全員` 合意)。size 2 以下では単一の Byzantine signer で finality を妨害できる。

**緊急時の fail-safe**: size が 3 ギリギリまで減った運用では、**新規 validator の Add を最優先**させるため ValidatorSetChange の effective_at_height を通常より短くするフラグを v1+ で検討 (`EMERGENCY_ADD` フラグ、N_ANNOUNCE_MIN=1)。v0 では固定 8 block。

#### 6.7.4 運用ガイドライン

- **committee 初期 size 5–9 推奨** (余裕を持たせ、Byzantine 除名後も 3 下回らない)
- **slash は議論を招きやすい** (誤認識の equivocation proof がバグの可能性) → event 適用前に `ValidatorSetChange.rationale` で予告経緯を残すことを強く推奨
- **新 validator 追加は N_ANNOUNCE_MIN を上回る予告** を慣例化 (32 block 等)、信頼醸成期間を確保

## 7. ネットワーク

### 7.1 Event propagation (mempool gossip)

- 利用側が `submit_event()` で full node の mempool に投入
- 接続先 full node から gossip で他 node に拡散 (Synergos gossipsub 流用)
- producer は自ノード mempool から優先度順に block に取り込む

### 7.2 Block propagation

- 生成した block は producer が gossip で broadcast
- light client は block header のみ購読 (body は必要時 pull)
- block size 目安: 500 ms × 1000 evt/s × 200 byte/evt ≈ 100 KB/block、header は 300 byte

### 7.3 Sync プロトコル

| mode | 内容 | 用途 |
|---|---|---|
| **full sync** | genesis から全 block + events 取得 | audit / 新規 full node |
| **fast sync** | checkpoint header + state snapshot + 以降の block | 新規 full node 高速起動 |
| **light sync** | 最新 header chain のみ、events は on-demand | モバイル主用途 |
| **state sync** | 特定 key の proof 付き値のみ | ゲーム UI / dashboard |

### 7.4 新興網最適化

1. **Header の zstd 圧縮** — 連続 header は prev_hash 以外ほぼ冗長、実測 1/4
2. **並列 header fetch** — light client は複数 full node から同時に取得し最速応答採択
3. **delta checkpoint** — fast sync 時、前回 checkpoint からの差分のみ
4. **adaptive pull** — RTT/loss を見て pull 間隔を 500 ms–5 s で動的に伸縮
5. **offline grace** — 切断中は最後の header を信頼、復帰時に差分 catch-up

## 8. Light client (モバイル最重要)

### 8.1 SPV (Simplified Proof Verification)

「event E は block B (height H, root R) に含まれる」を light client が検証:

```
full_node → light:  Proof { event: E, merkle_path: [...], header: B.header }
light_client:
  1. verify E.sig (ed25519)
  2. compute leaf = blake3(dom::LEAF ‖ ns ‖ event_canonical_hash)  // §5.4.2
  3. walk merkle_path using node_hash() folding → computed_root
  4. assert computed_root == B.header.events_root
  5. verify B.header.producer_sig (+ attestations if committee)
  6. verify B.header chains back to trusted checkpoint
→ O(log N) hashes、P50 < 20 ms (ARM v7)
```

### 8.2 State proof

「state において (namespace, key) の value は V である (at block B)」を検証:

```
full_node → light: ExistenceProof (§5.4.3) または NonExistenceProof
light:
  存在証明: §5.4.3 の検証手順に従う (leaf_hash 再計算 → sibling 折畳み → state_root 照合 → header chain 検証)
  非存在証明: left/right neighbor の存在証明 + adjacency 検証
→ "私は block H の時点でこの right を持っていた" / 持っていなかった を証明可能
```

### 8.3 Subscription (push 配送)

light client が関心ある `(namespace, key_pattern)` を subscribe:

- full node は新 block 適用後、マッチする state 変化を proof 付きで push
- subscription は軽量、数十件までなら帯域無視可能
- mobile app は「自分の rights」+「watching されてる対戦相手」を subscribe しておけば常に最新

### 8.4 Checkpoint trust

- light client は genesis + periodic trusted checkpoint header を bundled config で持つ
- そこから header chain を伸ばす
- bootstrap trust: LUDIARS の公開 checkpoint 署名者を app がデフォルト信頼 (opt-out 可)

## 9. API

### 9.1 Full node — namespace 登録 & 投入

```rust
impl Node {
    /// domain handler 登録。Codex core 起動時に利用側 crate が呼ぶ
    fn register_namespace(
        &mut self,
        ns: Namespace,
        handler: Box<dyn NamespaceHandler>,
    );

    /// Event 投入 (mempool)。戻り値は受理 / 検証エラー
    async fn submit_event(&self, evt: Event) -> Result<EventHash, SubmitError>;

    /// 現在 state の読み出し (full node 上の確定値)
    fn state_get(&self, ns: &Namespace, key: &Blake3Hash) -> Option<Bytes>;

    /// light client 向け proof 生成
    fn event_proof(&self, hash: EventHash) -> Option<EventProof>;
    fn state_proof(&self, ns: &Namespace, key: &Blake3Hash) -> Option<StateProof>;
}

trait NamespaceHandler {
    fn validate(&self, evt: &Event, state: &State) -> Result<(), ValidationError>;
    fn apply(&self, evt: &Event, state: &mut State);
}
```

### 9.2 Light client

```rust
impl LightClient {
    /// full node に接続し header chain を追随
    async fn connect(&mut self, endpoint: NodeEndpoint) -> Result<(), _>;

    /// 自分の right (=自 PeerId 絡み state) を subscribe
    async fn subscribe(&mut self, ns: Namespace, key_pattern: KeyPattern);

    /// 権威的 query (full node へ RPC + proof 検証)
    async fn query(&self, ns: &Namespace, key: &Blake3Hash) -> Result<Option<Bytes>, _>;

    /// event 検証 (proof 受取 → verify)
    fn verify_event(&self, proof: &EventProof) -> Result<&Event, VerifyError>;

    /// state proof 検証
    fn verify_state(&self, proof: &StateProof) -> Result<Option<&Bytes>, VerifyError>;
}
```

### 9.3 Third-party verifier

full node も light client も不要、**proof と header さえあれば検証可能**:

```rust
pub fn verify_event_proof(
    proof: &EventProof,
    trusted_header: &BlockHeader,
) -> Result<&Event, VerifyError>;

pub fn verify_state_proof(
    proof: &StateProof,
    trusted_header: &BlockHeader,
) -> Result<Option<&Bytes>, VerifyError>;
```

この API が **Ethereum-like verification** の核心。外部監査 / 司法 / ユーザ自身が独立に確認できる。

## 10. セキュリティ

| 脅威 | 対策 |
|---|---|
| Event なりすまし | ed25519 署名 + nonce 単調性 |
| Replay | (claimant, namespace, nonce) tuple 一意性強制 (§5.2.2)。nonce gap は許容、重複のみ拒否 |
| Double-spend (同 right を二重) | STF の validate() で namespace handler が検出 |
| Block なりすまし | producer_sig 検証 + chain_id 検証 + prev_hash 検証 |
| Byzantine producer (単 signer) | 運用選出 + 疑義発生時の session 再構築 |
| Byzantine signer (committee) | equivocation proof で除名 (§6.5) |
| DoS via event flood | rate limit per (claimant, namespace): 10 evt/s 既定 |
| Light client を欺く | trusted checkpoint + chain 連結性検証 + 重複 full node からの cross-check |
| Proof 改竄 | merkle tree の暗号学的性質により検出 |
| Nonce 飛ばし | namespace handler の前提条件チェック / skip 許容モード設定可 |

## 11. Crate 構成

```
codex/
├── codex-core          # Event, Block, Header, Namespace, EventHash (no_std ok)
├── codex-crypto        # synergos-crypto のファサード + domain-separation 定数 (no_std ok、§11.1)
├── codex-state         # State tree (sorted-key binary merkle)、STF loop
├── codex-consensus     # session (single signer) + committee (PoA)
├── codex-net           # QUIC + gossip + RPC (synergos-net 利用)
├── codex-sync          # full / fast / light sync プロトコル
├── codex-node          # full node (mempool + producer + verifier)
├── codex-light         # light client (header chain, SPV)
├── codex-rpc           # RPC API 型定義 (外部利用含む)
├── codex-cli           # 管理 CLI
├── codex-ffi           # C ABI (Unity / Godot / iOS / Android 向け)
└── codex-domain-examples/
    ├── game-rights     # Tessera が使う namespace (reference)
    └── asset-ledger    # Curare が使う namespace (reference)
```

### 11.1 `codex-crypto` — 独立実装 (v0.6 で方針改訂)

**方針**: `ed25519-dalek` + `blake3` に直接依存する独立 crate。Synergos に synergos-crypto crate は存在しない (crypto が synergos-net に埋込) ため、v0.4 で検討した facade 方針は撤回。

```rust
// codex-crypto/src/lib.rs
#![no_std]
extern crate alloc;

pub use ed25519_dalek::{SigningKey, VerifyingKey, Signature, Signer, Verifier};
pub use blake3::{Hash as Blake3Hash, Hasher as Blake3Hasher};

/// 20-byte binary PeerId (§5.1)
#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub struct PeerId(pub [u8; 20]);

impl PeerId {
    pub fn from_public_key(pubkey: &[u8; 32]) -> Self {
        let h = blake3::hash(pubkey);
        let mut out = [0u8; 20];
        out.copy_from_slice(&h.as_bytes()[..20]);
        Self(out)
    }
}

/// Codex 固有の domain-separation 定数
/// merkle leaf / internal / header 署名ごとに別プレフィクスで second-preimage 耐性を確保
pub mod dom {
    pub const LEAF:      &[u8; 16] = b"LUDIARS-CDX-L001";
    pub const INTERNAL:  &[u8; 16] = b"LUDIARS-CDX-N001";
    pub const BLOCK_SIG: &[u8; 16] = b"LUDIARS-CDX-B001";
    pub const EVENT_SIG: &[u8; 16] = b"LUDIARS-CDX-E001";
    pub const CHAIN_ID:  &[u8; 16] = b"LUDIARS-CDX-C001";  // session_chain_id 導出 (§6.6.2)
}
```

**Synergos との関係**:

- **PeerId は byte-level で同値** — Synergos `PeerId(pub String)` は同じ 20 byte を hex 化、Codex `PeerId([u8; 20])` は binary。相互変換は `hex::encode` / `hex::decode` で O(1)
- **Ed25519 / Blake3 実装は同じ crate** — `ed25519-dalek` と `blake3` を両プロジェクトが直接使う
- **将来の共通化パス**: Synergos が `synergos-net` から crypto を切り出して crate 化した段階で、`ludiars-crypto` 共通 crate を立ち上げ、Codex と Synergos 両方が依存する構造に移行可能 — **本 v0 では独立を保つ**

**v0 で独立実装を選ぶ根拠**:

1. Synergos 側 refactor を Codex M0 着手の前提にすると作業が直列化し、Codex 単独の進捗がブロックされる
2. Synergos の PeerId は文字列 wrapper、Codex は merkle proof 等で binary を多用 → 型選択の自然な方向が異なる
3. 両者の暗号要件 (P2P identity / event signing) は十分近く、`ed25519-dalek` + `blake3` を両者が並列に使っても divergence リスクは低い
4. 将来の共通化は facade 層か ludiars-crypto crate でいつでも可能、現時点で前倒し統合する利得がない

**外部依存**:
- `ed25519-dalek` (crates.io)
- `blake3` (crates.io)
- `hex` (表示用、feature flag で optional)

## 12. 依存関係

再利用:
- `synergos-net`: QUIC / gossipsub / connection migration (crypto は共有せず、transport のみ)

直接依存 (crates.io):
- `ed25519-dalek`: 署名
- `blake3`: hash / merkle
- `hex`: PeerId 表示 (optional)
- `quinn`: QUIC (synergos-net と同 crate 共有)
- `postcard` + `serde`: Event / Block シリアライズ
- `tokio`: runtime

新規想定:
- `rs_merkle` または自前: sorted-key binary merkle
- `dashmap`: mempool concurrent

## 13. テスト戦略

- **unit**: Event / Block シリアライズ round-trip、STF 決定論、merkle proof 構築/検証
- **integration**: 1 full node + 10 light client × 60 s、全 proof 検証成功
- **consensus**: committee mode で signer 1 人 Byzantine 時の equivocation 検出
- **emerging-network**: tc/netem で RTT 400 ms / loss 15% / 256 kbps、light client が 3s 以内に最新 header 到達
- **feature-phone**: ARMv7 / RAM 2GB 実機で SPV P50 < 20 ms
- **fuzzing**: Event デコード / merkle proof 検証 に cargo-fuzz

## 14. マイルストーン

| M | 内容 | 期間目安 |
|---|---|---|
| **M0** | `codex-core` + `codex-crypto` 型定義、Event/Block シリアライズ round-trip テスト | 1w |
| **M1** | `codex-state` sorted-key merkle + STF (namespace handler skeleton) | 1w |
| **M2** | `codex-consensus` session mode (single signer) + block 生成ループ | 1w |
| **M3** | `codex-node` full node (mempool + producer + verifier) 1 プロセスで動作 | 2w |
| **M4** | `codex-sync` full / fast sync、2 full node 間で state_root 一致 | 1w |
| **M5** | `codex-light` light client + SPV、モバイル実機で header 追従 | 2w |
| **M6** | `codex-consensus` committee mode + attestation / equivocation proof | 2w |
| **M7** | domain examples (game-rights, asset-ledger) + integration with Tessera | 1w |
| **M8** | 新興網プロファイル検証 + feature-phone bench + fuzz CI | 1w |
| **M9** | `codex-ffi` + モバイル SDK 雛形 | 2w |

合計: ~14w (3.5 month) の目安。

## 15. 未決事項

- [x] ~~Merkle tree の最終選択~~ — **v0.5 で確定**: sorted-key binary (v0)、domain-separated leaf/internal encoding、ExistenceProof + NonExistenceProof 構造 (§5.4.1–5.4.3)。Sparse Merkle / Verkle 移行評価は M4 state_root 実測後
- [x] ~~Namespace 登録の運用 — 静的 config か、special namespace event で動的登録か~~ — **v0.7 で確定**: v0 は binary 組込 + static config (§5.6)、`codex.system` を予約。動的登録は v1+ 持ち越し
- [x] ~~Committee mode の validator 変更プロトコル詳細 — 2/3 合意で即変更か、epoch 境界でのみか~~ — **v0.9 で確定** (§6.7): 予告制 `ValidatorSetChange` (effective_at_height ≥ 現+8) + 即時 `ValidatorSlash` (equivocation proof 添付) の 2 経路。committee size < 3 になる変更は reject。slashing に経済罰なし、除名のみ
- [ ] Checkpoint 署名者の bootstrap trust — bundled public key vs PKI vs transparency log
- [x] ~~Session → domain chain の checkpoint 形式 — 1 event として埋込か、header extension か~~ — **v0.8 で確定**: `codex.system.Checkpoint` event として domain chain に submit (§6.6)。header extension は不採用 (SPV 複雑化回避)。fraud proof は session producer 信頼モデルにより不要。v0 は final のみ、interim は v1+
- [x] ~~`codex-crypto` は独立 crate 化か `synergos-crypto` 再エクスポートか~~ — **v0.4 で facade 方針決定、v0.6 で撤回して独立実装に改訂** (§11.1)。Synergos は synergos-crypto crate を持たず crypto が synergos-net に埋込のため前提不成立。ed25519-dalek + blake3 を直接依存する独立 crate として実装、PeerId は `[u8; 20]` binary (Synergos の hex string と byte-level 互換)。将来 Synergos 側 refactor 時に ludiars-crypto 共通化を検討
- [x] ~~Event の `parent` フィールド必要性~~ — **v0.2 で削除確定**。DAG 依存は namespace body に埋込 (§5.2.1)
- [x] ~~`nonce` の spacing~~ — **v0.3 で確定**: ユニーク性のみ必須、単調増加は推奨、gap 許容 (§5.2.2)
- [ ] Ethereum RLP 互換は追求するか — 第三者 verifier の言語多様性に効く反面、実装コスト増

## 16. Ethereum との距離感 (参考)

| Ethereum 機能 | Codex | 理由 |
|---|---|---|
| Merkle Patricia Trie | ❌ 採用せず | 実装コスト vs モバイル proof サイズの trade-off で binary merkle 優位 |
| RLP encoding | ❌ 採用せず | postcard で十分。互換性より簡便性 |
| Gas meter | ❌ 採用せず | 経済モデル無し、rate limit で代替 |
| EVM bytecode | ❌ 採用せず | validation は namespace handler で Rust 直書き |
| Casper FFG finality | ❌ 採用せず | single signer は 1 block finality で十分、committee は簡易 2/3 |
| uncle blocks | ❌ 採用せず | single producer モデルで発生しない |
| Light client (LES) | ✅ 近似採用 | SPV proof + header chain は素直に取り入れる |
| EIP-2930/1559 | ❌ | 経済モデル無し |
| Receipts trie | ✅ 相当物を採用 | events_root として埋込 |
| State trie | ✅ 採用 (簡略版) | state_root は必須 |

**Codex = "Ethereum の検証レイヤーだけを取り出し、PoA + domain handler で走らせる最小実装"**。

## 17. 参考

- Ethereum Yellow Paper (state transition / merkle trie 構造)
- EIP-225 Clique PoA (参考: single-signer 風 consensus)
- LibP2P gossipsub
- Synergos `synergos-net/src/lib.rs` (transport/crypto 連携)
- Tessera DESIGN.md §5.7 (extraction 元、設計経緯参照)
- rs-merkle, merkle-tree-rs (Rust 実装候補)
