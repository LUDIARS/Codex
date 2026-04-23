# Codex 設計書

> 版: 0.3 — 2026-04-23
> 著者: kazmit299
> ステータス: 設計ドラフト (実装未着手)
>
> **変更履歴**
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

- **PeerId**: `blake3(ed25519_public_key)[..32]` — Synergos 流用。32 byte。
- **Account**: 状態は PeerId 単位ではなく **(namespace, key) 単位** に持つ。Account 抽象は使わず、state は右 (Right) の集合として管理する (§5.4)。
- 署名は常に ed25519、peer の秘密鍵で。

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

状態 = **(namespace, key) → Value** の map。

```rust
type StateKey = (Namespace, Blake3Hash);  // key は namespace + right-specific key hash
type StateValue = Bytes;                   // namespace で schema 定義

struct StateTree {
    root: Blake3Hash,
    // 実装: binary merkle tree (sparse) または sorted-key merkle
}
```

**Merkle tree の選択** (§15 で確定、暫定方針):

- v0: **sorted-key binary merkle** — シンプル、proof サイズ log N
- v1 (将来): Verkle tree or Sparse Merkle Tree — proof を定数化

Ethereum MPT の radix-16 Patricia は実装コストが重く、モバイル light client の proof decode も重いので v0 では採用しない。

### 5.5 State transition function (STF)

```
state_t+1 = apply(state_t, block)
  for event in block.events (in order):
    validate(event, state)  → must pass
    state = apply_event(state, event)
  return state
```

- `validate`: 署名検証、nonce 単調性、parent 存在、namespace 手続きの事前条件
- `apply_event`: namespace 登録済の handler を呼び state を変異
- **決定論必須**: 同一 (state_t, block) は必ず同じ state_{t+1} を出す → state_root が全 participant で一致

namespace handler は **Codex core には入れず、利用側 crate が register する** (§9.1)。

## 6. Consensus と block production

### 6.1 Session mode (single signer)

- 1 つの `producer` が全 block を署名
- producer = game server (authoritative) or arbiter (mesh、Tessera §5.5.3)
- Finality は **single-block**: signer の署名があれば確定
- Block 生成間隔: **500 ms 既定、100–2000 ms で設定可能**
- Throughput: producer 能力に依存、~10k evt/s 目安

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
- **committee**: 事前設定の固定 set。変更は committee 自身の `ValidatorSetChange` event で決議
- **fail-over**: producer 応答 timeout (3s) → committee の場合は next round の proposer がスキップ役目を引き継ぐ / session の場合は利用側が新 session 開始

### 6.5 Byzantine signer の扱い

- session mode: signer は信頼前提 (利用側の選出責任)。疑義あれば **新 session + 旧 chain 破棄**
- committee mode: signer が 2 つの block に署名 (equivocation) → proof が他 signer から提出された時点で set から除名
- Codex core に slashing 経済は無いため、除名は運用レベル

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
  2. compute leaf = hash(E)
  3. walk merkle_path, folding hashes → computed_root
  4. assert computed_root == B.header.events_root
  5. verify B.header.producer_sig (+ attestations if committee)
  6. verify B.header chains back to trusted checkpoint
→ O(log N) hashes、P50 < 20 ms (ARM v7)
```

### 8.2 State proof

「state において (namespace, key) の value は V である (at block B)」を検証:

```
full_node → light: StateProof { key, value, merkle_path, header }
light:
  1. compute leaf = hash(key, value)
  2. walk merkle_path → computed_root
  3. assert computed_root == header.state_root
  4. verify header chain
→ "私は block H の時点でこの right を持っていた" が証明可能
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
├── codex-crypto        # ed25519, blake3, merkle (no_std ok, synergos-crypto 再エクスポート想定)
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

## 12. 依存関係

再利用:
- `synergos-crypto` (想定): ed25519 / blake3
- `synergos-net`: QUIC / gossipsub / connection migration
- `quinn`: QUIC
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

- [ ] Merkle tree の最終選択 — v0 で sorted-key binary を採用するが、Sparse Merkle / Verkle への移行判断の材料 (proof サイズ・生成コスト) を M4 で計測
- [ ] Namespace 登録の運用 — 静的 config か、special namespace event で動的登録か
- [ ] Committee mode の validator 変更プロトコル詳細 — 2/3 合意で即変更か、epoch 境界でのみか
- [ ] Checkpoint 署名者の bootstrap trust — bundled public key vs PKI vs transparency log
- [ ] Session → domain chain の checkpoint 形式 — 1 event として埋込か、header extension か
- [ ] `codex-crypto` は独立 crate 化か `synergos-crypto` 再エクスポートか
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
