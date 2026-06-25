# burn 🔥

ワンタイム秘密共有サービス（ゼロ知識・エッジ配信）。

パスワードや API キーといった秘密を、**一度開いたら消えるリンク**で相手に渡す。
秘密はブラウザ内で暗号化し、復号鍵は URL の `#` フラグメントに載せるため、
サーバー（Cloudflare）には**鍵なしの暗号文しか届かない**。運営者は中身を知り得ない。

詳細は [`docs/burn_design_spec.md`](docs/burn_design_spec.md)（仕様書）を参照。

## アーキテクチャ

```
ブラウザ（信頼境界の内側）           Cloudflare エッジ（外側）
 平文 → AES-256-GCM 暗号化   ──id+暗号文──▶  Worker(Hono) + KV
 鍵 = 乱数（#fragment、外に出ない）            鍵なしの blob を保管・ワンタイム破棄
```

- **Worker / Hono** (`src/index.ts`) — `/api/secret` の封緘・開封。鍵も平文も受け取らない。
- **KV** — `{ ct, iv, salt, maxViews, views, expiresAt }` の暗号文 blob を保管。
- **フロント** (`public/`) — Web Crypto による暗号化/復号 UI。静的アセットとして配信。
- **暗号モジュール** (`public/crypto.js`) — ブラウザとテストで共用する §4 の実装。

## セットアップ

```sh
npm install
```

### ローカル開発

```sh
npm run dev          # wrangler dev（ローカル KV が自動で立つ）
```

ブラウザで表示された URL を開き、秘密を封緘 → 生成されたリンクを別タブで開く。

### テスト

```sh
npm test             # vitest（実 workerd + ローカル KV で §12 受け入れ基準を検証）
npm run typecheck
```

### デプロイ

本番用の KV namespace を作成し、`wrangler.toml` の `id` を差し替える:

```sh
npx wrangler kv namespace create SECRETS
# 出力された id を wrangler.toml の [[kv_namespaces]] に貼る
npm run deploy
```

## API（§7）

| メソッド | パス | 用途 |
|---|---|---|
| `POST` | `/api/secret` | 封緘。`{ ct, iv, salt, maxViews, ttl }` → `201 { id }` |
| `GET` | `/api/secret/:id` | 開封 + ワンタイム破棄。`200 { ct, iv, salt, maxViews, views }` / `404 { error: "gone" }` |

- `ttl` は `"1h" | "24h" | "7d"`。サーバー側で `expiresAt`（絶対エポック秒）に変換。
- `maxViews` は 1〜10。閾値到達で `delete`、未達なら TTL を維持して再 `put`。

## 脅威モデル（要点・§5）

**守れる**: KV/ログ流出（鍵なし暗号文のみ）、運営者の受動閲覧、暗号文の改竄（GCM タグ）、
リンク再利用（ワンタイム破棄＝傍受のトリップワイヤー）。

**守れない（範囲外）**: リンク送信経路の漏洩（→ パスフレーズを別経路で）、
悪意ある運営者による能動的バックドア JS 配信（ブラウザ E2E の根本限界。OSS/SRI で緩和）、
メタデータ（id・時刻・国・サイズ）、復号後の端末汚染。

## ワンタイム保証について（§10）

本実装は **KV（ベストエフォート）**。KV は結果整合のため、複数リージョンで同時に開くと
delete 伝播前に両方が読める可能性がある。厳密な exactly-once が必要なら `id` を
Durable Object にルーティングして read→burn を直列化する（将来拡張）。

## 受け入れ基準のテスト対応（§12）

| # | シナリオ | テスト |
|---|---|---|
| 1 | 封緘 → 開封で復号 | ✅ `§12-1` |
| 2 | 2回目開封（maxViews=1）→ gone | ✅ `§12-2` |
| 3 | 改竄 → badkey | ✅ `§12-3` |
| 4 | パスフレーズ誤入力 → badkey | ✅ `§12-4` |
| 5 | TTL 経過 → gone | KV 失効（手動/本番で確認） |
| 6 | maxViews=3、各回 TTL 維持 | ✅ `§12-6` |
| 7 | `#` 以降がサーバーに現れない | 設計（フラグメントは送信されない・手動監査） |
| 8 | KV ダンプに鍵・平文なし | ✅ `§12-8` |

## ライセンス

未定（OSS 化は §5.3 の緩和策として推奨）。
