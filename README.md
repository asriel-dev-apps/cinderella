# Cinderella 🔥

一度きりの秘密共有サービス（ゼロ知識・エッジ配信）。

パスワードや API キーといった秘密を、**一度開いたら消えるリンク**で相手に渡す。
秘密はブラウザ内で暗号化し、復号鍵は URL の `#` フラグメントに載せる。
サーバー（Cloudflare）には**鍵なしの暗号文しか届かない**ため、運営者は中身を知り得ない。

設計の詳細は [`docs/design_spec.md`](docs/design_spec.md) を参照。

## アーキテクチャ

```
ブラウザ（信頼境界の内側）              Cloudflare エッジ（外側）
 平文 → AES-256-GCM 暗号化   ──id+暗号文──▶  Worker(Hono) + KV
 鍵 = 乱数（#fragment、外に出ない）            鍵なしの暗号文を保管・ワンタイム破棄
```

- **Worker / Hono** (`src/index.ts`) — `/api/secret` の作成・開封。鍵も平文も受け取らない。
- **KV** — `{ ct, iv, salt, maxViews, views, expiresAt }` の暗号文レコードを保管。
- **フロント** (`public/`) — Web Crypto による暗号化/復号 UI。静的アセットとして配信。
- **暗号モジュール** (`public/crypto.js`) — ブラウザとテストで共用する暗号処理。

## セットアップ

```sh
npm install
```

### ローカル開発

```sh
npm run dev          # wrangler dev（ローカル KV が自動で立つ）
```

ブラウザで表示された URL を開き、秘密を作成 → 生成されたリンクを別タブで開く。

### テスト

```sh
npm test             # vitest（workerd + ローカル KV で実行）
npm run typecheck
```

### デプロイ

本番用の KV namespace を作成し、`wrangler.toml` の `id` を差し替える:

```sh
npx wrangler kv namespace create SECRETS
# 出力された id を wrangler.toml の [[kv_namespaces]] に貼る
npm run deploy
```

## API

| メソッド | パス | 用途 |
|---|---|---|
| `POST` | `/api/secret` | 作成。`{ ct, iv, salt, maxViews, ttl }` → `201 { id }` |
| `GET` | `/api/secret/:id` | 開封 + ワンタイム破棄。`200 { ct, iv, salt, maxViews, views }` / `404 { error: "gone" }` |

- `ttl` は `"1h" | "24h" | "7d"`。サーバー側で `expiresAt`（絶対エポック秒）に変換。
- `maxViews` は 1〜10。上限到達で `delete`、未達なら TTL を維持して再 `put`。

## 脅威モデル（要点）

**守れる**: KV/ログ流出（鍵なし暗号文のみ）、運営者の受動的閲覧、暗号文の改竄（GCM 認証タグ）、
リンク再利用（ワンタイム破棄が傍受のトリップワイヤーになる）。

**守れない（範囲外）**: リンク送信経路の漏洩（パスフレーズを別経路で渡して緩和）、
悪意ある運営者による能動的なバックドア JS 配信（ブラウザ E2E の根本的な限界）、
メタデータ（id・時刻・国・サイズ）、復号後の受信端末上の平文。

## ワンタイム保証について

本実装は KV を用いたベストエフォート。KV は結果整合のため、複数リージョンで同時に開くと
delete の伝播前に両方が読める可能性がある。厳密な exactly-once が必要なら `id` を
Durable Object にルーティングし、read→burn を直列化する（将来拡張）。

## テストでカバーするシナリオ

| シナリオ | 状態 |
|---|---|
| 作成 → 開封で復号できる | ✅ |
| 2 回目の開封（maxViews=1）→ gone | ✅ |
| 暗号文の改竄 → 復号失敗 | ✅ |
| パスフレーズ誤入力 → 復号失敗 | ✅ |
| maxViews=3、各回で TTL 維持 | ✅ |
| KV ダンプに鍵・平文が含まれない | ✅ |
| TTL 経過 → gone | KV 失効（本番で確認） |
| `#` 以降がサーバーに送信されない | 設計上保証 |

## ライセンス

未定。
