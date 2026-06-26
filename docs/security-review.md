# セキュリティレビュー結果

| 項目 | 内容 |
|---|---|
| 対象 | コミット `647f9a6`（Durable Object 化・レート制限・セキュリティヘッダ・入力検証の強化） |
| レビュアー | Claude Opus 4.8 ／ Codex（独立並行レビュー） |
| 実施日 | 2026-06-26 |
| 検証 | `npm test`（17/17 合格）・`npm run typecheck`（クリーン）。コード改変なしの読み取りレビュー |

## 総括

- **Critical はゼロ。** 鍵・平文の露出なし、認証バイパスなし、二重開封レースなし。
- exactly-once（read→burn の原子性）・CSP・期限切れ非提供・`maxViews` ロジックは**両レビューとも「正しい」と確認**。
- 残課題は主に **Medium の可用性・濫用系**：レート制限がフェイルオープン＆未検証、無料枠クォータの枯渇、Content-Length 依存の早期 413 がバイパス可能、`_headers` が API 応答に未適用。
- **コスト面**: Free プラン据え置きである限り課金は発生しない。Medium はいずれも「枯渇するとその日サービス停止」という**可用性リスクであって請求リスクではない**。

## 対応状況

下表のとおり、コードで対処可能な指摘はすべて反映済み。検証は `npm test`（35/35 合格。期限切れ・並行exactly-once・DO障害503・ゼロ知識応答の検証を含む）・`npm run typecheck`（クリーン）・`wrangler deploy --dry-run`（レート制限バインディングの配線を確認）。M2 のみ Cloudflare 管理画面側の運用設定が本体のため、コードでは二次防御に留め、手順を「[本番デプロイ時のハードニング（M2）](#本番デプロイ時のハードニングm2運用)」に記載した。

| ID | 状態 | 対応内容 |
|---|---|---|
| M1 | ✅ コード対応 | `readBodyCapped()` で本文をバイト数で数え、上限超過はパース前に打ち切り（Content-Length 非依存）。早期 413 は一次ゲートとして併用。Content-Length なしのストリーム経路で 413 になるテストを追加。 |
| M2 | ⚠️ 運用対応＋二次防御 | 根本対策はエッジ WAF（管理画面）。コード側は M3/M4 の強化で二次防御。手順は下記付録。 |
| M3 | ✅ コード対応 | `rateLimitKey()` で IPv6 を /64 に正規化。**圧縮表記（`::`）も展開**して集約する（`2001:db8::1`/`::5` 等が同一キー）。colo 単位という設計上の限界はコメントで明記。 |
| M4 | ✅ コード対応 | `denyByRateLimit()` に集約。バインディング欠落時／limiter 例外時はフェイルオープン＋初回警告ログ。スタブ注入で 429 を検証するテストを追加。 |
| M5 | ✅ コード対応 | 全応答に HSTS / Referrer-Policy / nosniff を付与する Hono ミドルウェアを追加。 |
| L1 | ✅ コード対応 | `isB64url` が `length % 4 === 1`（到達不能長）を拒否。17 文字 IV は 400。 |
| L2 | ✅ コード対応 | 破棄処理を `destroy()` に集約し `deleteAll()` ＋ `deleteAlarm()`。`deleteAlarm()` は消費成立後の後始末なので best-effort（失敗は警告のみ）。期限 `alarm()` 失敗時はランタイムの自動再試行に委ねるため握り潰さない。 |
| L3 | ✅ コード対応 | `create()` は既存レコードがあれば `false` を返し上書きしない。POST 側で id 再生成リトライ。 |
| L4 | ✅ コード対応 | DO 呼び出しを try/catch し、キャッシュ抑止付きの 503 を返す。 |
| L5 | ✅ コード対応 | レート制限が有効で `CF-Connecting-IP` 欠落時はフェイルクローズ（429）。 |

> **テスト環境に関する注意**: `@cloudflare/vitest-pool-workers`（miniflare）は `[[ratelimits]]` を未サポートで、テスト実行時に `Unexpected fields found in top-level field: "ratelimits"` と `rate limiter ... not bound` 警告が出る。テスト中はレート制限が実質 OFF のため、429 系はスタブ注入で検証している。**本番の配線は `wrangler deploy --dry-run` で両バインディングが Rate Limit として認識されることを確認済み**。

## 指摘一覧（両レビュー統合・重複排除）

重大度順。行番号は対象コミット時点。対応状況は上表を参照。

### M1 — ボディサイズ上限が Content-Length 欠落でバイパス可能
- **重大度**: Medium（Opus M4 ／ Codex #3）
- **場所**: `src/index.ts`（Content-Length チェック → `c.req.json()`）
- **シナリオ**: `Content-Length` を省く（chunked 転送）か非数値にすると早期 413 を素通りし、`ct` 長チェックの前に本文をバッファ＆JSON パースまで実行。巨大ボディの反復で CPU/メモリを消費。レート制限がフェイルオープンだと前段ゲートも無いため無制限。
- **修正**: Content-Length を信頼せず、ストリームをバイト数で数えて上限超過で打ち切ってからパースする。レート制限ゲートをパースより前に厳格化。

### M2 — 無料枠クォータの枯渇による可用性 DoS
- **重大度**: Medium（Opus M2/M3 ／ Codex #2/#6）
- **場所**: `src/index.ts`（GET/POST ハンドラ）・`wrangler.toml`
- **シナリオ**: レート制限は Worker 内で動くため、ブロックされた呼び出しも Worker invocation を消費。形式が正しいだけの存在しない id への GET は `ID_PATTERN` を通過し DO を起動（`idFromName`+`read`）して DO クォータを消費。分散 IP・複数 colo で 1 日分の無料枠を食い潰し、正規ユーザーが 5xx になる。
- **修正**: Worker の手前で効く **エッジ WAF レート制限ルール**を入れ、フラッディングが Worker/DO クォータを消費しないようにする。バインディングのレート制限は二次防御として併用。Turnstile／グローバルカウンタ／日次ハードキャップも検討。

### M3 — レート制限のキーが弱い（IPv6 /128・colo 単位）
- **重大度**: Medium（Opus M3）
- **場所**: `src/index.ts`（`CF-Connecting-IP` をキーに）・`wrangler.toml`
- **シナリオ**: IPv6 は /64 以上を保有するため 1 アドレスごとに新しいバケットになり 10/分 制限を回避可能。さらにカウンタは colo 単位のため実効上限は `limit × colo 数`。分散クライアントで上限が大幅に増える。
- **補足（良い点）**: `CF-Connecting-IP` はエッジが設定し**クライアント偽装不可**。被害者の IP を詐称してロックアウトする攻撃は**不可能**。
- **修正**: キーを IPv6 /64 プレフィックスに正規化。colo 単位という設計上の上限を明記し、ハードな全体上限はエッジ WAF に委ねる。

### M4 — レート制限がフェイルオープン＆テスト未カバー
- **重大度**: Medium（Opus M1 ／ Codex 2b）
- **場所**: `src/index.ts`（`if (c.env.CREATE_LIMITER) { … }` の任意ガード）
- **シナリオ**: バインディング欠落時（namespace 誤設定・環境差・wrangler 構成のずれ）はログも警告もなくレート制限を完全スキップ（フェイルオープン）。テストハーネス（vitest-pool-workers）は `ratelimits` を未知フィールドとして無視するため、レート制限経路は一度も実行されておらず、回帰がグリーンのまま出荷され得る。
- **修正**: スタブを注入して 429 を検証するテストを追加。フェイルオープン/クローズを明示的に決め、本番でバインディング欠落時は起動時に一度ログ。vitest-pool-workers を wrangler 4.x に合わせて `ratelimits` が落ちないようにする。

### M5 — `_headers` が `/api/*` 応答に適用されない
- **重大度**: Medium（ほぼ無害）（Opus M5 ／ Codex #4）
- **場所**: `public/_headers`・`src/index.ts`
- **シナリオ**: `_headers` は静的アセットのみに作用。`/api/*` は Hono が応答するため CSP/HSTS/X-Frame-Options 等が付かず、`noStore()` の `Cache-Control`/`Pragma`/`nosniff` のみ。JSON 応答なのでほぼ無害だが、**HSTS が全応答に乗らない**のが実質的なギャップ。
- **修正**: API 応答にも HSTS と `Referrer-Policy: no-referrer` を付ける小さな Hono ミドルウェアを追加。`_headers` に API カバレッジを依存しない。

### L1 — IV の長さ検証が 17 文字を許容
- **重大度**: Low（Opus L1）
- **場所**: `src/index.ts`（`isB64url` ＋ `b64urlBytes`）
- **シナリオ**: `isB64url` は文字種のみ検証し `length % 4 !== 1` を弾かない。`b64urlBytes = floor(len*3/4)` は長さ 16（正・12B）と 17（不正）の両方で 12 を返すため、17 文字 IV が通過。サーバは復号しないので影響は「復号不能なレコードが保存される」のみ（クライアントで "Couldn't open"）。サーバ側悪用は不可。
- **修正**: 文字列長を厳密化（IV=16、salt=22）するか、`isB64url` に `length % 4 !== 1` を追加。

### L2 — burn 時に alarm を解除しない／alarm 失敗で期限切れデータが残る
- **重大度**: Low（Opus L2/L5 ／ Codex 1b）
- **場所**: `src/secret-store.ts`（`read()` の `deleteAll()`、`alarm()`）
- **シナリオ**: `create()` で `expiresAt` に alarm を設定するが、早期 burn 時に `deleteAlarm()` を呼ばない。SQLite バックエンドが `deleteAll()` で alarm も消さない場合、消費済みの秘密ごとに将来の無駄な起動＋書き込みが残り、TTL=7d などで蓄積し DO 書き込みクォータを圧迫。alarm が恒久的に失敗し再読込もされない場合、鍵なし暗号文が意図した期限を超えて残存（機密性は維持。`read()` が `expiresAt` を再チェックするため提供はされない）。
- **修正**: burn 時に `deleteAlarm()`。`alarm()` を try/catch し再スケジュール。

### L3 — `create()` が既存レコードを上書き（衝突ガードなし）
- **重大度**: Low（Opus L3 ／ Codex 1a）
- **場所**: `src/secret-store.ts`（無条件 `put`）
- **シナリオ**: 72bit 乱数 id の衝突（誕生日限界で実質無視可能）時、2 回目の `create()` が 1 件目を黙って破壊しリンクを無効化。実害可能性は極小だが堅牢性のため。
- **修正**: `if (await this.ctx.storage.get("record")) throw`、または POST 側で衝突時に id を再生成。

### L4 — DO/RPC 例外が未捕捉で 500
- **重大度**: Low（Opus L4）
- **場所**: `src/index.ts`（`stub.create` / `stub.read` 未ラップ）
- **シナリオ**: 一過性の DO エラーで Hono 既定の 500。情報漏洩はない（スタックなし）が、`noStore()` 未適用。
- **修正**: DO 呼び出しを try/catch し、優雅な 503 を返す。

### L5 — `CF-Connecting-IP` 欠落時に全員が `"unknown"` バケットを共有
- **重大度**: Low（Opus L6 ／ Codex 2c）
- **場所**: `src/index.ts`（`?? "unknown"`）
- **シナリオ**: ヘッダ欠落時は全リクエストが 1 バケットを共有し、互いのレートを消費し合う。本番では Cloudflare が常に付与するため実質理論上。被害者の標的ロックアウトには使えない。
- **修正**: 信頼できるクライアント識別子が無い場合はフェイルクローズ、または匿名用の保守的ポリシーを別途適用。

## 正しく実装されている点（壊さない）

- **exactly-once / read→burn の原子性**: `read()` は storage 操作のみを await するため DO の入力ゲートが閉じたまま直列化され、同一 id への同時 GET はキューされる。二重読み取り不可。※将来 `get` と `put`/`deleteAll` の間に `fetch()` 等の非 storage await を挟むと保証が崩れる点に注意（コメント推奨）。
- **CSP は完全で、実アプリが動作する**: 外部モジュールスクリプト・スタイルは同一オリジンで `script-src 'self'`/`style-src 'self'` 内。インライン JS/CSS なし。平文は `textContent` 描画で DOM-XSS なし。クリックジャッキングは `X-Frame-Options: DENY` ＋ `frame-ancestors 'none'` で封鎖。
- **KV 版からの有害な回帰なし**: `maxViews` の増分・再保存、応答形、`gone` 意味論を維持。`expiresAt` は漏らさない。形式不正 id は DO 到達前に短絡。
- **その他**: `setAlarm` は秘密ごとに 1 つで競合なし。RPC 値はシリアライズ可能。`CF-Connecting-IP` は偽装不可。PBKDF2 600k は OWASP 準拠（クライアント側のみ）。IV=12B/salt=16B は実クライアントの実エンコードに対しては厳密。

## 本番デプロイ時のハードニング（M2／運用）

M2（無料枠クォータの枯渇による可用性 DoS）の根本対策は Worker の手前＝**エッジ**で効かせる必要があり、コードでは完結しない。Worker 内のレート制限（バインディング）は Worker invocation を消費してから効くため、フラッディングの一次防御にはならない。以下を Cloudflare 管理画面で設定する。

1. **WAF レート制限ルール（最優先・無料枠で可）**
   - `Security → WAF → Rate limiting rules` で `/api/*` 宛てに IP 単位のルールを作成（例: 1 分あたり 60 リクエスト超で 1 分ブロック）。
   - エッジで遮断されるため、ブロックされたフラッディングが Worker/DO クォータを消費しない。バインディングのレート制限は二次防御として併用。
2. **存在しない id への GET フラッディング対策**
   - 形式が正しいだけの存在しない id への GET でも DO が起動する（`idFromName`+`read`）。上記レート制限ルールでカバーするほか、必要なら**日次のグローバル上限**（カウンタ用 DO 等）を検討。
3. **Turnstile（任意・濫用が顕在化したら）**
   - 作成（POST `/api/secret`）に Turnstile を挟み、自動化された大量作成を抑止。UX とのトレードオフで判断。
4. **アラート**
   - `observability` のメトリクスで Worker/DO の呼び出し急増・5xx 増加にアラートを設定し、枯渇前に気付けるようにする。

> 補足: 課金は Free プラン据え置きである限り発生しない。M2 は「枯渇するとその日サービス停止」という**可用性リスク**であって請求リスクではない。

## 優先対応順

> 下記は対象コミット時点の推奨順。現在は M2 の運用設定を除きすべて反映済み（[対応状況](#対応状況)参照）。

1. **M1** — Content-Length に依存しないハードなボディ上限（パース前にバイト数で打ち切り）
2. **M2** — エッジ WAF レート制限 ＋ グローバル濫用制御で無料枠クォータ枯渇を防止
3. **M3/M4** — キーを IPv6 /64 に、バインディング欠落時はフェイルクローズ、colo 単位を明記、429 のテスト追加
4. **M5** — API 応答にも HSTS / Referrer-Policy を付与するミドルウェア
5. **L2** — burn 時 `deleteAlarm()`、alarm 再試行
6. **L1** — 厳密な長さチェック（IV=16, salt=22 / `length % 4 === 1` を拒否）
7. **L3/L4** — `create()` 衝突ガード、DO 呼び出しを 503 でラップ
