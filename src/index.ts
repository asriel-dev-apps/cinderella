import { Hono } from "hono";
import type { PublicRecord, SecretRecord, SecretStore } from "./secret-store";

export { SecretStore } from "./secret-store";

// サーバーは鍵も平文も受け取らない。保持するのは id と鍵なしの暗号文だけ。
// 暗号化・復号はすべてクライアント側で行う。

// レート制限バインディング（Cloudflare Workers Rate Limiting）。
type RateLimiter = { limit(opts: { key: string }): Promise<{ success: boolean }> };

type Bindings = {
  SECRET_STORE: DurableObjectNamespace<SecretStore>;
  CREATE_LIMITER?: RateLimiter;
  READ_LIMITER?: RateLimiter;
};

// 1 リンクあたりの開封回数の上限。
const MAX_VIEWS_LIMIT = 10;

// ttl ラベルから秒数へ。保存時に expiresAt（絶対エポック秒）へ変換する。
const TTL_SECONDS: Record<string, number> = {
  "1h": 60 * 60,
  "24h": 24 * 60 * 60,
  "7d": 7 * 24 * 60 * 60,
};

// 暗号文の上限。用途は短い秘密のため小さく抑える。
const MAX_CT_BYTES = 64 * 1024; // 復号後の平文も実質この範囲に収まる
const MIN_CT_BYTES = 16; // GCM 認証タグの最小長
// リクエストボディ全体の上限（暗号文 + メタ + JSON のオーバーヘッド）。
const MAX_BODY_BYTES = 128 * 1024;

// id は 9 バイト乱数を base64url 化した 12 文字。
const ID_PATTERN = /^[A-Za-z0-9_-]{12}$/;

// id 衝突時の再生成回数（72bit 乱数のため実質発火しない安全網）。
const ID_RETRY = 3;

const app = new Hono<{ Bindings: Bindings }>();

// API 応答にもセキュリティヘッダを付ける。`public/_headers` は静的アセットにしか
// 効かないため、HSTS と Referrer-Policy が /api/* に乗らないギャップを埋める。
app.use("*", async (c, next) => {
  await next();
  c.header("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload");
  c.header("Referrer-Policy", "no-referrer");
  c.header("X-Content-Type-Options", "nosniff");
});

// 暗号文の取得ハンドル。9 バイト乱数を base64url 化した 12 文字。
function generateId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(9));
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// 文字種が base64url で、かつパディングなし base64url として成立し得る長さか。
// 長さ ≡ 1 (mod 4) は base64 では到達不能なので弾く（不正な長さの素通り防止）。
const isB64url = (v: unknown): v is string =>
  typeof v === "string" && v.length > 0 && v.length % 4 !== 1 && /^[A-Za-z0-9_-]+$/.test(v);

// base64url 文字列が表すバイト数（パディングなし前提）。
const b64urlBytes = (s: string): number => Math.floor((s.length * 3) / 4);

// レスポンスにキャッシュ抑止ヘッダを付ける。暗号文が中間キャッシュへ残らないようにする。
function noStore(c: { header: (k: string, v: string) => void }): void {
  c.header("Cache-Control", "no-store");
  c.header("Pragma", "no-cache");
  c.header("X-Content-Type-Options", "nosniff");
}

// IPv6 アドレスの /64 プレフィックス（先頭 4 hextet）を正規形で返す。
// "::" 圧縮を 0 で展開し、各 hextet の先頭ゼロを落として表記揺れを吸収する。
// （これをしないと 2001:db8::1 と 2001:db8::2 が別キーになり /64 集約が効かない）
function ipv6Prefix64(ip: string): string {
  let groups: string[];
  if (ip.includes("::")) {
    const [head = "", tail = ""] = ip.split("::");
    const headParts = head ? head.split(":") : [];
    const tailParts = tail ? tail.split(":") : [];
    const missing = 8 - headParts.length - tailParts.length;
    groups = [...headParts, ...Array(Math.max(missing, 0)).fill("0"), ...tailParts];
  } else {
    groups = ip.split(":");
  }
  return groups
    .slice(0, 4)
    .map((h) => (h === "" ? "0" : h.replace(/^0+(?=.)/, "").toLowerCase()))
    .join(":");
}

// レート制限キー。IPv6 は 1 アドレスごとに別バケットになると上限回避できるため、
// /64 プレフィックスに正規化する（圧縮表記も展開して扱う）。IPv4 は全体をそのまま使う。
// なおカウントは Cloudflare の拠点(colo)単位のため、実効上限は colo 数倍になる。
// 全体のハード上限はエッジ WAF 側（管理画面設定）に委ねる前提。
const rateLimitKey = (ip: string): string =>
  ip.includes(":") ? ipv6Prefix64(ip) : ip;

// 同一メッセージのログ氾濫を防ぎ、isolate ごとに 1 回だけ警告する。
const warnedOnce = new Set<string>();
function warnOnce(key: string, message: string): void {
  if (warnedOnce.has(key)) return;
  warnedOnce.add(key);
  console.warn(message);
}

// レート制限を適用する。バインディング欠落時はフェイルオープン（サービス継続）だが、
// 黙って素通りさせず初回に警告ログを出す。レート制限が有効なのにクライアント識別子
// （CF-Connecting-IP）が取れない場合はフェイルクローズ（識別不能なので拒否）。
// 戻り値: 拒否すべきなら true。
async function denyByRateLimit(
  limiter: RateLimiter | undefined,
  name: string,
  ip: string | undefined,
): Promise<boolean> {
  if (!limiter) {
    warnOnce(name, `rate limiter ${name} not bound — requests are NOT rate limited`);
    return false;
  }
  if (!ip) return true; // 本番では CF が必ず付与するため、欠落は異常として拒否
  try {
    const { success } = await limiter.limit({ key: rateLimitKey(ip) });
    return !success;
  } catch {
    // limiter 自体が一時障害で throw した場合は M4 と同じくフェイルオープン＋警告。
    warnOnce(`${name}:error`, `rate limiter ${name} threw — failing open`);
    return false;
  }
}

// 本文をストリームで読み、上限超過分はパース前に打ち切る（Content-Length に依存しない）。
// 上限超過なら null。Content-Length 早期チェックは高速化のための一次ゲートとして併用する。
async function readBodyCapped(req: Request, max: number): Promise<Uint8Array | null> {
  const body = req.body;
  if (!body) return new Uint8Array(0);
  const reader = body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (!value) continue;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return out;
}

const bodyDecoder = new TextDecoder();

// 暗号文を保管し、取得用の id を返す。
app.post("/api/secret", async (c) => {
  // 一次ゲート: Content-Length が明らかに過大なら即 413（高速化用）。
  const contentLength = Number(c.req.header("content-length") ?? "0");
  if (contentLength > MAX_BODY_BYTES) {
    return c.json({ error: "payload too large" }, 413);
  }

  if (await denyByRateLimit(c.env.CREATE_LIMITER, "CREATE_LIMITER", c.req.header("CF-Connecting-IP"))) {
    return c.json({ error: "rate limited" }, 429);
  }

  // 本文をバイト数で数えながら読み、上限超過はパース前に打ち切る（Content-Length 非依存）。
  const raw = await readBodyCapped(c.req.raw, MAX_BODY_BYTES);
  if (raw === null) {
    return c.json({ error: "payload too large" }, 413);
  }

  let body: unknown;
  try {
    body = JSON.parse(bodyDecoder.decode(raw));
  } catch {
    return c.json({ error: "bad request" }, 400);
  }

  const { ct, iv, salt, maxViews, ttl } = (body ?? {}) as Record<string, unknown>;

  // 暗号文: base64url かつ復号後のバイト長が許容範囲。
  if (!isB64url(ct) || b64urlBytes(ct) < MIN_CT_BYTES || b64urlBytes(ct) > MAX_CT_BYTES) {
    return c.json({ error: "bad request" }, 400);
  }
  // IV: 12 バイト固定。
  if (!isB64url(iv) || b64urlBytes(iv) !== 12) {
    return c.json({ error: "bad request" }, 400);
  }
  // salt: なし（null）または 16 バイト固定。
  if (salt !== null && (!isB64url(salt) || b64urlBytes(salt) !== 16)) {
    return c.json({ error: "bad request" }, 400);
  }

  const mv = maxViews === undefined ? 1 : maxViews;
  if (!Number.isInteger(mv) || (mv as number) < 1 || (mv as number) > MAX_VIEWS_LIMIT) {
    return c.json({ error: "bad request" }, 400);
  }

  if (typeof ttl !== "string" || !(ttl in TTL_SECONDS)) {
    return c.json({ error: "bad request" }, 400);
  }

  const expiresAt = Math.floor(Date.now() / 1000) + TTL_SECONDS[ttl]!;
  const record: SecretRecord = {
    ct,
    iv,
    salt: (salt as string) ?? null,
    maxViews: mv as number,
    views: 0,
    expiresAt,
  };

  // create() は id 衝突時に false を返す（既存を上書きしない）。新しい id で再試行する。
  // 72bit 乱数のため衝突は実質発火しないが、安全網として数回だけ回す。
  let id = "";
  try {
    for (let attempt = 0; ; attempt++) {
      id = generateId();
      const stub = c.env.SECRET_STORE.get(c.env.SECRET_STORE.idFromName(id));
      if (await stub.create(record)) break;
      if (attempt >= ID_RETRY) throw new Error("id collision retry exhausted");
    }
  } catch {
    noStore(c);
    return c.json({ error: "unavailable" }, 503);
  }

  noStore(c);
  return c.json({ id }, 201);
});

// 暗号文を返し、開封回数が上限に達したら破棄する。
app.get("/api/secret/:id", async (c) => {
  const id = c.req.param("id");
  // 形式不正な id は存在しないものとして扱う（DO へ到達させない）。
  if (!ID_PATTERN.test(id)) {
    noStore(c);
    return c.json({ error: "gone" }, 404);
  }

  if (await denyByRateLimit(c.env.READ_LIMITER, "READ_LIMITER", c.req.header("CF-Connecting-IP"))) {
    return c.json({ error: "rate limited" }, 429);
  }

  let record: PublicRecord | null;
  try {
    const stub = c.env.SECRET_STORE.get(c.env.SECRET_STORE.idFromName(id));
    record = await stub.read();
  } catch {
    noStore(c);
    return c.json({ error: "unavailable" }, 503);
  }

  noStore(c);
  // 不在・開封済み・期限切れはすべて gone として扱う。
  if (record === null) {
    return c.json({ error: "gone" }, 404);
  }

  // 鍵は返さない。復号はクライアントが #fragment の鍵で行う。
  return c.json(record);
});

export default app;
