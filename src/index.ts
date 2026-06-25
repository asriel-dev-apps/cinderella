import { Hono } from "hono";
import type { SecretRecord, SecretStore } from "./secret-store";

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

const app = new Hono<{ Bindings: Bindings }>();

// 暗号文の取得ハンドル。9 バイト乱数を base64url 化した 12 文字。
function generateId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(9));
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const isB64url = (v: unknown): v is string =>
  typeof v === "string" && v.length > 0 && /^[A-Za-z0-9_-]+$/.test(v);

// base64url 文字列が表すバイト数（パディングなし前提）。
const b64urlBytes = (s: string): number => Math.floor((s.length * 3) / 4);

// レスポンスにキャッシュ抑止ヘッダを付ける。暗号文が中間キャッシュへ残らないようにする。
function noStore(c: { header: (k: string, v: string) => void }): void {
  c.header("Cache-Control", "no-store");
  c.header("Pragma", "no-cache");
  c.header("X-Content-Type-Options", "nosniff");
}

const clientIp = (c: { req: { header: (k: string) => string | undefined } }): string =>
  c.req.header("CF-Connecting-IP") ?? "unknown";

// 暗号文を保管し、取得用の id を返す。
app.post("/api/secret", async (c) => {
  // パース前にボディサイズを拒否する（巨大ペイロード対策）。
  const contentLength = Number(c.req.header("content-length") ?? "0");
  if (contentLength > MAX_BODY_BYTES) {
    return c.json({ error: "payload too large" }, 413);
  }

  if (c.env.CREATE_LIMITER) {
    const { success } = await c.env.CREATE_LIMITER.limit({ key: clientIp(c) });
    if (!success) return c.json({ error: "rate limited" }, 429);
  }

  let body: unknown;
  try {
    body = await c.req.json();
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
  const id = generateId();
  const record: SecretRecord = {
    ct,
    iv,
    salt: (salt as string) ?? null,
    maxViews: mv as number,
    views: 0,
    expiresAt,
  };

  const stub = c.env.SECRET_STORE.get(c.env.SECRET_STORE.idFromName(id));
  await stub.create(record);

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

  if (c.env.READ_LIMITER) {
    const { success } = await c.env.READ_LIMITER.limit({ key: clientIp(c) });
    if (!success) return c.json({ error: "rate limited" }, 429);
  }

  const stub = c.env.SECRET_STORE.get(c.env.SECRET_STORE.idFromName(id));
  const record = await stub.read();

  noStore(c);
  // 不在・開封済み・期限切れはすべて gone として扱う。
  if (record === null) {
    return c.json({ error: "gone" }, 404);
  }

  // 鍵は返さない。復号はクライアントが #fragment の鍵で行う。
  return c.json(record);
});

export default app;
