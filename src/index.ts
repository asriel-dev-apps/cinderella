import { Hono } from "hono";

// §3: Worker は信頼境界の外側。鍵・平文は決して受け取らない。
// 扱うのは id（引き出しハンドル）と鍵なしの暗号文 blob のみ。

type Bindings = {
  SECRETS: KVNamespace;
};

// §6 KV 値の形。鍵トークン・平文は構造上存在しない。
type SecretRecord = {
  ct: string; // base64url(暗号文 + GCM タグ)
  iv: string; // base64url(12B)
  salt: string | null; // base64url(16B) or null（パスフレーズなし）
  maxViews: number;
  views: number;
  expiresAt: number; // 絶対エポック秒。TTL の真実の源（§6）
};

// §8.1 OPENS の上限。封緘リクエストの maxViews を律する。
const MAX_VIEWS_LIMIT = 10;

// §6/§7.1 ttl ラベル → 秒。expiresAt に変換して保存する。
const TTL_SECONDS: Record<string, number> = {
  "1h": 60 * 60,
  "24h": 24 * 60 * 60,
  "7d": 7 * 24 * 60 * 60,
};

// 暗号文サイズの上限（KV 値上限 ~25MiB に対する安全弁）。
const MAX_CT_LENGTH = 1024 * 1024;

const app = new Hono<{ Bindings: Bindings }>();

// §4.2: id = base64url(9B 乱数) = 12 文字。暗号文の lookup handle。
function generateId(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(9));
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const isB64url = (v: unknown): v is string =>
  typeof v === "string" && v.length > 0 && /^[A-Za-z0-9_-]+$/.test(v);

// §7.1 封緘: 暗号文の保管。鍵・平文は受け取らない。
app.post("/api/secret", async (c) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "bad request" }, 400);
  }

  const { ct, iv, salt, maxViews, ttl } = (body ?? {}) as Record<string, unknown>;

  if (!isB64url(ct) || ct.length > MAX_CT_LENGTH) {
    return c.json({ error: "bad request" }, 400);
  }
  if (!isB64url(iv)) {
    return c.json({ error: "bad request" }, 400);
  }
  if (salt !== null && !isB64url(salt)) {
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

  // §6: put は TTL を自動継承しないため expiration を毎回明示する。
  await c.env.SECRETS.put(`s:${id}`, JSON.stringify(record), {
    expiration: expiresAt,
  });

  return c.json({ id }, 201);
});

// §7.2 開封: 取得 + ワンタイム破棄。
app.get("/api/secret/:id", async (c) => {
  const id = c.req.param("id");
  const key = `s:${id}`;

  const raw = await c.env.SECRETS.get(key);
  // 不在・開封済み・TTL 失効はいずれも gone（§7.2 / §12-2,5）。
  if (raw === null) {
    c.header("Cache-Control", "no-store");
    c.header("Pragma", "no-cache");
    return c.json({ error: "gone" }, 404);
  }

  const record = JSON.parse(raw) as SecretRecord;
  record.views += 1;

  if (record.views >= record.maxViews) {
    // burn（§5.1 露出窓最小化）。maxViews=1 なら初回で必ずここ。
    await c.env.SECRETS.delete(key);
  } else {
    // §6: 再 put では残存 TTL を維持するため expiresAt を明示。
    // KV の expiration は 60 秒以上先である必要がある。
    await c.env.SECRETS.put(key, JSON.stringify(record), {
      expiration: Math.max(record.expiresAt, Math.floor(Date.now() / 1000) + 60),
    });
  }

  // 鍵は含めない。クライアントが URL の #fragment から保持している（§7.2）。
  c.header("Cache-Control", "no-store");
  c.header("Pragma", "no-cache");
  return c.json({
    ct: record.ct,
    iv: record.iv,
    salt: record.salt,
    maxViews: record.maxViews,
    views: record.views,
  });
});

export default app;
