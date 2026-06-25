import { Hono } from "hono";

// サーバーは鍵も平文も受け取らない。保持するのは id と鍵なしの暗号文だけ。
// 暗号化・復号はすべてクライアント側で行う。

type Bindings = {
  SECRETS: KVNamespace;
};

// KV に保存するレコード。鍵・平文は構造上含まれない。
type SecretRecord = {
  ct: string; // base64url(暗号文 + 認証タグ)
  iv: string; // base64url(12 バイト)
  salt: string | null; // base64url(16 バイト)。パスフレーズなしなら null
  maxViews: number;
  views: number;
  expiresAt: number; // 絶対エポック秒
};

// 1 リンクあたりの開封回数の上限。
const MAX_VIEWS_LIMIT = 10;

// ttl ラベルから秒数へ。保存時に expiresAt（絶対エポック秒）へ変換する。
const TTL_SECONDS: Record<string, number> = {
  "1h": 60 * 60,
  "24h": 24 * 60 * 60,
  "7d": 7 * 24 * 60 * 60,
};

// 暗号文サイズの上限（KV 値上限に対する安全弁）。
const MAX_CT_LENGTH = 1024 * 1024;

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

// 暗号文を保管し、取得用の id を返す。
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

  // KV の put は TTL を自動継承しないため expiration を毎回明示する。
  await c.env.SECRETS.put(`s:${id}`, JSON.stringify(record), {
    expiration: expiresAt,
  });

  return c.json({ id }, 201);
});

// 暗号文を返し、開封回数が上限に達したら破棄する。
app.get("/api/secret/:id", async (c) => {
  const id = c.req.param("id");
  const key = `s:${id}`;

  const raw = await c.env.SECRETS.get(key);
  // 不在・開封済み・期限切れはすべて gone として扱う。
  if (raw === null) {
    c.header("Cache-Control", "no-store");
    c.header("Pragma", "no-cache");
    return c.json({ error: "gone" }, 404);
  }

  const record = JSON.parse(raw) as SecretRecord;
  record.views += 1;

  if (record.views >= record.maxViews) {
    // 開封上限に達したため破棄する。maxViews=1 では初回で必ず該当する。
    await c.env.SECRETS.delete(key);
  } else {
    // 再保存。expiration は元の expiresAt を維持しつつ、KV の下限 60 秒でクランプする。
    await c.env.SECRETS.put(key, JSON.stringify(record), {
      expiration: Math.max(record.expiresAt, Math.floor(Date.now() / 1000) + 60),
    });
  }

  // 鍵は返さない。復号はクライアントが #fragment の鍵で行う。
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
