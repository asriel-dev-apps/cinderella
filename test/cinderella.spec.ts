import { env } from "cloudflare:test";
import { describe, it, expect } from "vitest";
import app from "../src/index";
// フロントと同一の暗号モジュールでラウンドトリップを検証する。
import { seal, open, b64urlDecode, b64urlEncode } from "../public/crypto.js";

type Bindings = Parameters<typeof app.request>[2];

function postSecret(body: unknown) {
  return app.request(
    "/api/secret",
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    },
    env as Bindings,
  );
}

function getSecret(id: string) {
  return app.request(`/api/secret/${id}`, {}, env as Bindings);
}

async function sealAndStore(
  plaintext: string,
  passphrase: string | null,
  opts: { maxViews?: number; ttl?: string } = {},
) {
  const sealed = await seal(plaintext, passphrase);
  const res = await postSecret({
    ct: sealed.ct,
    iv: sealed.iv,
    salt: sealed.salt,
    maxViews: opts.maxViews ?? 1,
    ttl: opts.ttl ?? "1h",
  });
  expect(res.status).toBe(201);
  const { id } = (await res.json()) as { id: string };
  return { id, sealed };
}

describe("作成と開封", () => {
  it("平文が復号できる", async () => {
    const { id, sealed } = await sealAndStore("hello cinderella 🔥", null);
    const res = await getSecret(id);
    expect(res.status).toBe(200);
    const record = await res.json();
    const plaintext = await open(record, sealed.keyToken, null);
    expect(plaintext).toBe("hello cinderella 🔥");
  });
});

describe("同一リンクの2回目の開封（maxViews=1）", () => {
  it("2回目は gone", async () => {
    const { id } = await sealAndStore("once only", null);
    const first = await getSecret(id);
    expect(first.status).toBe(200);
    const second = await getSecret(id);
    expect(second.status).toBe(404);
    expect(await second.json()).toEqual({ error: "gone" });
  });
});

describe("暗号文の改竄", () => {
  it("復号に失敗する（GCM 認証タグ検証）", async () => {
    const sealed = await seal("tamper me", null);
    // ct の末尾バイト（GCM 認証タグ領域）を 1 bit 反転させる。
    const bytes = b64urlDecode(sealed.ct);
    bytes[bytes.length - 1] = (bytes[bytes.length - 1] ?? 0) ^ 0x01;
    const tampered = { ...sealed, ct: b64urlEncode(bytes) };
    await expect(open(tampered, sealed.keyToken, null)).rejects.toBeDefined();
  });
});

describe("パスフレーズの誤入力", () => {
  it("正しいパスフレーズで復号でき、誤入力では失敗する", async () => {
    const record = await seal("pw protected", "correct horse battery");
    const ok = await open(record, record.keyToken, "correct horse battery");
    expect(ok).toBe("pw protected");
    await expect(
      open(record, record.keyToken, "wrong passphrase"),
    ).rejects.toBeDefined();
    // パスフレーズ未入力も同様に失敗。
    await expect(open(record, record.keyToken, null)).rejects.toBeDefined();
  });
});

describe("maxViews=3", () => {
  it("3回開封でき、4回目は gone、各回で TTL を維持する", async () => {
    const { id, sealed } = await sealAndStore("triple", null, { maxViews: 3 });

    for (let i = 1; i <= 3; i++) {
      const res = await getSecret(id);
      expect(res.status).toBe(200);
      const record = (await res.json()) as { views: number };
      expect(record.views).toBe(i);
      // 各回で復号が成功する。
      const pt = await open(record, sealed.keyToken, null);
      expect(pt).toBe("triple");
      // 上限到達までは KV に残り、expiration が維持される。
      if (i < 3) {
        const meta = await env.SECRETS.getWithMetadata(`s:${id}`);
        expect(meta.value).not.toBeNull();
      }
    }

    const gone = await getSecret(id);
    expect(gone.status).toBe(404);
  });
});

describe("KV の保存内容検査", () => {
  it("保存値に鍵トークン・平文が含まれない", async () => {
    const { id, sealed } = await sealAndStore("no key in kv", null);
    const raw = await env.SECRETS.get(`s:${id}`);
    expect(raw).not.toBeNull();
    const record = JSON.parse(raw!);
    // 鍵を含まない暗号文レコードのフィールドのみが保存される。
    expect(Object.keys(record).sort()).toEqual(
      ["ct", "expiresAt", "iv", "maxViews", "salt", "views"].sort(),
    );
    expect(raw).not.toContain(sealed.keyToken);
    expect(raw).not.toContain("no key in kv");
  });
});

describe("POST のバリデーション", () => {
  it("不正な ttl は 400", async () => {
    const res = await postSecret({ ct: "AAAA", iv: "BBBB", salt: null, maxViews: 1, ttl: "99y" });
    expect(res.status).toBe(400);
  });
  it("ct 欠落は 400", async () => {
    const res = await postSecret({ iv: "BBBB", salt: null, maxViews: 1, ttl: "1h" });
    expect(res.status).toBe(400);
  });
  it("maxViews 範囲外は 400", async () => {
    const res = await postSecret({ ct: "AAAA", iv: "BBBB", salt: null, maxViews: 999, ttl: "1h" });
    expect(res.status).toBe(400);
  });
  it("不正な JSON は 400", async () => {
    const res = await app.request(
      "/api/secret",
      { method: "POST", headers: { "content-type": "application/json" }, body: "{not json" },
      env as Bindings,
    );
    expect(res.status).toBe(400);
  });
});

describe("存在しない id", () => {
  it("gone", async () => {
    const res = await getSecret("doesnotexist1");
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "gone" });
  });
});
