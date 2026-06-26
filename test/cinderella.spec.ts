import { env, runInDurableObject } from "cloudflare:test";
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
  it("3回開封でき、4回目は gone", async () => {
    const { id, sealed } = await sealAndStore("triple", null, { maxViews: 3 });

    for (let i = 1; i <= 3; i++) {
      const res = await getSecret(id);
      expect(res.status).toBe(200);
      const record = (await res.json()) as { views: number };
      expect(record.views).toBe(i);
      // 各回で復号が成功する。
      const pt = await open(record, sealed.keyToken, null);
      expect(pt).toBe("triple");
    }

    const gone = await getSecret(id);
    expect(gone.status).toBe(404);
  });
});

describe("Durable Object の保存内容検査", () => {
  it("保存値に鍵トークン・平文が含まれない", async () => {
    const { id, sealed } = await sealAndStore("no key in storage", null);
    const stub = env.SECRET_STORE.get(env.SECRET_STORE.idFromName(id));
    await runInDurableObject(stub, async (_instance, state) => {
      const record = await state.storage.get<Record<string, unknown>>("record");
      expect(record).toBeTruthy();
      const json = JSON.stringify(record);
      expect(json).not.toContain(sealed.keyToken);
      expect(json).not.toContain("no key in storage");
      expect(Object.keys(record!).sort()).toEqual(
        ["ct", "expiresAt", "iv", "maxViews", "salt", "views"].sort(),
      );
    });
  });
});

describe("ワンタイム破棄後のストレージ", () => {
  it("開封後は Durable Object に何も残らない", async () => {
    const { id } = await sealAndStore("burn me", null);
    await getSecret(id);
    const stub = env.SECRET_STORE.get(env.SECRET_STORE.idFromName(id));
    await runInDurableObject(stub, async (_instance, state) => {
      const record = await state.storage.get("record");
      expect(record).toBeUndefined();
    });
  });
});

describe("POST のバリデーション", () => {
  it("不正な ttl は 400", async () => {
    const s = await seal("x", null);
    const res = await postSecret({ ct: s.ct, iv: s.iv, salt: null, maxViews: 1, ttl: "99y" });
    expect(res.status).toBe(400);
  });
  it("ct 欠落は 400", async () => {
    const s = await seal("x", null);
    const res = await postSecret({ iv: s.iv, salt: null, maxViews: 1, ttl: "1h" });
    expect(res.status).toBe(400);
  });
  it("maxViews 範囲外は 400", async () => {
    const s = await seal("x", null);
    const res = await postSecret({ ct: s.ct, iv: s.iv, salt: null, maxViews: 999, ttl: "1h" });
    expect(res.status).toBe(400);
  });
  it("IV の長さ不正は 400", async () => {
    const s = await seal("x", null);
    const res = await postSecret({ ct: s.ct, iv: "AAAA", salt: null, maxViews: 1, ttl: "1h" });
    expect(res.status).toBe(400);
  });
  it("巨大な暗号文は 400", async () => {
    const s = await seal("x", null);
    const huge = "A".repeat(90_000); // 上限 64KiB を超える base64url
    const res = await postSecret({ ct: huge, iv: s.iv, salt: null, maxViews: 1, ttl: "1h" });
    expect(res.status).toBe(400);
  });
  it("ボディ全体が大きすぎる場合は拒否される", async () => {
    // 本番では Content-Length により 413、テスト経路では暗号文長で 400。いずれも拒否。
    const big = "A".repeat(200_000);
    const res = await postSecret({ ct: big, iv: "AAAAAAAAAAAAAAAA", salt: null, maxViews: 1, ttl: "1h" });
    expect([400, 413]).toContain(res.status);
  });
  it("Content-Length 超過は 413", async () => {
    // ヘッダを明示して早期拒否パスを検証する。
    const s = await seal("x", null);
    const res = await app.request(
      "/api/secret",
      {
        method: "POST",
        headers: { "content-type": "application/json", "content-length": "999999" },
        body: JSON.stringify({ ct: s.ct, iv: s.iv, salt: null, maxViews: 1, ttl: "1h" }),
      },
      env as Bindings,
    );
    expect(res.status).toBe(413);
  });
  it("Content-Length 無しの巨大ボディはパース前にストリームで打ち切られ 413", async () => {
    // ストリーム本体を流すと Content-Length は付かないため一次ゲートを通過し、
    // readBodyCapped がバイト数で打ち切る経路（Content-Length 非依存の本丸）を検証する。
    const big = new TextEncoder().encode("A".repeat(200_000)); // 上限 128KiB 超
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(big);
        controller.close();
      },
    });
    const res = await app.request(
      "/api/secret",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: stream,
        duplex: "half",
      } as RequestInit,
      env as Bindings,
    );
    expect(res.status).toBe(413);
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

describe("GET の id 検証", () => {
  it("存在しない id は gone", async () => {
    const res = await getSecret("doesnotexis1"); // 12 文字・形式は正しい
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "gone" });
  });
  it("形式不正な id は gone", async () => {
    const res = await getSecret("too-short");
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "gone" });
  });
});

// テスト用のレート制限スタブ。呼び出しキーを記録できる。
function stubLimiter(success: boolean, keys?: string[]) {
  return {
    limit: async ({ key }: { key: string }) => {
      keys?.push(key);
      return { success };
    },
  };
}

// 指定メソッドが必ず throw する SECRET_STORE スタブ（DO 障害を模す）。
function throwingStore(method: "read" | "create") {
  return {
    idFromName: (name: string) => name,
    get: () => ({
      [method]: async () => {
        throw new Error("storage down");
      },
    }),
  } as unknown as typeof env.SECRET_STORE;
}

describe("レート制限", () => {
  it("CREATE_LIMITER が拒否を返すと POST は 429", async () => {
    const res = await app.request(
      "/api/secret",
      {
        method: "POST",
        headers: { "content-type": "application/json", "CF-Connecting-IP": "203.0.113.1" },
        body: "{}",
      },
      { ...env, CREATE_LIMITER: stubLimiter(false) } as Bindings,
    );
    expect(res.status).toBe(429);
  });

  it("READ_LIMITER が拒否を返すと GET は 429", async () => {
    const res = await app.request(
      "/api/secret/doesnotexis1",
      { headers: { "CF-Connecting-IP": "203.0.113.1" } },
      { ...env, READ_LIMITER: stubLimiter(false) } as Bindings,
    );
    expect(res.status).toBe(429);
  });

  it("制限有効かつ CF-Connecting-IP 欠落はフェイルクローズ（429）", async () => {
    const res = await app.request(
      "/api/secret",
      { method: "POST", headers: { "content-type": "application/json" }, body: "{}" },
      { ...env, CREATE_LIMITER: stubLimiter(true) } as Bindings,
    );
    expect(res.status).toBe(429);
  });

  it("IPv6 のキーは /64 プレフィックスに正規化される", async () => {
    const keys: string[] = [];
    await app.request(
      "/api/secret/doesnotexis1",
      { headers: { "CF-Connecting-IP": "2001:db8:1234:5678:9abc:def0:1111:2222" } },
      { ...env, READ_LIMITER: stubLimiter(true, keys) } as Bindings,
    );
    expect(keys).toEqual(["2001:db8:1234:5678"]);
  });

  it("圧縮表記（ゼロ含みプレフィックス）でも同一 /64 は同じキーに集約される", async () => {
    // 同じ 2001:db8::/64 に属するが、圧縮表記・ホスト部だけ異なる 3 アドレス。
    // 展開せずに先頭 4 hextet を取ると別キーに割れてレート制限を回避できてしまう。
    const keys: string[] = [];
    const limiter = stubLimiter(true, keys);
    for (const ip of ["2001:db8::1", "2001:db8::5", "2001:db8::1:2:3:4"]) {
      await app.request(
        "/api/secret/doesnotexis1",
        { headers: { "CF-Connecting-IP": ip } },
        { ...env, READ_LIMITER: limiter } as Bindings,
      );
    }
    expect(keys).toEqual(["2001:db8:0:0", "2001:db8:0:0", "2001:db8:0:0"]);
  });

  it("バインディング欠落時はフェイルオープン（通常応答）", async () => {
    // バインディング欠落を明示し、通常どおり 404 を返す（素通り）ことを確認する。
    const res = await app.request(
      "/api/secret/doesnotexis1",
      { headers: { "CF-Connecting-IP": "203.0.113.1" } },
      { ...env, READ_LIMITER: undefined } as Bindings,
    );
    expect(res.status).toBe(404);
  });

  it("limiter が throw してもフェイルオープンで後続処理が走る", async () => {
    // limiter の一過性障害（throw）は握って素通り。429 でも 5xx でもなく通常処理に進む。
    const throwingLimiter = {
      limit: async () => {
        throw new Error("limiter down");
      },
    };
    const res = await app.request(
      "/api/secret/doesnotexis1",
      { headers: { "CF-Connecting-IP": "203.0.113.1" } },
      { ...env, READ_LIMITER: throwingLimiter } as Bindings,
    );
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "gone" });
  });
});

describe("API 応答のセキュリティヘッダ", () => {
  it("HSTS と Referrer-Policy が付く", async () => {
    const res = await getSecret("doesnotexis1");
    expect(res.headers.get("Strict-Transport-Security")).toBe(
      "max-age=63072000; includeSubDomains; preload",
    );
    expect(res.headers.get("Referrer-Policy")).toBe("no-referrer");
    expect(res.headers.get("X-Content-Type-Options")).toBe("nosniff");
  });
});

describe("不正な base64url 長の拒否（L1）", () => {
  it("17 文字の IV は 400", async () => {
    const s = await seal("x", null);
    const res = await postSecret({ ct: s.ct, iv: "A".repeat(17), salt: null, maxViews: 1, ttl: "1h" });
    expect(res.status).toBe(400);
  });
});

describe("id 衝突ガード（L3）", () => {
  it("既存レコードがあると create は false を返し、既存値を上書きしない", async () => {
    const stub = env.SECRET_STORE.get(env.SECRET_STORE.idFromName("collide-test1"));
    await runInDurableObject(stub, async (instance, state) => {
      const first = {
        ct: "first-ct".padEnd(24, "x"),
        iv: "y".repeat(16),
        salt: null,
        maxViews: 1,
        views: 0,
        expiresAt: Math.floor(Date.now() / 1000) + 3600,
      };
      // 2 回目は中身を変えて投げ、上書きされていないことを観測できるようにする。
      const second = { ...first, ct: "second-ct".padEnd(24, "z") };
      expect(await instance.create(first)).toBe(true);
      expect(await instance.create(second)).toBe(false);
      const stored = await state.storage.get<{ ct: string }>("record");
      expect(stored?.ct).toBe(first.ct);
    });
  });
});

describe("破棄時のアラーム解除（L2）", () => {
  it("開封破棄後はアラームが残らない", async () => {
    const { id } = await sealAndStore("burn with alarm", null);
    await getSecret(id); // maxViews=1 なので開封で破棄される
    const stub = env.SECRET_STORE.get(env.SECRET_STORE.idFromName(id));
    await runInDurableObject(stub, async (_instance, state) => {
      expect(await state.storage.getAlarm()).toBeNull();
    });
  });
});

describe("期限切れ（expiry）", () => {
  // 過去の expiresAt を持つレコードを直接注入するヘルパ。
  // create() を使うと過去時刻のアラームが即発火し得るため、storage に直接 put する。
  function expiredRecord(expiresAtOffsetSec: number) {
    return {
      ct: "x".repeat(24),
      iv: "y".repeat(16),
      salt: null,
      maxViews: 1,
      views: 0,
      expiresAt: Math.floor(Date.now() / 1000) + expiresAtOffsetSec,
    };
  }

  it("expiresAt を過ぎた秘密の GET は gone(404)", async () => {
    const id = "expiredsec01"; // 12 文字・形式は正しい
    const stub = env.SECRET_STORE.get(env.SECRET_STORE.idFromName(id));
    await runInDurableObject(stub, async (_instance, state) => {
      await state.storage.put("record", expiredRecord(-1)); // 1 秒前 = 期限切れ
    });
    const res = await getSecret(id);
    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ error: "gone" });
  });

  it("期限切れの GET 後はレコードもアラームも破棄される", async () => {
    const id = "expiredsec02";
    const stub = env.SECRET_STORE.get(env.SECRET_STORE.idFromName(id));
    await runInDurableObject(stub, async (_instance, state) => {
      await state.storage.put("record", expiredRecord(-1));
      await state.storage.setAlarm(Date.now() + 60_000); // 将来のアラーム → destroy で消えることを確認
    });
    await getSecret(id); // 期限切れ → read() が destroy()
    await runInDurableObject(stub, async (_instance, state) => {
      expect(await state.storage.get("record")).toBeUndefined();
      expect(await state.storage.getAlarm()).toBeNull();
    });
  });

  it("alarm() が呼ばれるとレコードを破棄する", async () => {
    const id = "expiredsec03";
    const stub = env.SECRET_STORE.get(env.SECRET_STORE.idFromName(id));
    await runInDurableObject(stub, async (instance, state) => {
      await state.storage.put("record", expiredRecord(-1));
      await instance.alarm(); // 期限アラーム発火を直接呼ぶ
      expect(await state.storage.get("record")).toBeUndefined();
    });
  });
});

describe("並行GETでの exactly-once（二重開封防止）", () => {
  it("同一リンクへの同時GETは1件だけ成功し残りは gone", async () => {
    // maxViews=1 のリンクに同時 GET を浴びせる。DO の直列化により、
    // 読み取りは厳密に順序化され、成功は 1 件・残りは破棄後の 404 になる。
    const { id, sealed } = await sealAndStore("only once concurrently", null);
    const N = 8;
    const results = await Promise.all(
      Array.from({ length: N }, () => getSecret(id)),
    );
    const statuses = results.map((r) => r.status);
    expect(statuses.filter((s) => s === 200)).toHaveLength(1);
    expect(statuses.filter((s) => s === 404)).toHaveLength(N - 1);

    // 唯一の 200 応答は正しく復号できる（壊れた暗号文を返していない）。
    const ok = results[statuses.indexOf(200)]!;
    const record = await ok.json();
    expect(await open(record, sealed.keyToken, null)).toBe("only once concurrently");
  });
});

describe("DO 障害時のエラー応答（L4）", () => {
  it("read() 例外時の GET は 503", async () => {
    const res = await app.request(
      "/api/secret/doesnotexis1",
      {},
      { ...env, SECRET_STORE: throwingStore("read") } as Bindings,
    );
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "unavailable" });
  });

  it("create() 例外時の POST は 503", async () => {
    const s = await seal("x", null);
    const res = await app.request(
      "/api/secret",
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ ct: s.ct, iv: s.iv, salt: null, maxViews: 1, ttl: "1h" }),
      },
      { ...env, SECRET_STORE: throwingStore("create") } as Bindings,
    );
    expect(res.status).toBe(503);
    expect(await res.json()).toEqual({ error: "unavailable" });
  });
});

describe("ゼロ知識: GET 応答の形状", () => {
  it("応答に expiresAt・平文・鍵トークンが含まれない", async () => {
    const { id, sealed } = await sealAndStore("zero-knowledge response", null);
    const res = await getSecret(id);
    expect(res.status).toBe(200);
    const record = (await res.json()) as Record<string, unknown>;
    // 公開フィールドは ct/iv/salt/maxViews/views のみ。expiresAt は漏らさない。
    expect(Object.keys(record).sort()).toEqual(
      ["ct", "iv", "maxViews", "salt", "views"].sort(),
    );
    expect(record).not.toHaveProperty("expiresAt");
    const json = JSON.stringify(record);
    expect(json).not.toContain(sealed.keyToken);
    expect(json).not.toContain("zero-knowledge response");
  });
});
