// Cinderella 暗号モジュール
//
// 暗号化・復号はブラウザ内で完結する。鍵（rawKey）と平文はネットワークを越えない。
// Web Crypto のみ使用。ブラウザと workerd（テスト）の両方で動作する。

const utf8 = new TextEncoder();
const fromUtf8 = new TextDecoder();

// --- base64url ---------------------------------------------------------------

export function b64urlEncode(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(str) {
  let s = str.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

// --- 鍵導出 ------------------------------------------------------------------
//
// パスフレーズ指定時は material = rawKey ‖ PBKDF2(passphrase, salt)、未指定時は rawKey。
// material を SHA-256 で 32 バイトに正規化し、AES-GCM 鍵として importKey する。
// パスフレーズ指定時は rawKey とパスフレーズの双方が復号に必須となる。
async function deriveKey(rawKey, passphrase, salt) {
  let material = rawKey;
  if (passphrase) {
    const baseKey = await crypto.subtle.importKey(
      "raw",
      utf8.encode(passphrase),
      "PBKDF2",
      false,
      ["deriveBits"],
    );
    const derived = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
      baseKey,
      256,
    );
    material = concat(rawKey, new Uint8Array(derived));
  }
  const keyBytes = await crypto.subtle.digest("SHA-256", material);
  return crypto.subtle.importKey("raw", keyBytes, "AES-GCM", false, [
    "encrypt",
    "decrypt",
  ]);
}

// --- 暗号化 ------------------------------------------------------------------
// 戻り値の keyToken は URL の #fragment に載せ、サーバーには送らない。
export async function seal(plaintext, passphrase) {
  const rawKey = crypto.getRandomValues(new Uint8Array(32)); // 256 ビット鍵
  const iv = crypto.getRandomValues(new Uint8Array(12)); // GCM 用の IV
  const salt = passphrase ? crypto.getRandomValues(new Uint8Array(16)) : null;
  const key = await deriveKey(rawKey, passphrase, salt);

  const ct = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, // 認証タグを含む
    key,
    utf8.encode(plaintext),
  );

  return {
    ct: b64urlEncode(ct),
    iv: b64urlEncode(iv),
    salt: salt ? b64urlEncode(salt) : null,
    keyToken: b64urlEncode(rawKey), // URL の #fragment に載せる鍵
  };
}

// --- 復号 --------------------------------------------------------------------
// 認証タグの検証に失敗すると例外を投げる（パスフレーズ違い、または改竄）。
export async function open(record, keyToken, passphrase) {
  const rawKey = b64urlDecode(keyToken);
  const salt = record.salt ? b64urlDecode(record.salt) : null;
  const key = await deriveKey(rawKey, passphrase, salt);

  const pt = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: b64urlDecode(record.iv) },
    key,
    b64urlDecode(record.ct),
  );
  return fromUtf8.decode(pt);
}
