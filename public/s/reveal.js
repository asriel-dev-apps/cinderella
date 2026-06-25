// recipient 画面: 開封フロー（§8.2）
// location.hash を id と key に分割 → GET /api/secret/:id → key（＋passphrase）で復号。

import { open } from "/crypto.js";

const $ = (id) => document.getElementById(id);

function showOnly(stateId) {
  for (const s of ["recipient", "revealed", "error"]) {
    $(s).classList.toggle("hidden", s !== stateId);
  }
}

const ERRORS = {
  gone: ["already opened", "この秘密は存在しないか、既に開封済みです。傍受の可能性があれば送信者に連絡し、当該秘密をローテートしてください。"],
  expired: ["expired", "有効期限が切れています。"],
  badkey: ["復号できません", "パスフレーズが違うか、リンクが不正・改竄されています（GCM 検証失敗）。"],
};

function showError(kind) {
  const [title, body] = ERRORS[kind] ?? ERRORS.badkey;
  $("error-title").textContent = title;
  $("error-body").textContent = body;
  showOnly("error");
}

// #<id>.<key> を分割。base64url は '.' を含まないので最初の '.' で切る。
const hash = location.hash.replace(/^#/, "");
const dot = hash.indexOf(".");
const id = dot >= 0 ? hash.slice(0, dot) : "";
const keyToken = dot >= 0 ? hash.slice(dot + 1) : "";

if (!id || !keyToken) {
  showError("badkey");
}

$("reveal").addEventListener("click", async () => {
  $("reveal").disabled = true;
  try {
    // この GET がサーバー側の burn を引き起こす（§7.2）。
    const res = await fetch(`/api/secret/${encodeURIComponent(id)}`);
    if (res.status === 404) {
      showError("gone");
      return;
    }
    if (!res.ok) {
      showError("gone");
      return;
    }
    const record = await res.json();

    const passphrase = $("passphrase").value || null;
    let plaintext;
    try {
      // 復号は完全にクライアント側。鍵は #fragment 由来。
      plaintext = await open(record, keyToken, passphrase);
    } catch {
      // パスフレーズ違い・改竄は GCM では区別不能（§4.3）。
      showError("badkey");
      return;
    }

    $("plaintext").textContent = plaintext;
    showOnly("revealed");
  } catch {
    showError("gone");
  }
});

$("copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("plaintext").textContent);
    $("copy").textContent = "コピー済み";
    setTimeout(() => ($("copy").textContent = "コピー"), 1500);
  } catch {
    /* noop */
  }
});
