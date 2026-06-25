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
  gone: [
    "Already opened",
    "This secret doesn't exist or has already been opened. If someone may have opened it first, tell the sender and rotate the affected password or key just in case.",
  ],
  expired: ["Expired", "This link has expired."],
  badkey: [
    "Couldn't open",
    "The passphrase may be wrong, or the link may be corrupted.",
  ],
};

let fetchedRecord = null;

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
  $("passphrase-hint").classList.add("hidden");
  try {
    let record = fetchedRecord;
    if (!record) {
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
      record = await res.json();
      fetchedRecord = record;
    }

    const passphrase = $("passphrase").value || null;
    let plaintext;
    try {
      // 復号は完全にクライアント側。鍵は #fragment 由来。
      plaintext = await open(record, keyToken, passphrase);
    } catch {
      // パスフレーズ違い・改竄は GCM では区別不能（§4.3）。
      $("passphrase-hint").textContent = "Check the passphrase and try again.";
      $("passphrase-hint").classList.remove("hidden");
      $("reveal").disabled = false;
      $("passphrase").focus();
      showOnly("recipient");
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
    $("copy").textContent = "Copied";
    setTimeout(() => ($("copy").textContent = "Copy"), 1500);
  } catch {
    /* noop */
  }
});
