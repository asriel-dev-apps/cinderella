// 受信画面: URL の #fragment を id と鍵に分割 → GET /api/secret/:id → 鍵で復号。

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
      // この GET でサーバー側の開封カウントが進み、上限に達すると破棄される。
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
      // 復号はクライアント側で行う。鍵は URL の #fragment から取得済み。
      plaintext = await open(record, keyToken, passphrase);
    } catch {
      // 取得済みレコードは fetchedRecord に保持。再取得せずパスフレーズ再入力を促す。
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
