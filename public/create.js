// 作成画面: 鍵生成 → 暗号化 → POST /api/secret → 共有リンクを組み立てて表示。

import { seal } from "/crypto.js";

const $ = (id) => document.getElementById(id);

function show(stateId) {
  for (const s of ["create", "sealed"]) {
    $(s).classList.toggle("hidden", s !== stateId);
  }
}

$("seal").addEventListener("click", async () => {
  const plaintext = $("secret").value;
  if (!plaintext) {
    $("secret").focus();
    return;
  }
  const passphrase = $("passphrase").value || null;
  const maxViews = parseInt($("opens").value, 10);
  const ttl = $("expires").value;

  $("seal").disabled = true;
  try {
    // 鍵・平文はクライアント外に出ない。送信するのは暗号文とメタ情報のみ。
    const s = await seal(plaintext, passphrase);
    const res = await fetch("/api/secret", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        ct: s.ct,
        iv: s.iv,
        salt: s.salt,
        maxViews,
        ttl,
      }),
    });
    if (!res.ok) throw new Error(`server ${res.status}`);
    const { id } = await res.json();

    // 鍵は URL の #fragment に載せる。fragment はサーバーへ送信されない。
    const link = `${location.origin}/s/#${id}.${s.keyToken}`;
    $("link").value = link;
    show("sealed");
  } catch (e) {
    alert("Failed to create link: " + e.message);
  } finally {
    $("seal").disabled = false;
  }
});

$("copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("link").value);
    $("copy").textContent = "Copied";
    setTimeout(() => ($("copy").textContent = "Copy"), 1500);
  } catch {
    $("link").select();
  }
});

$("again").addEventListener("click", () => {
  $("secret").value = "";
  $("passphrase").value = "";
  $("link").value = "";
  show("create");
  $("secret").focus();
});
