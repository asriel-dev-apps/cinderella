// create 画面: 封緘フロー（§8.2）
// 鍵生成 → 暗号化 → POST /api/secret → #<id>.<key> を組み立てて提示。

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
    // 鍵・平文はここから外に出ない。送るのは暗号文とメタのみ。
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

    // 鍵トークンは #fragment に。RFC 3986 によりサーバーへ送られない。
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
