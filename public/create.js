// 作成画面: 鍵生成 → 暗号化 → POST /api/secret → 共有リンクを組み立てて表示。

import { seal } from "/crypto.js";

const $ = (id) => document.getElementById(id);

// セグメント型コントロール（radio グループ）の選択値を取る。
const picked = (name) =>
  document.querySelector(`input[name="${name}"]:checked`).value;

// 秘密の最大文字数。textarea の maxlength と一致させる。
const MAX_SECRET = 10000;
const fmt = (n) => n.toLocaleString("en-US");

function show(stateId) {
  for (const s of ["create", "sealed"]) {
    $(s).classList.toggle("hidden", s !== stateId);
  }
}

// 文字数カウンタを更新し、未入力なら封緘ボタンを失活させる。
function refresh() {
  const len = $("secret").value.length;
  $("counter").textContent = `${fmt(len)} / ${fmt(MAX_SECRET)}`;
  $("seal").disabled = $("secret").value.trim().length === 0;
}

$("secret").addEventListener("input", refresh);
refresh();

$("seal").addEventListener("click", async () => {
  const plaintext = $("secret").value;
  if (!plaintext) {
    $("secret").focus();
    return;
  }
  const passphrase = $("passphrase").value || null;
  const maxViews = parseInt(picked("opens"), 10);
  const ttl = picked("expires");

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
  refresh();
  show("create");
  $("secret").focus();
});
