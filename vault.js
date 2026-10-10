// Расшифровка архива в браузере: PBKDF2-SHA256 → AES-256-GCM. Пароль никуда не отправляется.
"use strict";
const Vault = (() => {
  let key = null, manifest = null;
  const b64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
  async function open(password) {
    const kdf = await (await fetch("vault/kdf.json", {cache: "no-store"})).json();
    const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
    key = await crypto.subtle.deriveKey({name: "PBKDF2", hash: "SHA-256", salt: b64(kdf.salt), iterations: kdf.iter},
      base, {name: "AES-GCM", length: 256}, false, ["decrypt"]);
    manifest = JSON.parse(new TextDecoder().decode(await read("manifest.bin"))); // неверный пароль → исключение
    return manifest;
  }
  async function read(blob) {
    const buf = new Uint8Array(await (await fetch("vault/" + blob)).arrayBuffer());
    return crypto.subtle.decrypt({name: "AES-GCM", iv: buf.slice(0, 12)}, key, buf.slice(12));
  }
  async function url(item) { return URL.createObjectURL(new Blob([await read(item.blob)], {type: item.mime})); }
  async function download(item) {
    const a = document.createElement("a"); a.href = await url(item); a.download = item.name;
    document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  }
  function remember(pw) { try { sessionStorage.setItem("shalabuda-pw", pw); } catch (_) {} }
  function remembered() { try { return sessionStorage.getItem("shalabuda-pw"); } catch (_) { return null; } }
  return {open, read, url, download, remember, remembered};
})();

function gate(onOpen) {
  const form = document.getElementById("gate"), err = document.getElementById("err"), inp = document.getElementById("pw");
  async function tryOpen(pw, silent) {
    err.textContent = silent ? "" : "проверяю…";
    try { const m = await Vault.open(pw); Vault.remember(pw); document.getElementById("lock").classList.add("hidden"); err.textContent = ""; await onOpen(m); }
    catch (e) { if (!silent) { err.textContent = "R Tape loading error, 0:1 — пароль не тот"; inp.select(); } }
  }
  form.addEventListener("submit", e => { e.preventDefault(); tryOpen(inp.value.trim(), false); });
  const pw = Vault.remembered(); if (pw) tryOpen(pw, true);
}
