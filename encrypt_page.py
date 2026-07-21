#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
encrypt_page.py

把 index.html 用密码加密成一个自解密的 HTML(密码墙 + AES-GCM 密文)。
用法:
  python encrypt_page.py                # 交互输密码
  python encrypt_page.py -p <password>  # 命令行传密码(仅本地用,别推 git)

流程:
  1) 读 index.html(明文页)
  2) 若不存在 index.plain.html 则备份一份到 index.plain.html(被 .gitignore 挡住)
  3) PBKDF2-HMAC-SHA256 250k 轮从密码派生 256-bit AES 密钥
  4) AES-GCM 加密整份 HTML,盐+IV+密文一起 base64 塞进模板
  5) 生成新的 index.html —— 密码墙 UI + WebCrypto 解密逻辑
     解密成功后 document.open/write 全量替换页面,原页面的 <script> 正常执行
     密码通过 sessionStorage 缓存,同 tab 刷新免输
"""
from __future__ import annotations
import argparse, base64, getpass, os, sys
from pathlib import Path

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

HERE      = Path(__file__).resolve().parent
PLAIN_BAK = HERE / "index.plain.html"
TARGET    = HERE / "index.html"
ITERS     = 250_000

WRAPPER_TEMPLATE = r"""<!doctype html>
<html lang="zh">
<head>
<meta charset="utf-8">
<title>需要密码</title>
<meta name="viewport" content="width=device-width,initial-scale=1">
<style>
  html,body{height:100%;margin:0;font-family:-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;background:#f5f6f8;color:#222}
  .wrap{min-height:100%;display:flex;align-items:center;justify-content:center;padding:20px;box-sizing:border-box}
  .card{background:#fff;padding:28px 32px;border-radius:10px;box-shadow:0 4px 24px rgba(0,0,0,0.08);width:100%;max-width:340px}
  h1{margin:0 0 6px;font-size:18px}
  p{margin:0 0 16px;color:#666;font-size:13px}
  input[type=password]{width:100%;box-sizing:border-box;padding:9px 11px;font-size:14px;border:1px solid #cfd6de;border-radius:6px;outline:none}
  input[type=password]:focus{border-color:#3182ce}
  button{margin-top:12px;width:100%;padding:9px 0;font-size:14px;background:#3182ce;color:#fff;border:none;border-radius:6px;cursor:pointer}
  button:hover{background:#2b6cb0}
  button:disabled{background:#a0aec0;cursor:not-allowed}
  .err{margin-top:10px;color:#c53030;font-size:12.5px;min-height:16px}
  .hint{margin-top:14px;font-size:11.5px;color:#999;text-align:center}
</style>
</head>
<body>
<div class="wrap">
  <div class="card">
    <h1>京东自营冰箱 · 产品地图</h1>
    <p>此页需要密码访问,请输入访问密码。</p>
    <input id="pw" type="password" autocomplete="current-password" placeholder="输入密码" autofocus>
    <button id="go">进入</button>
    <div class="err" id="err"></div>
    <div class="hint">加密方式:AES-GCM · PBKDF2 250k</div>
  </div>
</div>
<script>
(function(){
  const PAYLOAD = "__PAYLOAD_B64__";
  const SALT_B64 = "__SALT_B64__";
  const IV_B64 = "__IV_B64__";
  const ITERS = __ITERS__;
  const SKEY = "jd-fridge-map-pw-v1";
  const COUNTER_NS = "jd-fridge-map-dblows08";
  // Fire-and-forget beacon to counterapi.dev (3 keys: load / attempt / success)
  // Retries up to 3 times with backoff — counterapi occasionally times out.
  function beacon(event){
    const url = "https://api.counterapi.dev/v1/" + COUNTER_NS + "/" + event + "/up";
    let attempts = 0;
    function tryOnce(){
      attempts++;
      fetch(url, {mode:"cors", cache:"no-store", keepalive:true})
        .then(r => { if (!r.ok && attempts < 3) setTimeout(tryOnce, 400 * attempts); })
        .catch(() => { if (attempts < 3) setTimeout(tryOnce, 400 * attempts); });
    }
    try { tryOnce(); } catch(e){}
  }

  function b64d(s){
    const bin = atob(s);
    const arr = new Uint8Array(bin.length);
    for (let i=0;i<bin.length;i++) arr[i] = bin.charCodeAt(i);
    return arr;
  }

  async function deriveKey(pw, saltBytes){
    const enc = new TextEncoder();
    const baseKey = await crypto.subtle.importKey(
      "raw", enc.encode(pw), {name:"PBKDF2"}, false, ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      {name:"PBKDF2", salt:saltBytes, iterations:ITERS, hash:"SHA-256"},
      baseKey,
      {name:"AES-GCM", length:256},
      false,
      ["decrypt"]
    );
  }

  async function tryDecrypt(pw){
    const salt = b64d(SALT_B64);
    const iv   = b64d(IV_B64);
    const ct   = b64d(PAYLOAD);
    const key  = await deriveKey(pw, salt);
    const buf  = await crypto.subtle.decrypt({name:"AES-GCM", iv:iv}, key, ct);
    return new TextDecoder("utf-8").decode(buf);
  }

  function renderPage(html){
    try { sessionStorage.setItem(SKEY, "ok"); } catch(e){}
    document.open();
    document.write(html);
    document.close();
  }

  async function attempt(pw, silent){
    const err = document.getElementById("err");
    const btn = document.getElementById("go");
    const inp = document.getElementById("pw");
    if (btn) btn.disabled = true;
    // 只把用户手动输入 (silent=false) 算作 attempt;自动重放缓存不计
    if (!silent) beacon("attempt");
    try {
      const html = await tryDecrypt(pw);
      if (btn) btn.disabled = false;
      // 缓存输入的密码到 sessionStorage(明文,tab 关闭清空),下次刷新免输
      try { sessionStorage.setItem(SKEY + "-pw", pw); } catch(e){}
      beacon("success");
      renderPage(html);
      return true;
    } catch(e){
      if (btn) btn.disabled = false;
      if (!silent && err) { err.textContent = "密码错误"; }
      if (inp) { inp.select(); }
      return false;
    }
  }

  // 页面加载:如果 sessionStorage 里有上次输过的密码就自动试
  window.addEventListener("DOMContentLoaded", function(){
    beacon("load");
    let cached = null;
    try { cached = sessionStorage.getItem(SKEY + "-pw"); } catch(e){}
    if (cached) { attempt(cached, true); }
    const btn = document.getElementById("go");
    const inp = document.getElementById("pw");
    btn.addEventListener("click", () => attempt(inp.value, false));
    inp.addEventListener("keydown", e => { if (e.key === "Enter") attempt(inp.value, false); });
  });
})();
</script>
</body>
</html>
"""


def is_already_encrypted(html: str) -> bool:
    return "__PAYLOAD_B64__" not in html and "PBKDF2" in html and "AES-GCM" in html and "PAYLOAD =" in html


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-p", "--password", help="密码;不传则交互式输入")
    ap.add_argument("--pw-file", help="从文件读密码(单行,首尾空白剥掉);用于定时任务,避免密码出现在命令行/日志")
    ap.add_argument("--force", action="store_true", help="即使 index.html 看起来已加密也继续(会用 index.plain.html 作为源)")
    args = ap.parse_args()

    if not TARGET.exists():
        print(f"[ERR] {TARGET} 不存在", file=sys.stderr); sys.exit(1)

    current = TARGET.read_text(encoding="utf-8")

    # 判断源:如果 index.html 已经是加密页,就从 index.plain.html 读
    if is_already_encrypted(current):
        if not PLAIN_BAK.exists():
            print(f"[ERR] index.html 已经是加密页,但找不到 {PLAIN_BAK.name} 作为源文件", file=sys.stderr)
            sys.exit(2)
        src_html = PLAIN_BAK.read_text(encoding="utf-8")
        print(f"[INFO] 检测到 index.html 已加密,从 {PLAIN_BAK.name} 读取源")
    else:
        src_html = current
        # 备份明文(只在还没备份时)
        if not PLAIN_BAK.exists():
            PLAIN_BAK.write_text(src_html, encoding="utf-8")
            print(f"[INFO] 备份明文到 {PLAIN_BAK.name}")
        else:
            # 覆盖备份为最新明文
            PLAIN_BAK.write_text(src_html, encoding="utf-8")
            print(f"[INFO] 刷新明文备份 {PLAIN_BAK.name}")

    if args.pw_file:
        pw_path = Path(args.pw_file)
        if not pw_path.exists():
            print(f"[ERR] --pw-file 指向的文件不存在: {pw_path}", file=sys.stderr); sys.exit(3)
        pw = pw_path.read_text(encoding="utf-8").strip()
    else:
        pw = args.password or getpass.getpass("密码: ")
    if not pw:
        print("[ERR] 密码为空", file=sys.stderr); sys.exit(3)

    salt = os.urandom(16)
    iv   = os.urandom(12)
    kdf  = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERS)
    key  = kdf.derive(pw.encode("utf-8"))
    ct   = AESGCM(key).encrypt(iv, src_html.encode("utf-8"), None)

    out = (WRAPPER_TEMPLATE
           .replace("__PAYLOAD_B64__", base64.b64encode(ct).decode())
           .replace("__SALT_B64__",    base64.b64encode(salt).decode())
           .replace("__IV_B64__",      base64.b64encode(iv).decode())
           .replace("__ITERS__",       str(ITERS)))

    TARGET.write_text(out, encoding="utf-8")
    print(f"[OK] 已生成加密页: {TARGET}  ({len(out):,} bytes,密文 {len(ct):,} bytes)")


if __name__ == "__main__":
    main()
