// Encrypt every standalone HTML page before it is copied to a public repo.
// Requires only Node.js; the password is generated once in a local ignored file.
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const root = __dirname;
const source = path.join(root, 'traces_20261010');
const output = path.join(root, 'locked_site');
const secretPath = path.join(root, 'site_password.txt');
const iterations = 600000;

if (!fs.existsSync(secretPath)) {
  fs.writeFileSync(secretPath, crypto.randomBytes(24).toString('base64url') + '\n', {flag:'wx'});
  console.log('Generated a new password in site_password.txt. Keep this file private.');
}
const password = fs.readFileSync(secretPath, 'utf8').trim();
if (password.length < 24) throw new Error('Use a password of at least 24 characters.');

function encrypt(markup) {
  const salt = crypto.randomBytes(16);
  const iv = crypto.randomBytes(12);
  const key = crypto.pbkdf2Sync(password, salt, iterations, 32, 'sha256');
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const body = Buffer.concat([cipher.update(Buffer.from(markup, 'utf8')), cipher.final(), cipher.getAuthTag()]);
  return {salt:salt.toString('base64'),iv:iv.toString('base64'),body:body.toString('base64')};
}

function wrapper(payload) {
  return `<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>教材の閲覧</title>
<style>*{box-sizing:border-box}body{font:16px/1.6 system-ui,'Yu Gothic UI',sans-serif;background:#f6f7fb;color:#1f2430;margin:0;display:grid;place-items:center;min-height:100vh;padding:20px}.box{background:white;border:1px solid #e3e6ee;border-radius:12px;padding:24px;width:min(100%,420px)}h1{font-size:21px;margin:0 0 10px}label{display:block;margin:14px 0 6px}input,button{font:inherit;width:100%;padding:10px;border-radius:8px}input{border:1px solid #aab1bf}button{margin-top:14px;border:0;background:#2f6fed;color:white;cursor:pointer}.error{color:#b42318;min-height:1.6em}</style></head><body>
<div class="box"><h1>教材の閲覧</h1><p>配布されたパスワードを入力してください。</p><form id="unlock"><label for="pass">パスワード</label><input id="pass" type="password" autocomplete="current-password" required><button>開く</button></form><p id="error" class="error" role="alert"></p></div>
<script>
const locked=${JSON.stringify(payload)};
const bytes=s=>Uint8Array.from(atob(s),c=>c.charCodeAt(0));
async function unlock(password){
  const raw=await crypto.subtle.importKey('raw',new TextEncoder().encode(password),'PBKDF2',false,['deriveKey']);
  const key=await crypto.subtle.deriveKey({name:'PBKDF2',salt:bytes(locked.salt),iterations:${iterations},hash:'SHA-256'},raw,{name:'AES-GCM',length:256},false,['decrypt']);
  const clear=await crypto.subtle.decrypt({name:'AES-GCM',iv:bytes(locked.iv)},key,bytes(locked.body));
  sessionStorage.setItem('trace-access-password',password);
  const markup=new TextDecoder().decode(clear);
  document.open();document.write(markup);document.close();
}
document.getElementById('unlock').addEventListener('submit',async e=>{e.preventDefault();document.getElementById('error').textContent='';try{await unlock(document.getElementById('pass').value)}catch{document.getElementById('error').textContent='パスワードを確認してください。'}});
const saved=sessionStorage.getItem('trace-access-password');
if(saved)unlock(saved).catch(()=>sessionStorage.removeItem('trace-access-password'));
</script></body></html>`;
}

const pages = fs.readdirSync(source).filter(name=>/^trace_.*\.html$/u.test(name)).sort();
if (!pages.length || !fs.existsSync(path.join(source,'index.html'))) throw new Error('Source pages or index.html not found.');
const mapping = new Map(pages.map((name,i)=>[name,'p'+String(i+1).padStart(3,'0')+'.html']));
let index = fs.readFileSync(path.join(source,'index.html'),'utf8');
for (const [from,to] of mapping) {
  const reference = 'href="'+from+'"';
  if (!index.includes(reference)) throw new Error('Missing index link for '+from);
  index=index.replaceAll(reference,'href="'+to+'"');
}
if (/href="trace_[^"]+\.html"/.test(index)) throw new Error('Unencrypted link remains in index.');
const files = new Map([['index.html',wrapper(encrypt(index))]]);
for (const [from,to] of mapping) {
  const markup=fs.readFileSync(path.join(source,from),'utf8');
  files.set(to,wrapper(encrypt(markup)));
}
fs.mkdirSync(output,{recursive:true});
for (const name of fs.readdirSync(output)) {
  if (/^(index|p\d+)\.html$/.test(name)) fs.unlinkSync(path.join(output,name));
}
for (const [name,markup] of files) {
  fs.writeFileSync(path.join(output,name),markup,'utf8');
}
fs.writeFileSync(path.join(output,'.nojekyll'),'');
console.log('Encrypted '+pages.length+' problems and index into locked_site/.');
