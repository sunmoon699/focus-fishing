/* ============================================================
   专注钓鱼 —— Cloudflare Pages Functions 后端（账号 + 云存档）
   ------------------------------------------------------------
   这是一个 catch-all 路由（functions/api/[[path]].js），
   一个文件收拢全部接口，避免额外的辅助文件被误当成路由暴露。

   接口一览：
     GET  /api/ping          健康检查（前端据此判断后端是否就绪）
     POST /api/check         用户名是否可注册
     POST /api/register      注册（密码 + 确认密码）
     POST /api/login         登录
     GET  /api/save          读取云端存档（Bearer token）
     PUT  /api/save          写入云端存档（Bearer token）
     POST /api/logout        退出登录

   依赖：D1 绑定，变量名必须是 DB。
   ============================================================ */

const ITERATIONS = 100000;                  /* PBKDF2 轮数 */
const TOKEN_TTL  = 30 * 24 * 3600 * 1000;   /* 登录有效期 30 天 */
const SAVE_MAX   = 400 * 1024;              /* 单份存档上限 400KB */

/* ---------- 通用工具 ---------- */

function json(body, status){
  return new Response(JSON.stringify(body), {
    status: status || 200,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
      'access-control-allow-methods': 'GET, POST, PUT, OPTIONS',
      'access-control-allow-headers': 'content-type, authorization',
      'cache-control': 'no-store'
    }
  });
}
const ok  = (data, status) => json(Object.assign({ ok: true },  data || {}), status);
const bad = (msg, status, extra) =>
  json(Object.assign({ ok: false, msg: msg }, extra || {}), status || 400);

function toHex(bytes){
  return Array.prototype.map.call(new Uint8Array(bytes), function(b){
    return b.toString(16).padStart(2, '0');
  }).join('');
}
function fromHex(s){
  const a = new Uint8Array(s.length / 2);
  for(let i = 0; i < a.length; i++) a[i] = parseInt(s.substr(i * 2, 2), 16);
  return a;
}

/* 定长比较，避免通过响应时间侧信道逐字节猜哈希 */
function safeEqual(a, b){
  if(typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let d = 0;
  for(let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

async function hashPassword(password, saltHex){
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', salt: fromHex(saltHex), iterations: ITERATIONS, hash: 'SHA-256' },
    key, 256
  );
  return toHex(bits);
}
function newSalt(){ return toHex(crypto.getRandomValues(new Uint8Array(16))); }
function newToken(){ return toHex(crypto.getRandomValues(new Uint8Array(32))); }

/* 用户名：2–16 位，字母 / 数字 / 下划线 / 汉字 */
function validUsername(u){
  return typeof u === 'string' && /^[A-Za-z0-9_\u4e00-\u9fa5]{2,16}$/.test(u);
}
/* 密码：6–64 位。不做 trim —— 空格也是合法密码字符，但长度必须够 */
function validPassword(p){
  return typeof p === 'string' && p.length >= 6 && p.length <= 64;
}

async function readJson(req){
  try{ return await req.json() || {}; }catch(e){ return {}; }
}

/* ---------- 会话 ---------- */

async function resolveUser(env, req){
  const h = req.headers.get('authorization') || '';
  const m = h.match(/^Bearer\s+(.+)$/i);
  if(!m) return null;
  const token = m[1].trim();
  const row = await env.DB.prepare(
    'SELECT s.user_id AS uid, s.expires_at AS exp, u.username AS username ' +
    'FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token = ?'
  ).bind(token).first();
  if(!row) return null;
  if(row.exp && row.exp < Date.now()){
    await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
    return null;
  }
  return { uid: row.uid, username: row.username, token: token };
}

async function createSession(env, uid){
  const token = newToken(), now = Date.now();
  await env.DB.prepare(
    'INSERT INTO sessions(token, user_id, created_at, expires_at) VALUES(?,?,?,?)'
  ).bind(token, uid, now, now + TOKEN_TTL).run();
  return token;
}

async function readSave(env, uid){
  const s = await env.DB.prepare('SELECT data, updated_at FROM saves WHERE user_id = ?')
    .bind(uid).first();
  if(!s || !s.data) return { save: null, updatedAt: 0 };
  let save = null;
  try{ save = JSON.parse(s.data); }catch(e){ save = null; }
  return { save: save, updatedAt: s.updated_at || 0 };
}

/* ---------- 接口实现 ---------- */

async function handleCheck(req, env){
  const b = await readJson(req);
  const u = (b.username || '').trim();
  if(!u) return bad('请输入用户名');
  if(!validUsername(u)) return bad('用户名需为 2–16 位字母、数字、下划线或汉字', 400, { available: false });
  const row = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(u).first();
  return ok({ available: !row });
}

async function handleRegister(req, env){
  const b = await readJson(req);
  const username = (b.username || '').trim();
  const password = b.password;
  /* 两种字段名都认，前端用 confirmPassword */
  const confirm = (b.confirmPassword !== undefined) ? b.confirmPassword : b.confirm;

  if(!validUsername(username)) return bad('用户名需为 2–16 位字母、数字、下划线或汉字');
  if(!validPassword(password))  return bad('密码需 6–64 位');
  if(typeof confirm !== 'string') return bad('请填写确认密码');
  if(password !== confirm)        return bad('两次输入的密码不一致');

  const exist = await env.DB.prepare('SELECT id FROM users WHERE username = ?').bind(username).first();
  if(exist) return bad('用户名已被注册', 409);

  const salt = newSalt();
  const hash = await hashPassword(password, salt);
  const now = Date.now();
  const ins = await env.DB.prepare(
    'INSERT INTO users(username, pass_hash, pass_salt, created_at) VALUES(?,?,?,?)'
  ).bind(username, hash, salt, now).run();

  const uid = ins.meta && ins.meta.last_row_id;
  if(!uid) return bad('注册失败，请稍后重试', 500);

  const token = await createSession(env, uid);
  /* 新账号不预建空存档：返回 save=null，由前端把本机进度作为初始存档上传 */
  return ok({ token: token, username: username, save: null, updatedAt: 0 });
}

async function handleLogin(req, env){
  const b = await readJson(req);
  const username = (b.username || '').trim();
  const password = b.password || '';
  if(!username || !password) return bad('请输入用户名和密码');

  const u = await env.DB.prepare(
    'SELECT id, pass_hash, pass_salt FROM users WHERE username = ?'
  ).bind(username).first();
  if(!u) return bad('用户名不存在', 404);

  const h = await hashPassword(password, u.pass_salt);
  if(!safeEqual(h, u.pass_hash)) return bad('密码错误', 401);

  const token = await createSession(env, u.id);
  const s = await readSave(env, u.id);
  return ok({ token: token, username: username, save: s.save, updatedAt: s.updatedAt });
}

async function handleSaveGet(env, uid, username){
  const s = await readSave(env, uid);
  return ok({ save: s.save, updatedAt: s.updatedAt, username: username });
}

async function handleSavePut(req, env, uid){
  const b = await readJson(req);
  const data = b.data;
  if(!data || typeof data !== 'object' || Array.isArray(data)) return bad('存档数据格式有误');
  const str = JSON.stringify(data);
  if(str.length > SAVE_MAX) return bad('存档过大（上限 400KB）', 413);
  const now = Date.now();
  await env.DB.prepare(
    'INSERT INTO saves(user_id, data, updated_at) VALUES(?,?,?) ' +
    'ON CONFLICT(user_id) DO UPDATE SET data = excluded.data, updated_at = excluded.updated_at'
  ).bind(uid, str, now).run();
  return ok({ updatedAt: now });
}

/* ---------- 路由入口 ---------- */

export async function onRequest(context){
  const request = context.request, env = context.env;

  if(request.method === 'OPTIONS') return json({ ok: true });

  if(!env || !env.DB){
    return json({ ok: false, msg: '服务端未绑定 D1 数据库（变量名需为 DB）' }, 500);
  }

  let path = '';
  try{
    path = new URL(request.url).pathname.replace(/^\/api\/?/, '').replace(/\/+$/, '');
  }catch(e){ path = ''; }

  try{
    if(path === 'ping' && request.method === 'GET') return ok({ msg: 'pong' });

    if(path === 'check'){
      if(request.method !== 'POST') return bad('方法不支持', 405);
      return await handleCheck(request, env);
    }
    if(path === 'register'){
      if(request.method !== 'POST') return bad('方法不支持', 405);
      return await handleRegister(request, env);
    }
    if(path === 'login'){
      if(request.method !== 'POST') return bad('方法不支持', 405);
      return await handleLogin(request, env);
    }
    if(path === 'logout'){
      if(request.method !== 'POST') return bad('方法不支持', 405);
      const u = await resolveUser(env, request);
      if(u) await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(u.token).run();
      return ok({});
    }
    if(path === 'save'){
      const u = await resolveUser(env, request);
      if(!u) return bad('登录已失效，请重新登录', 401);
      if(request.method === 'GET')  return await handleSaveGet(env, u.uid, u.username);
      if(request.method === 'PUT')  return await handleSavePut(request, env, u.uid);
      return bad('方法不支持', 405);
    }

    return bad('未知接口', 404);
  }catch(e){
    return json({ ok: false, msg: '服务端异常：' + (e && e.message ? e.message : '未知错误') }, 500);
  }
}
