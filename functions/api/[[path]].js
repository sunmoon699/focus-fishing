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

/* ---------- 社交 / 统计（联机前置） ---------- */

function todayStrLocal(){
  const d = new Date(), p = n => ('0' + n).slice(-2);
  return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate());
}
/* 登录名大小写不敏感匹配：SQLite 的 TEXT = 默认区分大小写（BINARY），
   直接用 username = ? 会导致"张三"搜不到"张三"以外的写法；统一用 LOWER 比对，
   搜索 / 申请 / 通过 / 拒绝 / 撤回 全部受益。 */
async function uidByUsername(env, u){
  return await env.DB.prepare('SELECT id, username FROM users WHERE LOWER(username) = LOWER(?)').bind(u).first() || null;
}
/* 从用户存档里取 profile.name / profile.avatar（头像配置供前端渲染像素头像） */
async function getProfile(env, uid){
  const s = await env.DB.prepare('SELECT data FROM saves WHERE user_id = ?').bind(uid).first();
  let name = '', avatar = null;
  if(s && s.data){
    try{
      const j = JSON.parse(s.data);
      if(j && j.profile){ name = j.profile.name || ''; avatar = j.profile.avatar || null; }
    }catch(e){}
  }
  return { name: name, avatar: avatar };
}
/* 未处理的好友申请超 10 天自动清理（Q8） */
async function cleanupExpiredRequests(env){
  const cut = Date.now() - 10 * 24 * 3600 * 1000;
  try{ await env.DB.prepare('DELETE FROM friend_requests WHERE created_at < ?').bind(cut).run(); }catch(e){}
}

async function handleFriendSearch(req, env, uid){
  const b = await readJson(req);
  const u = (b.username || '').trim();
  if(!validUsername(u)) return bad('请输入 2–16 位字母、数字、下划线或汉字');
  const t = await uidByUsername(env, u);
  if(!t) return ok({ found: false });
  if(t.id === uid) return ok({ found: true, self: true, username: t.username });
  const prof = await getProfile(env, t.id);
  let relation = 'none';
  if(await env.DB.prepare('SELECT 1 FROM friends WHERE user_id=? AND friend_id=?').bind(uid, t.id).first()) relation = 'friend';
  else if(await env.DB.prepare('SELECT 1 FROM friend_requests WHERE from_id=? AND to_id=?').bind(uid, t.id).first()) relation = 'pending_out';
  else if(await env.DB.prepare('SELECT 1 FROM friend_requests WHERE from_id=? AND to_id=?').bind(t.id, uid).first()) relation = 'pending_in';
  return ok({ found: true, self: false, username: t.username, name: prof.name, avatar: prof.avatar, relation: relation });
}

async function handleFriendRequest(req, env, uid, myname){
  const b = await readJson(req);
  const u = (b.username || '').trim();
  if(!validUsername(u)) return bad('用户名格式有误');
  const t = await uidByUsername(env, u);
  if(!t) return bad('用户不存在');
  if(t.id === uid) return bad('不能添加自己为好友');
  cleanupExpiredRequests(env);
  if(await env.DB.prepare('SELECT 1 FROM friends WHERE user_id=? AND friend_id=?').bind(uid, t.id).first()) return bad('已经是好友了');
  if(await env.DB.prepare('SELECT 1 FROM friend_requests WHERE from_id=? AND to_id=?').bind(uid, t.id).first()) return bad('已经申请过该用户，请等待对方通过');
  if(await env.DB.prepare('SELECT 1 FROM friend_requests WHERE from_id=? AND to_id=?').bind(t.id, uid).first()) return bad('对方已向你发送申请，请去通知区处理');
  /* 频率限制：每用户每小时最多 20 次申请（Q7） */
  const cnt = await env.DB.prepare('SELECT COUNT(*) AS c FROM friend_requests WHERE from_id=? AND created_at>=?').bind(uid, Date.now() - 3600 * 1000).first();
  if(cnt && cnt.c >= 20) return bad('申请过于频繁，请稍后再试', 429);
  const now = Date.now();
  await env.DB.prepare('INSERT INTO friend_requests(from_id, to_id, created_at) VALUES(?,?,?)').bind(uid, t.id, now).run();
  await env.DB.prepare("INSERT INTO notifications(user_id, type, from_id, from_name, read, created_at) VALUES(?, ?, ?, ?, ?, ?)")
    .bind(t.id, 'friend_request', uid, myname || '', 0, now).run();
  return ok({});
}

async function handleFriendAccept(req, env, uid, myname){
  const b = await readJson(req);
  const u = (b.username || '').trim();
  const t = await uidByUsername(env, u);
  if(!t) return bad('用户不存在');
  if(!await env.DB.prepare('SELECT 1 FROM friend_requests WHERE from_id=? AND to_id=?').bind(t.id, uid).first()) return bad('没有待处理的好友申请');
  const now = Date.now();
  await env.DB.prepare('DELETE FROM friend_requests WHERE from_id=? AND to_id=?').bind(t.id, uid).run();
  await env.DB.prepare('INSERT INTO friends(user_id, friend_id, starred, last_interact, created_at) VALUES(?,?,0,?,?)').bind(uid, t.id, now, now).run();
  await env.DB.prepare('INSERT INTO friends(user_id, friend_id, starred, last_interact, created_at) VALUES(?,?,0,?,?)').bind(t.id, uid, now, now).run();
  await env.DB.prepare("INSERT INTO notifications(user_id, type, from_id, from_name, read, created_at) VALUES(?, ?, ?, ?, ?, ?)")
    .bind(t.id, 'friend_accepted', uid, myname || '', 0, now).run();
  return ok({});
}

async function handleFriendReject(req, env, uid){
  const b = await readJson(req);
  const u = (b.username || '').trim();
  const t = await uidByUsername(env, u);
  if(!t) return bad('用户不存在');
  await env.DB.prepare('DELETE FROM friend_requests WHERE from_id=? AND to_id=?').bind(t.id, uid).run();
  await env.DB.prepare("INSERT INTO notifications(user_id, type, from_id, from_name, read, created_at) VALUES(?, ?, ?, ?, ?, ?)")
    .bind(t.id, 'request_rejected', uid, '', 0, Date.now()).run();
  return ok({});
}

async function handleFriendCancel(req, env, uid){
  const b = await readJson(req);
  const u = (b.username || '').trim();
  const t = await uidByUsername(env, u);
  if(!t) return bad('用户不存在');
  await env.DB.prepare('DELETE FROM friend_requests WHERE from_id=? AND to_id=?').bind(uid, t.id).run();
  await env.DB.prepare("DELETE FROM notifications WHERE type='friend_request' AND user_id=? AND from_id=?").bind(t.id, uid).run();
  return ok({});
}

async function handleFriendList(env, uid, dateStr){
  const rows = await env.DB.prepare('SELECT friend_id, starred, last_interact FROM friends WHERE user_id=?').bind(uid).all();
  const out = [];
  for(const r of (rows.results || [])){
    const u = await env.DB.prepare('SELECT username FROM users WHERE id=?').bind(r.friend_id).first();
    if(!u) continue;
    const prof = await getProfile(env, r.friend_id);
    const st = await env.DB.prepare('SELECT focus_min, fish, coins FROM daily_stats WHERE user_id=? AND date=?').bind(r.friend_id, dateStr).first();
    out.push({
      username: u.username, name: prof.name, avatar: prof.avatar, starred: !!r.starred,
      last_interact: r.last_interact || 0,
      today: { focusMin: st ? st.focus_min : 0, fish: st ? st.fish : 0, coins: st ? st.coins : 0 }
    });
  }
  out.sort((a, b) => (b.last_interact || 0) - (a.last_interact || 0));   /* Q4：按最近互动排序 */
  return ok({ friends: out });
}

async function handleFriendStar(req, env, uid){
  const b = await readJson(req);
  const u = (b.username || '').trim();
  const t = await uidByUsername(env, u);
  if(!t) return bad('用户不存在');
  if(!await env.DB.prepare('SELECT 1 FROM friends WHERE user_id=? AND friend_id=?').bind(uid, t.id).first()) return bad('还不是好友');
  await env.DB.prepare('UPDATE friends SET starred=? WHERE user_id=? AND friend_id=?').bind(b.starred ? 1 : 0, uid, t.id).run();
  return ok({ starred: !!b.starred });
}

async function handleFriendRemove(req, env, uid, myname){
  const b = await readJson(req);
  const u = (b.username || '').trim();
  const t = await uidByUsername(env, u);
  if(!t) return bad('用户不存在');
  await env.DB.prepare('DELETE FROM friends WHERE user_id=? AND friend_id=?').bind(uid, t.id).run();
  await env.DB.prepare('DELETE FROM friends WHERE user_id=? AND friend_id=?').bind(t.id, uid).run();
  await env.DB.prepare("INSERT INTO notifications(user_id, type, from_id, from_name, read, created_at) VALUES(?, ?, ?, ?, ?, ?)")
    .bind(t.id, 'friend_removed', uid, myname || '', 0, Date.now()).run();
  return ok({});
}

async function handleNotifications(env, uid){
  cleanupExpiredRequests(env);
  const inRows  = await env.DB.prepare('SELECT from_id, created_at FROM friend_requests WHERE to_id=?').bind(uid).all();
  const outRows = await env.DB.prepare('SELECT to_id, created_at FROM friend_requests WHERE from_id=?').bind(uid).all();
  const notices = await env.DB.prepare("SELECT id, type, from_name, read, created_at FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 50").bind(uid).all();
  const inList = [], outList = [];
  for(const r of (inRows.results || [])){
    const u = await env.DB.prepare('SELECT username FROM users WHERE id=?').bind(r.from_id).first(); if(!u) continue;
    const p = await getProfile(env, r.from_id);
    inList.push({ username: u.username, name: p.name, avatar: p.avatar, created_at: r.created_at });
  }
  for(const r of (outRows.results || [])){
    const u = await env.DB.prepare('SELECT username FROM users WHERE id=?').bind(r.to_id).first(); if(!u) continue;
    const p = await getProfile(env, r.to_id);
    outList.push({ username: u.username, name: p.name, avatar: p.avatar, created_at: r.created_at });
  }
  const ns = (notices.results || []).map(r => ({ id: r.id, type: r.type, from_name: r.from_name, read: !!r.read, created_at: r.created_at }));
  return ok({ requests_in: inList, requests_out: outList, notices: ns, unread: ns.filter(r => !r.read).length });
}

async function handleNotifRead(req, env, uid){
  const b = await readJson(req);
  if(b.id) await env.DB.prepare('UPDATE notifications SET read=1 WHERE id=? AND user_id=?').bind(b.id, uid).run();
  else      await env.DB.prepare('UPDATE notifications SET read=1 WHERE user_id=?').bind(uid).run();
  return ok({});
}

async function handleStatsReport(req, env, uid){
  const b = await readJson(req);
  const date = (b.date || '').trim();
  if(!/^\d{4}-\d{2}-\d{2}$/.test(date)) return bad('日期格式有误');
  const fm = Math.max(0, Math.min(100000, b.focusMin | 0));
  const fish = Math.max(0, Math.min(100000, b.fish | 0));
  const coins = Math.max(0, Math.min(1000000000, b.coins | 0));
  await env.DB.prepare(
    'INSERT INTO daily_stats(user_id, date, focus_min, fish, coins, updated_at) VALUES(?,?,?,?,?,?) ' +
    'ON CONFLICT(user_id,date) DO UPDATE SET focus_min=excluded.focus_min, fish=excluded.fish, coins=excluded.coins, updated_at=excluded.updated_at'
  ).bind(uid, date, fm, fish, coins, Date.now()).run();
  return ok({});
}

/* 注销账号：删除该用户的一切数据。
   先清 rooms（host_id 无级联，需手动删；其 room_players 经 rooms 级联删除），
   再删 users；saves / sessions / friends / friend_requests / notifications /
   daily_stats / room_players 均通过 users 的 ON DELETE CASCADE 一并清理。 */
async function handleAccountDelete(env, uid){
  await env.DB.prepare('DELETE FROM rooms WHERE host_id = ?').bind(uid).run();
  await env.DB.prepare('DELETE FROM users WHERE id = ?').bind(uid).run();
  return ok({});
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

    /* 社交 / 统计（需登录） */
    if(path === 'friend/search'    || path === 'friend/request'  || path === 'friend/accept' ||
       path === 'friend/reject'    || path === 'friend/cancel'   || path === 'friend/list'  ||
       path === 'friend/star'      || path === 'friend/remove'   || path === 'notifications' ||
       path === 'notification/read' || path === 'stats/report'   || path === 'account/delete'){
      const u = await resolveUser(env, request);
      if(!u) return bad('登录已失效，请重新登录', 401);
      if(path === 'friend/search'){        if(request.method!=='POST') return bad('方法不支持',405); return await handleFriendSearch(request, env, u.uid); }
      if(path === 'friend/request'){       if(request.method!=='POST') return bad('方法不支持',405); return await handleFriendRequest(request, env, u.uid, u.username); }
      if(path === 'friend/accept'){        if(request.method!=='POST') return bad('方法不支持',405); return await handleFriendAccept(request, env, u.uid, u.username); }
      if(path === 'friend/reject'){        if(request.method!=='POST') return bad('方法不支持',405); return await handleFriendReject(request, env, u.uid); }
      if(path === 'friend/cancel'){        if(request.method!=='POST') return bad('方法不支持',405); return await handleFriendCancel(request, env, u.uid); }
      if(path === 'friend/list'){          if(request.method!=='GET')  return bad('方法不支持',405);
        const dt = (new URL(request.url).searchParams.get('date') || '').trim();
        return await handleFriendList(env, u.uid, dt || todayStrLocal()); }
      if(path === 'friend/star'){          if(request.method!=='POST') return bad('方法不支持',405); return await handleFriendStar(request, env, u.uid); }
      if(path === 'friend/remove'){        if(request.method!=='POST') return bad('方法不支持',405); return await handleFriendRemove(request, env, u.uid, u.username); }
      if(path === 'notifications'){        if(request.method!=='GET')  return bad('方法不支持',405); return await handleNotifications(env, u.uid); }
      if(path === 'notification/read'){    if(request.method!=='POST') return bad('方法不支持',405); return await handleNotifRead(request, env, u.uid); }
      if(path === 'stats/report'){         if(request.method!=='POST') return bad('方法不支持',405); return await handleStatsReport(request, env, u.uid); }
      if(path === 'account/delete'){       if(request.method!=='POST') return bad('方法不支持',405); return await handleAccountDelete(env, u.uid); }
      return bad('未知接口', 404);
    }

    return bad('未知接口', 404);
  }catch(e){
    return json({ ok: false, msg: '服务端异常：' + (e && e.message ? e.message : '未知错误') }, 500);
  }
}
