'use strict';
/*
 * Дневник ДЗ — local server.
 * No dependencies: plain Node.js (18+). Data lives in ./data/db.json,
 * homework photos in ./data/photos/. Start with `node server.js`.
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const os = require('node:os');

const PORT = Number(process.env.PORT) || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'db.json');
const PHOTO_DIR = path.join(DATA_DIR, 'photos');
const SESSION_DAYS = 60;
const DEFAULT_BELLS = {dayStart: '08:00', lessonLen: 40, breakLen: 10};
const ID_RE = /^[A-Za-z0-9_-]{4,40}$/;
const DATE_RE = /^\d{4}-\d{2}-\d{2}$/;
const TIME_RE = /^\d{1,2}:\d{2}$/;

fs.mkdirSync(PHOTO_DIR, {recursive: true});

/* ---------- seed: class 11б timetable (index = lesson number - 1, null = no lesson) ---------- */
const PRESET = {
  1: [['Разговоры о важном', '304'], ['История', '304'], ['География', '306'], ['Вероятность и статистика', '115'], ['Русский язык', '207'], ['Русский язык', '207']],
  2: [['Физика', '221'], ['Физика', '221'], ['Биология', '208'], ['Физкультура', ''], ['Алгебра', '114'], ['Алгебра', '114']],
  3: [['Фил. проблемы современности', '304'], ['История', '304'], ['История', '304'], ['Литература', '207'], ['Литература', '207'], ['Физкультура', ''], ['Геометрия', '115'], ['Алгебра', '115']],
  4: [['Информатика', '309'], ['История', '304'], ['Обществознание', '304'], ['Обществознание', '304'], ['Литература', '207'], ['Смысловой лингв. анализ', '207'], ['Немецкий язык', '310'], ['Немецкий язык', '310']],
  5: [['Дискуссионные вопросы истории', '304'], ['Дискуссионные вопросы истории', '304'], ['Обществознание', '304'], ['Обществознание', '304'], ['ОБЗР', '108'], ['Смысловой лингв. анализ', '207'], ['Английский язык', '219'], ['Химия', '307']],
  6: [null, ['Немецкий язык / Информатика', '106/309'], ['Избранные вопросы математики', '115'], ['Избранные вопросы математики', '115'], ['Английский язык', '219'], ['Английский язык', '219']]
};
const PALETTE = ['#4A74E0', '#2E9E77', '#D08A2E', '#D0584F', '#7B68D8', '#2A9DB0', '#B0569E', '#5E8A3A', '#C2703D', '#5872B8'];
const newId = () => crypto.randomBytes(9).toString('base64url');
function seedSchedule() {
  const subjects = [], lessons = [];
  for (const wd of [1, 2, 3, 4, 5, 6]) {
    PRESET[wd].forEach((item, i) => {
      if (!item) return;
      let s = subjects.find(x => x.name === item[0]);
      if (!s) { s = {id: newId(), name: item[0], color: PALETTE[subjects.length % PALETTE.length]}; subjects.push(s); }
      lessons.push({id: newId(), weekday: wd, period: i + 1, subjectId: s.id, room: item[1]});
    });
  }
  return {subjects, lessons, bells: {...DEFAULT_BELLS}, updatedAt: new Date().toISOString()};
}

/* ---------- storage ---------- */
let db;
function loadDb() {
  try {
    db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
  } catch (e) {
    if (e.code !== 'ENOENT') {
      console.error('Не удалось прочитать ' + DB_FILE + '. Файл повреждён, сервер остановлен, чтобы не затереть данные.');
      console.error(e.message);
      process.exit(1);
    }
    db = {users: [], sessions: {}, schedule: seedSchedule(), homeworks: [], prefs: {}};
    saveDbNow();
  }
  db.users ||= []; db.sessions ||= {}; db.homeworks ||= []; db.prefs ||= {};
  db.schedule ||= {subjects: [], lessons: [], bells: {...DEFAULT_BELLS}};
}
let saveTimer = null;
function saveDb() { clearTimeout(saveTimer); saveTimer = setTimeout(saveDbNow, 150); }
function saveDbNow() {
  clearTimeout(saveTimer);
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db));
  fs.renameSync(tmp, DB_FILE);
}
for (const sig of ['SIGINT', 'SIGTERM']) process.on(sig, () => { saveDbNow(); process.exit(0); });

const photoFile = id => path.join(PHOTO_DIR, id + '.jpg');
function removePhoto(id) { if (ID_RE.test(id)) fs.rm(photoFile(id), {force: true}, () => {}); }
function writePhoto(id, dataUrl) {
  const m = /^data:image\/jpeg;base64,([A-Za-z0-9+/=]+)$/.exec(dataUrl || '');
  if (!ID_RE.test(id) || !m) return false;
  fs.writeFileSync(photoFile(id), Buffer.from(m[1], 'base64'));
  return true;
}

/* ---------- auth ---------- */
const hashPassword = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString('hex');
function checkPassword(user, pw) {
  const got = Buffer.from(hashPassword(pw, user.salt), 'hex'), want = Buffer.from(user.hash, 'hex');
  return got.length === want.length && crypto.timingSafeEqual(got, want);
}
function setPassword(user, pw) { user.salt = crypto.randomBytes(16).toString('hex'); user.hash = hashPassword(pw, user.salt); }
function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}
function currentUser(req) {
  const token = parseCookies(req).sid;
  const s = token && db.sessions[token];
  if (!s) return null;
  if (Date.now() - s.created > SESSION_DAYS * 86400000) { delete db.sessions[token]; saveDb(); return null; }
  return db.users.find(u => u.id === s.userId) || null;
}
function startSession(res, user) {
  const token = crypto.randomBytes(24).toString('base64url');
  db.sessions[token] = {userId: user.id, created: Date.now()};
  saveDb();
  res.setHeader('Set-Cookie', 'sid=' + token + '; HttpOnly; SameSite=Lax; Path=/; Max-Age=' + SESSION_DAYS * 86400);
}
function endSessionsOf(userId, except) {
  for (const [t, s] of Object.entries(db.sessions)) if (s.userId === userId && t !== except) delete db.sessions[t];
}
const attempts = new Map();
function tooManyAttempts(ip) {
  const now = Date.now();
  let a = attempts.get(ip);
  if (!a || a.reset < now) { a = {n: 0, reset: now + 10 * 60000}; attempts.set(ip, a); }
  return ++a.n > 30;
}
const validName = n => typeof n === 'string' ? n.trim().replace(/\s+/g, ' ').slice(0, 40) : '';
function passwordProblem(pw) {
  if (typeof pw !== 'string' || pw.length < 6) return 'Пароль должен быть не короче 6 символов.';
  if (pw.length > 200) return 'Пароль слишком длинный.';
  return null;
}

/* ---------- validation ---------- */
const str = (v, max) => typeof v === 'string' ? v.slice(0, max) : '';
const int = (v, lo, hi, dflt) => { const n = Math.round(Number(v)); return Number.isFinite(n) && n >= lo && n <= hi ? n : dflt; };
function cleanSchedule(b) {
  const subjects = (Array.isArray(b?.subjects) ? b.subjects : []).slice(0, 200)
    .map(s => ({id: str(s?.id, 40), name: str(s?.name, 80).trim(), color: str(s?.color, 16)}))
    .filter(s => ID_RE.test(s.id) && s.name);
  const ids = new Set(subjects.map(s => s.id));
  const lessons = (Array.isArray(b?.lessons) ? b.lessons : []).slice(0, 400)
    .map(l => ({id: str(l?.id, 40), weekday: int(l?.weekday, 0, 6, -1), period: int(l?.period, 1, 10, -1), subjectId: str(l?.subjectId, 40), room: str(l?.room, 20)}))
    .filter(l => ID_RE.test(l.id) && l.weekday >= 0 && l.period > 0 && ids.has(l.subjectId));
  const bells = b?.bells || {};
  return {
    subjects, lessons,
    bells: {
      dayStart: TIME_RE.test(bells.dayStart) ? bells.dayStart : DEFAULT_BELLS.dayStart,
      lessonLen: int(bells.lessonLen, 20, 90, DEFAULT_BELLS.lessonLen),
      breakLen: int(bells.breakLen, 0, 60, DEFAULT_BELLS.breakLen)
    },
    updatedAt: new Date().toISOString()
  };
}
function cleanHomework(id, b, prev, user) {
  return {
    id,
    subjectId: str(b?.subjectId, 40),
    due: DATE_RE.test(b?.due) ? b.due : '',
    text: str(b?.text, 4000),
    photos: (Array.isArray(b?.photos) ? b.photos : []).filter(p => typeof p === 'string' && ID_RE.test(p)).slice(0, 12),
    createdAt: prev?.createdAt || new Date().toISOString(),
    author: prev ? prev.author : user.id,
    updatedAt: new Date().toISOString(),
    updatedBy: user.id
  };
}
function cleanPrefs(b) {
  const done = {};
  if (b?.done && typeof b.done === 'object') {
    for (const [k, v] of Object.entries(b.done).slice(0, 5000)) if (ID_RE.test(k) && typeof v === 'string') done[k] = v.slice(0, 40);
  }
  const plan = {};
  if (b?.plan && typeof b.plan === 'object') {
    for (const [k, v] of Object.entries(b.plan).slice(0, 5000)) if (ID_RE.test(k) && DATE_RE.test(v)) plan[k] = v;
  }
  return {
    done,
    plan,
    theme: ['system', 'light', 'dark'].includes(b?.theme) ? b.theme : 'system',
    remind: !!b?.remind,
    remindTime: TIME_RE.test(b?.remindTime) ? b.remindTime : '19:00'
  };
}

/* ---------- http helpers ---------- */
function send(res, code, obj) {
  res.writeHead(code, {'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store'});
  res.end(JSON.stringify(obj));
}
function readJson(req, limit) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => {
      size += c.length;
      if (size > limit) { reject(Object.assign(new Error('too big'), {status: 413})); req.destroy(); }
      else chunks.push(c);
    });
    req.on('end', () => {
      try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); }
      catch (e) { reject(Object.assign(new Error('bad json'), {status: 400})); }
    });
    req.on('error', reject);
  });
}
function lanUrls() {
  const out = [];
  for (const list of Object.values(os.networkInterfaces())) {
    for (const a of list || []) if (a.family === 'IPv4' && !a.internal) out.push('http://' + a.address + ':' + PORT);
  }
  return out;
}

/* ---------- live updates (Server-Sent Events) ---------- */
const clients = new Set();
function broadcast(kind) {
  const msg = 'event: change\ndata: ' + JSON.stringify({kind, at: Date.now()}) + '\n\n';
  for (const c of clients) c.write(msg);
}

function statePayload(user) {
  const users = {};
  for (const u of db.users) users[u.id] = u.name;
  return {
    me: {id: user.id, name: user.name, admin: !!user.admin},
    schedule: db.schedule, homeworks: db.homeworks, prefs: db.prefs[user.id] || null,
    users, lan: lanUrls()
  };
}

/* ---------- static files ---------- */
const TYPES = {'.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.png': 'image/png', '.svg': 'image/svg+xml', '.ico': 'image/x-icon', '.json': 'application/json', '.webmanifest': 'application/manifest+json'};
function serveStatic(pathname, res) {
  let p;
  try { p = decodeURIComponent(pathname); } catch (e) { res.writeHead(400); return res.end(); }
  if (p === '/') p = '/index.html';
  const file = path.normalize(path.join(PUBLIC_DIR, p));
  if (!file.startsWith(PUBLIC_DIR + path.sep)) { res.writeHead(403); return res.end(); }
  fs.readFile(file, (err, data) => {
    if (err) { res.writeHead(404, {'Content-Type': 'text/plain; charset=utf-8'}); return res.end('Не найдено'); }
    res.writeHead(200, {'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-cache'});
    res.end(data);
  });
}

/* ---------- API ---------- */
async function handleApi(req, res, p, m) {
  const ip = req.socket.remoteAddress || '';

  if (p === '/api/register' && m === 'POST') {
    if (tooManyAttempts(ip)) return send(res, 429, {error: 'Слишком много попыток. Подожди 10 минут.'});
    const b = await readJson(req, 10000);
    const name = validName(b.name);
    if (name.length < 2) return send(res, 400, {error: 'Имя должно быть не короче 2 символов.'});
    const problem = passwordProblem(b.password);
    if (problem) return send(res, 400, {error: problem});
    if (db.users.some(u => u.name.toLowerCase() === name.toLowerCase())) return send(res, 409, {error: 'Это имя уже занято. Придумай другое или войди.'});
    const user = {id: newId(), name, admin: db.users.length === 0, createdAt: new Date().toISOString()};
    setPassword(user, b.password);
    db.users.push(user);
    startSession(res, user);
    broadcast('users');
    return send(res, 200, {ok: true});
  }
  if (p === '/api/login' && m === 'POST') {
    if (tooManyAttempts(ip)) return send(res, 429, {error: 'Слишком много попыток. Подожди 10 минут.'});
    const b = await readJson(req, 10000);
    const name = validName(b.name).toLowerCase();
    const user = db.users.find(u => u.name.toLowerCase() === name);
    if (!user || typeof b.password !== 'string' || !checkPassword(user, b.password)) return send(res, 401, {error: 'Неверное имя или пароль.'});
    startSession(res, user);
    return send(res, 200, {ok: true});
  }
  if (p === '/api/logout' && m === 'POST') {
    const token = parseCookies(req).sid;
    if (token && db.sessions[token]) { delete db.sessions[token]; saveDb(); }
    res.setHeader('Set-Cookie', 'sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
    return send(res, 200, {ok: true});
  }

  const user = currentUser(req);
  if (!user) return send(res, 401, {error: 'Нужно войти.'});

  if (p === '/api/state' && m === 'GET') return send(res, 200, statePayload(user));

  if (p === '/api/events' && m === 'GET') {
    res.writeHead(200, {'Content-Type': 'text/event-stream; charset=utf-8', 'Cache-Control': 'no-store', 'Connection': 'keep-alive'});
    res.write('retry: 3000\n\n');
    clients.add(res);
    const ping = setInterval(() => res.write(': ping\n\n'), 25000);
    req.on('close', () => { clearInterval(ping); clients.delete(res); });
    return;
  }

  if (p === '/api/password' && m === 'POST') {
    const b = await readJson(req, 10000);
    if (typeof b.oldPassword !== 'string' || !checkPassword(user, b.oldPassword)) return send(res, 400, {error: 'Старый пароль указан неверно.'});
    const problem = passwordProblem(b.newPassword);
    if (problem) return send(res, 400, {error: problem});
    setPassword(user, b.newPassword);
    endSessionsOf(user.id, parseCookies(req).sid);
    saveDb();
    return send(res, 200, {ok: true});
  }

  if (p === '/api/schedule' && m === 'PUT') {
    db.schedule = cleanSchedule(await readJson(req, 500000));
    saveDb(); broadcast('schedule');
    return send(res, 200, {ok: true});
  }

  if (p === '/api/prefs' && m === 'PUT') {
    db.prefs[user.id] = cleanPrefs(await readJson(req, 500000));
    saveDb(); broadcast('prefs');
    return send(res, 200, {ok: true});
  }

  let match = /^\/api\/homeworks\/([A-Za-z0-9_-]{4,40})$/.exec(p);
  if (match) {
    const id = match[1], i = db.homeworks.findIndex(h => h.id === id);
    if (m === 'PUT') {
      const prev = i >= 0 ? db.homeworks[i] : null;
      const h = cleanHomework(id, await readJson(req, 100000), prev, user);
      if (!h.due || !h.subjectId) return send(res, 400, {error: 'У задания должны быть предмет и дата.'});
      if (prev) for (const pid of prev.photos || []) if (!h.photos.includes(pid)) removePhoto(pid);
      if (prev) db.homeworks[i] = h; else db.homeworks.push(h);
      saveDb(); broadcast('homeworks');
      return send(res, 200, {ok: true});
    }
    if (m === 'DELETE') {
      if (i >= 0) { const [h] = db.homeworks.splice(i, 1); (h.photos || []).forEach(removePhoto); saveDb(); broadcast('homeworks'); }
      return send(res, 200, {ok: true});
    }
  }

  if (p === '/api/photos' && m === 'POST') {
    const b = await readJson(req, 4 * 1024 * 1024);
    if (!writePhoto(b.id, b.data)) return send(res, 400, {error: 'Фото не удалось сохранить.'});
    return send(res, 200, {ok: true});
  }
  match = /^\/api\/photos\/([A-Za-z0-9_-]{4,40})$/.exec(p);
  if (match && m === 'GET') {
    return fs.readFile(photoFile(match[1]), (err, data) => {
      if (err) { res.writeHead(404); return res.end(); }
      res.writeHead(200, {'Content-Type': 'image/jpeg', 'Cache-Control': 'private, max-age=31536000, immutable'});
      res.end(data);
    });
  }

  /* admin-only: these change the diary for everyone */
  if (p.startsWith('/api/admin/')) {
    if (!user.admin) return send(res, 403, {error: 'Это может сделать только администратор дневника.'});
    if (p === '/api/admin/reset' && m === 'POST') {
      const b = await readJson(req, 10000);
      const target = db.users.find(u => u.id === b.userId);
      if (!target) return send(res, 404, {error: 'Такого ученика нет.'});
      const password = String(crypto.randomInt(100000, 1000000));
      setPassword(target, password);
      endSessionsOf(target.id);
      saveDb();
      return send(res, 200, {password});
    }
    if (p === '/api/admin/clear-old' && m === 'POST') {
      const b = await readJson(req, 1000);
      if (!DATE_RE.test(b.before)) return send(res, 400, {error: 'Нужна дата.'});
      const old = db.homeworks.filter(h => h.due < b.before);
      old.forEach(h => (h.photos || []).forEach(removePhoto));
      db.homeworks = db.homeworks.filter(h => h.due >= b.before);
      saveDb(); broadcast('homeworks');
      return send(res, 200, {removed: old.length});
    }
    if (p === '/api/admin/wipe' && m === 'POST') {
      db.homeworks.forEach(h => (h.photos || []).forEach(removePhoto));
      db.homeworks = [];
      db.schedule = {subjects: [], lessons: [], bells: {...DEFAULT_BELLS}, updatedAt: new Date().toISOString()};
      for (const pr of Object.values(db.prefs)) pr.done = {};
      saveDb(); broadcast('all');
      return send(res, 200, {ok: true});
    }
    if (p === '/api/admin/import' && m === 'POST') {
      const b = await readJson(req, 80 * 1024 * 1024);
      const schedule = cleanSchedule(b.schedule);
      const homeworks = (Array.isArray(b.homeworks) ? b.homeworks : []).slice(0, 4000)
        .map(h => cleanHomework(ID_RE.test(h?.id) ? h.id : newId(), h, {createdAt: h?.createdAt, author: h?.author || user.id}, user))
        .filter(h => h.due && h.subjectId);
      db.homeworks.forEach(h => (h.photos || []).forEach(removePhoto));
      let photos = 0;
      for (const [id, data] of Object.entries(b.photos || {})) if (writePhoto(id, data)) photos++;
      db.schedule = schedule; db.homeworks = homeworks;
      saveDb(); broadcast('all');
      return send(res, 200, {homeworks: homeworks.length, photos});
    }
  }

  return send(res, 404, {error: 'Не найдено.'});
}

loadDb();
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (!url.pathname.startsWith('/api/')) return serveStatic(url.pathname, res);
  try {
    await handleApi(req, res, url.pathname, req.method);
  } catch (e) {
    if (!e.status) console.error(e);
    if (!res.headersSent) send(res, e.status || 500, {error: e.status === 413 ? 'Слишком большой запрос.' : e.status === 400 ? 'Неверный запрос.' : 'Ошибка сервера.'});
  }
});
server.on('error', e => {
  if (e.code === 'EADDRINUSE') console.error('Порт ' + PORT + ' уже занят. Закрой другое окно с сервером или запусти так: set PORT=3001 && node server.js');
  else console.error(e);
  process.exit(1);
});
server.listen(PORT, '0.0.0.0', () => {
  console.log('');
  console.log('  Дневник ДЗ запущен');
  console.log('  На этом компьютере:  http://localhost:' + PORT);
  for (const u of lanUrls()) console.log('  С телефона (та же Wi-Fi сеть):  ' + u);
  console.log('');
  console.log('  Данные: ' + DB_FILE);
  console.log('  Остановить сервер: Ctrl+C');
  console.log('');
});
