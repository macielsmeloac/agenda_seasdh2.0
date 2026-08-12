/* API Agenda Institucional SEASDH — sem dependências externas (Node 18+). */
const http = require('node:http');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');

const PORT = Number(process.env.PORT || 3000);
const SECRET = process.env.JWT_SECRET || 'altere-esta-chave-em-producao';
const DATA_FILE = path.join(__dirname, 'data.json');
const now = () => new Date().toISOString();
const id = () => crypto.randomUUID();
const b64 = value => Buffer.from(value).toString('base64url');
const unb64 = value => Buffer.from(value, 'base64url').toString();
const clean = value => String(value ?? '').trim().replace(/[<>]/g, '');
const safeUser = ({ passwordHash, ...user }) => user;

function passwordHash(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.pbkdf2Sync(String(password), salt, 120000, 32, 'sha256').toString('hex');
  return `${salt}:${hash}`;
}
function passwordMatches(password, stored) {
  const [salt, expected] = String(stored).split(':');
  if (!salt || !expected) return false;
  const actual = passwordHash(password, salt).split(':')[1];
  return crypto.timingSafeEqual(Buffer.from(actual, 'hex'), Buffer.from(expected, 'hex'));
}
function tokenFor(user) {
  const header = b64(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const payload = b64(JSON.stringify({ sub: user.id, role: user.role, exp: Math.floor(Date.now() / 1000) + 60 * 60 * 12 }));
  const signature = crypto.createHmac('sha256', SECRET).update(`${header}.${payload}`).digest('base64url');
  return `${header}.${payload}.${signature}`;
}
function tokenPayload(token) {
  const [header, payload, signature] = String(token || '').split('.');
  if (!header || !payload || !signature) return null;
  const expected = crypto.createHmac('sha256', SECRET).update(`${header}.${payload}`).digest('base64url');
  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected))) return null;
  try { const decoded = JSON.parse(unb64(payload)); return decoded.exp > Date.now() / 1000 ? decoded : null; } catch { return null; }
}
function initialData() {
  const email = process.env.ADMIN_EMAIL || 'administrador@seasdh.gov.br';
  return { users: [{ id: id(), name: process.env.ADMIN_NAME || 'Administrador SEASDH', email, username: 'administrador', department: 'Administração', division: '', title: 'Administrador do Sistema', phone: '', role: 'ADMIN', passwordHash: passwordHash(process.env.ADMIN_PASSWORD || 'seasdh@2026'), createdAt: now() }], events: [], auditLogs: [] };
}
function load() { try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch { const data = initialData(); save(data); return data; } }
function save(data) { if (Array.isArray(data.users)) data.users.forEach(user => { user.role = user.username === 'maciel.soares' ? 'ADMIN' : 'USER'; }); fs.writeFileSync(DATA_FILE, JSON.stringify(data, null, 2), 'utf8'); }
let db = load();
db.users.forEach(user => { user.role = user.username === 'maciel.soares' ? 'ADMIN' : 'USER'; });
save(db);
function log(user, action, eventName) { db.auditLogs.unshift({ id: id(), userId: user.id, userName: user.name, action, eventName, createdAt: now() }); }

function send(res, status, body) { res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS' }); res.end(JSON.stringify(body)); }
function body(req) { return new Promise((resolve, reject) => { let raw = ''; req.on('data', part => { raw += part; if (raw.length > 1_000_000) reject(new Error('Payload muito grande')); }); req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch { reject(new Error('JSON inválido')); } }); req.on('error', reject); }); }
function authenticated(req) { const payload = tokenPayload(req.headers.authorization?.replace(/^Bearer\s+/i, '')); if (!payload) return null; return db.users.find(user => user.id === payload.sub) || null; }
function requireUser(req, res) { const user = authenticated(req); if (!user) { send(res, 401, { error: 'Não autenticado' }); return null; } return user; }
function requireAdmin(req, res) { const user = requireUser(req, res); if (!user) return null; if (user.role !== 'ADMIN') { send(res, 403, { error: 'Acesso restrito a administradores' }); return null; } return user; }
function validEvent(input) { return input && clean(input.title) && /^\d{4}-\d{2}-\d{2}$/.test(String(input.eventDate || input.date)) && /^\d{2}:\d{2}$/.test(String(input.eventTime || input.time)) && clean(input.location); }
function eventFrom(input, owner) { return { id: id(), userId: owner.id, responsible: clean(input.responsible) || owner.name, department: clean(input.department) || owner.department, title: clean(input.title), eventDate: String(input.eventDate || input.date), eventTime: String(input.eventTime || input.time), location: clean(input.location), tagText: clean(input.tagText || input.tag), tagColor: /^#[0-9a-f]{6}$/i.test(input.tagColor || input.color) ? (input.tagColor || input.color) : '#027E28', description: clean(input.description), createdAt: now(), updatedAt: now() }; }

const server = http.createServer(async (req, res) => {
  if (req.method === 'OPTIONS') return send(res, 204, {});
  const url = new URL(req.url, `http://${req.headers.host}`); const route = url.pathname; const parts = route.split('/').filter(Boolean);
  try {
    if (req.method === 'POST' && route === '/api/auth/register') {
      const input = await body(req); const name = clean(input.name); const email = clean(input.email).toLowerCase(); const username = clean(input.username).toLowerCase();
      if (!name || !email || !username || String(input.password || '').length < 8) return send(res, 422, { error: 'Nome, e-mail, usuário e senha de ao menos 8 caracteres são obrigatórios' });
      if (db.users.some(user => user.email === email || user.username === username)) return send(res, 409, { error: 'E-mail ou usuário já cadastrado' });
      const user = { id: id(), name, email, username, department: clean(input.department), division: clean(input.division), title: clean(input.title), phone: clean(input.phone), role: 'USER', createdByAdmin: false, passwordPersonalized: true, passwordHash: passwordHash(input.password), createdAt: now() }; db.users.push(user); save(db); return send(res, 201, { token: tokenFor(user), user: safeUser(user) });
    }
    if (req.method === 'POST' && route === '/api/auth/login') {
      const input = await body(req); const login = clean(input.login || input.username || input.email).toLowerCase(); const user = db.users.find(item => item.username === login || item.email === login);
      if (!user || !passwordMatches(input.password, user.passwordHash)) return send(res, 401, { error: 'Credenciais inválidas' });
      return send(res, 200, { token: tokenFor(user), user: safeUser(user) });
    }
    if (req.method === 'GET' && route === '/api/auth/me') { const user = requireUser(req, res); if (user) send(res, 200, { user: safeUser(user) }); return; }
    if (req.method === 'POST' && route === '/api/auth/change-password') { const user = requireUser(req, res); if (!user) return; if (!user.createdByAdmin || user.passwordPersonalized) return send(res, 403, { error: 'A senha pode ser personalizada uma única vez em contas criadas pelo administrador' }); const input = await body(req); if (!passwordMatches(input.currentPassword, user.passwordHash)) return send(res, 422, { error: 'Senha atual incorreta' }); if (String(input.newPassword || '').length < 8) return send(res, 422, { error: 'A nova senha deve ter ao menos 8 caracteres' }); user.passwordHash = passwordHash(input.newPassword); user.passwordPersonalized = true; save(db); return send(res, 204, {}); }
    if (route === '/api/events' && req.method === 'GET') { const user = requireUser(req, res); if (!user) return; let events = db.events; const start = url.searchParams.get('startDate'), end = url.searchParams.get('endDate'), text = clean(url.searchParams.get('q')).toLowerCase(); if (start) events = events.filter(event => event.eventDate >= start); if (end) events = events.filter(event => event.eventDate <= end); if (text) events = events.filter(event => `${event.title} ${event.tagText}`.toLowerCase().includes(text)); return send(res, 200, { events }); }
    if (route === '/api/events' && req.method === 'POST') { const user = requireUser(req, res); if (!user) return; const input = await body(req); if (!validEvent(input)) return send(res, 422, { error: 'Dados do evento inválidos' }); const event = eventFrom(input, user); db.events.push(event); log(user, 'CREATED', event.title); save(db); return send(res, 201, { event }); }
    if (parts[0] === 'api' && parts[1] === 'events' && parts[2]) {
      const user = requireUser(req, res); if (!user) return; const index = db.events.findIndex(event => event.id === parts[2]); if (index < 0) return send(res, 404, { error: 'Evento não encontrado' }); const event = db.events[index]; if (user.role !== 'ADMIN' && event.userId !== user.id) return send(res, 403, { error: 'Sem permissão para este evento' });
      if (req.method === 'PUT') { const input = await body(req); if (!validEvent(input)) return send(res, 422, { error: 'Dados do evento inválidos' }); const updated = { ...eventFrom(input, user), id: event.id, userId: event.userId, createdAt: event.createdAt, updatedAt: now() }; db.events[index] = updated; log(user, 'EDITED', updated.title); save(db); return send(res, 200, { event: updated }); }
      if (req.method === 'DELETE') { db.events.splice(index, 1); log(user, 'DELETED', event.title); save(db); return send(res, 204, {}); }
    }
    if (route === '/api/users' && req.method === 'GET') { const admin = requireAdmin(req, res); if (admin) send(res, 200, { users: db.users.map(safeUser) }); return; }
    if (route === '/api/users' && req.method === 'POST') { const admin = requireAdmin(req, res); if (!admin) return; const input = await body(req); const name = clean(input.name), email = clean(input.email).toLowerCase(), username = clean(input.username).toLowerCase(), role = input.role === 'ADMIN' ? 'ADMIN' : 'USER'; if (!name || !email || !username || String(input.password || '').length < 8) return send(res, 422, { error: 'Dados obrigatórios ausentes' }); if (db.users.some(user => user.email === email || user.username === username)) return send(res, 409, { error: 'E-mail ou usuário já cadastrado' }); const user = { id: id(), name, email, username, department: clean(input.department), division: clean(input.division), title: clean(input.title), phone: clean(input.phone), role, createdByAdmin: true, passwordPersonalized: false, passwordHash: passwordHash(input.password), createdAt: now() }; db.users.push(user); save(db); return send(res, 201, { user: safeUser(user) }); }
    if (parts[0] === 'api' && parts[1] === 'users' && parts[2]) { const admin = requireAdmin(req, res); if (!admin) return; const index = db.users.findIndex(user => user.id === parts[2]); if (index < 0) return send(res, 404, { error: 'Usuário não encontrado' }); if (db.users[index].id === admin.id && req.method !== 'GET') return send(res, 400, { error: 'Não altere sua própria conta por esta rota' }); if (req.method === 'PUT') { const input = await body(req); db.users[index] = { ...db.users[index], name: clean(input.name) || db.users[index].name, department: clean(input.department) || db.users[index].department, division: clean(input.division), title: clean(input.title), phone: clean(input.phone), role: input.role === 'ADMIN' ? 'ADMIN' : 'USER' }; save(db); return send(res, 200, { user: safeUser(db.users[index]) }); } if (req.method === 'DELETE') { db.users.splice(index, 1); save(db); return send(res, 204, {}); } }
    if (parts[0] === 'api' && parts[1] === 'users' && parts[2] && parts[3] === 'reset-password' && req.method === 'POST') { const admin = requireAdmin(req, res); if (!admin) return; const user = db.users.find(item => item.id === parts[2]); const input = await body(req); if (!user) return send(res, 404, { error: 'Usuário não encontrado' }); if (String(input.newPassword || '').length < 8) return send(res, 422, { error: 'A nova senha deve ter ao menos 8 caracteres' }); user.passwordHash = passwordHash(input.newPassword); user.passwordPersonalized = false; save(db); return send(res, 204, {}); }
    if (route === '/api/audit-logs' && req.method === 'GET') { const admin = requireAdmin(req, res); if (!admin) return; const start = url.searchParams.get('startDate'), end = url.searchParams.get('endDate'); const logs = db.auditLogs.filter(item => (!start || item.createdAt.slice(0, 10) >= start) && (!end || item.createdAt.slice(0, 10) <= end)); return send(res, 200, { auditLogs: logs }); }
    send(res, 404, { error: 'Rota não encontrada' });
  } catch (error) { send(res, 400, { error: error.message || 'Erro ao processar a solicitação' }); }
});
server.listen(PORT, () => console.log(`Agenda Social API em http://localhost:${PORT}`));
