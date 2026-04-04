/**
 * Poll Platform / server.js
 * ──────────────────────────
 * Express + SQLite: 인증, 폴 생성/관리, AI 생성, 숏 URL, 결과 저장
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const { execSync } = require('child_process');

const app = express();
const PORT = process.env.PORT || 4000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// -- Database ----------------------------------------------------------------
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(path.join(DATA_DIR, 'poll.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

// -- Schema ------------------------------------------------------------------
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    email TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS invites (
    code TEXT PRIMARY KEY,
    created_by TEXT NOT NULL,
    used INTEGER NOT NULL DEFAULT 0,
    used_by TEXT,
    used_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS polls (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    description TEXT DEFAULT '',
    questions TEXT NOT NULL,
    settings TEXT DEFAULT '{}',
    result_mode TEXT,
    types TEXT,
    status TEXT NOT NULL DEFAULT 'active',
    response_count INTEGER NOT NULL DEFAULT 0,
    created_by TEXT DEFAULT 'system',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS responses (
    id TEXT PRIMARY KEY,
    poll_id TEXT NOT NULL,
    session_id TEXT,
    answers TEXT NOT NULL,
    user_agent TEXT,
    result_type TEXT,
    scores TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (poll_id) REFERENCES polls(id) ON DELETE CASCADE
  );

  CREATE TABLE IF NOT EXISTS short_urls (
    code TEXT PRIMARY KEY,
    target_url TEXT NOT NULL,
    poll_id TEXT,
    clicks INTEGER NOT NULL DEFAULT 0,
    created_by TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS idx_responses_poll ON responses(poll_id);
  CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
`);

// -- Middleware --------------------------------------------------------------
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// -- Helpers -----------------------------------------------------------------
function toBase62(buf) {
  const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  let num = BigInt('0x' + buf.toString('hex'));
  let result = '';
  while (num > 0n) { result = chars[Number(num % 62n)] + result; num = num / 62n; }
  return result || chars[0];
}
function makeShortCode() { return toBase62(crypto.randomBytes(4)).slice(0, 7); }

function parsePoll(row) {
  if (!row) return null;
  return {
    ...row,
    questions: JSON.parse(row.questions),
    settings: JSON.parse(row.settings || '{}'),
    types: row.types ? JSON.parse(row.types) : undefined,
  };
}

// ============================================================================
//  AUTH
// ============================================================================

// Clean expired sessions
db.exec(`DELETE FROM sessions WHERE created_at < datetime('now', '-7 days')`);

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  const session = db.prepare('SELECT * FROM sessions WHERE token = ?').get(token);
  if (!session) return res.status(401).json({ error: 'Invalid or expired session' });

  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(session.user_id);
  if (!user) return res.status(401).json({ error: 'User not found' });

  req.user = user;
  next();
}

function ownerOnly(req, res, next) {
  if (req.user.role !== 'owner') return res.status(403).json({ error: 'Owner permission required' });
  next();
}

app.get('/api/auth/status', (req, res) => {
  const count = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  res.json({ initialized: count > 0, user_count: count });
});

app.post('/api/auth/signup', async (req, res) => {
  const { email, password, name, invite_code } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password are required' });
  if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

  const userCount = db.prepare('SELECT COUNT(*) as c FROM users').get().c;
  const isFirst = userCount === 0;

  if (db.prepare('SELECT id FROM users WHERE email = ?').get(email)) {
    return res.status(409).json({ error: 'Email already registered' });
  }

  if (!isFirst) {
    if (!invite_code) return res.status(403).json({ error: 'Invite code required' });
    const invite = db.prepare('SELECT * FROM invites WHERE code = ? AND used = 0').get(invite_code);
    if (!invite) return res.status(403).json({ error: 'Invalid or expired invite code' });
    db.prepare('UPDATE invites SET used = 1, used_by = ?, used_at = datetime(\'now\') WHERE code = ?').run(email, invite_code);
  }

  const id = uuidv4();
  const hashedPassword = await bcrypt.hash(password, 10);
  const role = isFirst ? 'owner' : 'member';

  db.prepare('INSERT INTO users (id, email, name, password, role) VALUES (?, ?, ?, ?, ?)').run(id, email, name || email.split('@')[0], hashedPassword, role);

  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').run(token, id);

  console.log(`[Auth] New user: ${email} (${role})`);
  res.json({ success: true, token, user: { id, email, name: name || email.split('@')[0], role } });
});

app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) return res.status(400).json({ error: 'email and password are required' });

  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions (token, user_id) VALUES (?, ?)').run(token, user.id);

  console.log(`[Auth] Login: ${email}`);
  res.json({ success: true, token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
});

app.post('/api/auth/logout', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  res.json({ success: true });
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  const { id, email, name, role } = req.user;
  res.json({ id, email, name, role });
});

app.post('/api/auth/invites', authMiddleware, ownerOnly, (req, res) => {
  const code = crypto.randomBytes(6).toString('hex');
  db.prepare('INSERT INTO invites (code, created_by) VALUES (?, ?)').run(code, req.user.id);
  res.json({ success: true, code });
});

app.get('/api/auth/invites', authMiddleware, ownerOnly, (req, res) => {
  res.json(db.prepare('SELECT * FROM invites ORDER BY created_at DESC').all());
});

app.get('/api/auth/members', authMiddleware, (req, res) => {
  res.json(db.prepare('SELECT id, email, name, role, created_at FROM users ORDER BY created_at').all());
});

app.delete('/api/auth/members/:id', authMiddleware, ownerOnly, (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'Cannot remove yourself' });
  db.prepare('DELETE FROM sessions WHERE user_id = ?').run(req.params.id);
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.json({ success: true });
});

// ============================================================================
//  POLL CRUD
// ============================================================================

app.get('/api/polls', (req, res) => {
  const rows = db.prepare('SELECT * FROM polls ORDER BY created_at DESC').all();
  res.json(rows.map(parsePoll));
});

app.get('/api/polls/:id', (req, res) => {
  const poll = parsePoll(db.prepare('SELECT * FROM polls WHERE id = ?').get(req.params.id));
  if (!poll) return res.status(404).json({ error: 'Poll not found' });
  res.json(poll);
});

app.post('/api/polls', authMiddleware, (req, res) => {
  const { title, description, questions, settings, result_mode, types } = req.body;
  if (!title || !questions || !questions.length) return res.status(400).json({ error: 'title and questions are required' });

  const id = uuidv4();
  const s = { steps: questions.length, show_results: true, allow_multiple: false, ...settings };

  db.prepare(`INSERT INTO polls (id, title, description, questions, settings, result_mode, types, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)`).run(
    id, title, description || '', JSON.stringify(questions), JSON.stringify(s),
    result_mode || null, types ? JSON.stringify(types) : null, req.user.id
  );

  const poll = parsePoll(db.prepare('SELECT * FROM polls WHERE id = ?').get(id));
  console.log(`[Poll Created] ${title} (${id}) by ${req.user.email}`);
  res.json({ success: true, poll });
});

app.put('/api/polls/:id', authMiddleware, (req, res) => {
  const existing = db.prepare('SELECT * FROM polls WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Poll not found' });

  const { title, description, questions, settings, status, result_mode, types } = req.body;
  const updates = [];
  const params = [];

  if (title) { updates.push('title = ?'); params.push(title); }
  if (description !== undefined) { updates.push('description = ?'); params.push(description); }
  if (questions) { updates.push('questions = ?'); params.push(JSON.stringify(questions)); }
  if (settings) {
    const merged = { ...JSON.parse(existing.settings || '{}'), ...settings };
    if (questions) merged.steps = questions.length;
    updates.push('settings = ?'); params.push(JSON.stringify(merged));
  }
  if (status) { updates.push('status = ?'); params.push(status); }
  if (result_mode !== undefined) { updates.push('result_mode = ?'); params.push(result_mode); }
  if (types !== undefined) { updates.push('types = ?'); params.push(types ? JSON.stringify(types) : null); }

  updates.push("updated_at = datetime('now')");
  params.push(req.params.id);

  db.prepare(`UPDATE polls SET ${updates.join(', ')} WHERE id = ?`).run(...params);
  res.json({ success: true, poll: parsePoll(db.prepare('SELECT * FROM polls WHERE id = ?').get(req.params.id)) });
});

app.delete('/api/polls/:id', authMiddleware, (req, res) => {
  const result = db.prepare('DELETE FROM polls WHERE id = ?').run(req.params.id);
  if (!result.changes) return res.status(404).json({ error: 'Poll not found' });
  res.json({ success: true });
});

// ============================================================================
//  POLL RESPONSES (public)
// ============================================================================

app.post('/api/polls/:id/responses', (req, res) => {
  const poll = db.prepare('SELECT id FROM polls WHERE id = ?').get(req.params.id);
  if (!poll) return res.status(404).json({ error: 'Poll not found' });

  const { answers, session_id, result_type, scores } = req.body;
  const id = uuidv4();

  db.prepare(`INSERT INTO responses (id, poll_id, session_id, answers, user_agent, result_type, scores)
    VALUES (?, ?, ?, ?, ?, ?, ?)`).run(
    id, req.params.id, session_id || uuidv4(), JSON.stringify(answers),
    req.headers['user-agent'] || null, result_type || null, scores ? JSON.stringify(scores) : null
  );

  db.prepare('UPDATE polls SET response_count = response_count + 1 WHERE id = ?').run(req.params.id);
  res.json({ success: true, id });
});

app.get('/api/polls/:id/responses', (req, res) => {
  const poll = parsePoll(db.prepare('SELECT * FROM polls WHERE id = ?').get(req.params.id));
  if (!poll) return res.status(404).json({ error: 'Poll not found' });

  const rows = db.prepare('SELECT * FROM responses WHERE poll_id = ? ORDER BY created_at DESC').all(req.params.id);

  const aggregated = {};
  poll.questions.forEach((q, qi) => {
    aggregated[qi] = {};
    q.options.forEach((opt, oi) => { aggregated[qi][oi] = 0; });
  });

  rows.forEach(r => {
    const ans = JSON.parse(r.answers);
    Object.entries(ans).forEach(([qIdx, optIdx]) => {
      if (aggregated[qIdx]) aggregated[qIdx][optIdx] = (aggregated[qIdx][optIdx] || 0) + 1;
    });
  });

  res.json({
    poll_id: req.params.id,
    total_responses: rows.length,
    aggregated,
    latest: rows.slice(0, 20).map(r => ({ ...r, answers: JSON.parse(r.answers) })),
  });
});

// ============================================================================
//  LEGACY: Quiz results (backward compat for index.html)
// ============================================================================

app.post('/api/results', (req, res) => {
  const { session_id, result_type, scores, answers } = req.body;
  if (!result_type || !scores || !answers) return res.status(400).json({ error: 'result_type, scores, answers are required' });

  const id = uuidv4();
  db.prepare(`INSERT INTO responses (id, poll_id, session_id, answers, user_agent, result_type, scores)
    VALUES (?, ?, ?, ?, ?, ?, ?)`).run(
    id, 'legacy-quiz', session_id || uuidv4(), JSON.stringify(answers),
    req.headers['user-agent'] || null, result_type, JSON.stringify(scores)
  );

  res.json({ success: true, id, result_type });
});

app.get('/api/results', (req, res) => {
  const rows = db.prepare("SELECT * FROM responses WHERE result_type IS NOT NULL AND poll_id = 'legacy-quiz' ORDER BY created_at DESC LIMIT 100").all();
  const byType = {};
  rows.forEach(r => { byType[r.result_type] = (byType[r.result_type] || 0) + 1; });
  res.json({ total: rows.length, by_type: byType, latest: rows.slice(0, 10).map(r => ({ ...r, answers: JSON.parse(r.answers), scores: r.scores ? JSON.parse(r.scores) : null })) });
});

app.get('/api/results/:id', (req, res) => {
  const row = db.prepare('SELECT * FROM responses WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'Not found' });
  res.json({ ...row, answers: JSON.parse(row.answers), scores: row.scores ? JSON.parse(row.scores) : null });
});

// ============================================================================
//  AI POLL GENERATION (protected)
// ============================================================================

app.post('/api/ai/generate', authMiddleware, async (req, res) => {
  const { engine, title, description, steps, api_key } = req.body;
  if (!engine || !title || !api_key) return res.status(400).json({ error: 'engine, title, api_key are required' });

  const numSteps = steps || 5;
  const systemPrompt = `You are a poll/quiz creation expert. Generate a poll based on the user's request.
Return ONLY valid JSON with this exact structure:
{
  "title": "poll title",
  "description": "brief description",
  "questions": [
    {
      "text": "question text",
      "options": [
        { "text": "option 1" },
        { "text": "option 2" },
        { "text": "option 3" },
        { "text": "option 4" }
      ]
    }
  ]
}
Generate exactly ${numSteps} questions. Each question must have 2-5 options.
All text should be in Korean unless the user specifies otherwise.`;

  const userPrompt = `제목: ${title}\n${description ? `설명: ${description}` : ''}\n질문 수: ${numSteps}개`;

  try {
    let result;
    if (engine === 'claude') result = await callClaude(api_key, systemPrompt, userPrompt);
    else if (engine === 'gemini') result = await callGemini(api_key, systemPrompt, userPrompt);
    else return res.status(400).json({ error: 'Unsupported engine' });

    const jsonMatch = result.match(/\{[\s\S]*\}/);
    if (!jsonMatch) return res.status(500).json({ error: 'AI did not return valid JSON', raw: result });

    res.json({ success: true, poll: JSON.parse(jsonMatch[0]) });
  } catch (err) {
    console.error('[AI Generate Error]', err.message);
    res.status(500).json({ error: err.message });
  }
});

async function callClaude(apiKey, systemPrompt, userPrompt) {
  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'x-api-key': apiKey, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens: 4096, system: systemPrompt, messages: [{ role: 'user', content: userPrompt }] }),
  });
  if (!resp.ok) throw new Error(`Claude API error (${resp.status}): ${await resp.text()}`);
  return (await resp.json()).content[0].text;
}

async function callGemini(apiKey, systemPrompt, userPrompt) {
  const resp = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ system_instruction: { parts: [{ text: systemPrompt }] }, contents: [{ parts: [{ text: userPrompt }] }], generationConfig: { temperature: 0.8, maxOutputTokens: 4096 } }),
  });
  if (!resp.ok) throw new Error(`Gemini API error (${resp.status}): ${await resp.text()}`);
  return (await resp.json()).candidates[0].content.parts[0].text;
}

// ============================================================================
//  SHORT URL
// ============================================================================

app.post('/api/short-url', authMiddleware, (req, res) => {
  const { target_url, poll_id } = req.body;
  if (!target_url && !poll_id) return res.status(400).json({ error: 'target_url or poll_id required' });

  const code = makeShortCode();
  const targetUrl = target_url || `${BASE_URL}/p/${poll_id}`;

  db.prepare('INSERT INTO short_urls (code, target_url, poll_id, created_by) VALUES (?, ?, ?, ?)').run(code, targetUrl, poll_id || null, req.user.id);
  res.json({ success: true, short_url: `${BASE_URL}/s/${code}`, code });
});

app.get('/api/short-urls', authMiddleware, (req, res) => {
  res.json(db.prepare('SELECT * FROM short_urls ORDER BY created_at DESC').all());
});

app.get('/s/:code', (req, res) => {
  const entry = db.prepare('SELECT * FROM short_urls WHERE code = ?').get(req.params.code);
  if (!entry) return res.status(404).send('Short URL not found');
  db.prepare('UPDATE short_urls SET clicks = clicks + 1 WHERE code = ?').run(req.params.code);
  res.redirect(302, entry.target_url);
});

// ============================================================================
//  RELEASE NOTES (from git log)
// ============================================================================

app.get('/api/releases', (req, res) => {
  try {
    const log = execSync('git log --pretty=format:"%H||%ai||%s" --no-merges -50', { cwd: __dirname, encoding: 'utf-8', timeout: 5000 });
    const commits = log.trim().split('\n').filter(Boolean).map(line => {
      const [hash, date, message] = line.split('||');
      return { hash: hash.slice(0, 7), date: date.slice(0, 10), message };
    });
    const grouped = {};
    commits.forEach(c => { if (!grouped[c.date]) grouped[c.date] = []; grouped[c.date].push(c); });
    res.json(Object.entries(grouped).sort(([a], [b]) => b.localeCompare(a)).map(([date, items], idx) => ({ date, latest: idx === 0, commits: items })));
  } catch { res.status(500).json({ error: 'Failed to read git log' }); }
});

// ============================================================================
//  PAGE ROUTES
// ============================================================================

app.get('/admin', (req, res) => res.sendFile(path.join(__dirname, 'public', 'admin.html')));
app.get('/admin/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/p/:id', (req, res) => res.sendFile(path.join(__dirname, 'public', 'poll.html')));
app.get('/quiz', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'public', 'landing.html')));

// ============================================================================
//  SEED: Developer type quiz
// ============================================================================

function seedDefaultPoll() {
  const existing = db.prepare('SELECT id, result_mode FROM polls WHERE id = ?').get('aline-developer-type-quiz');

  // Force update if old seed without result_mode
  if (existing && existing.result_mode === 'type') return;
  if (existing) db.prepare('DELETE FROM polls WHERE id = ?').run('aline-developer-type-quiz');

  const questions = [
    { text:'새 프로젝트에 투입됐을 때, 가장 먼저 하는 행동은?', options:[
      {text:'바로 코드를 짜기 시작한다. 일단 돌아가게 만들고 보자.', scores:{agility:10,stability:2,contribution:5,adaptability:8,consistency:1}},
      {text:'기존 코드베이스 전체를 꼼꼼히 읽고 구조를 파악한다.', scores:{agility:2,stability:9,contribution:6,adaptability:5,consistency:9}},
      {text:'팀원들에게 히스토리와 아키텍처 결정 이유를 먼저 물어본다.', scores:{agility:4,stability:6,contribution:10,adaptability:6,consistency:7}},
      {text:'문서와 이슈를 뒤져서 어디서부터 기여할 수 있는지 찾는다.', scores:{agility:6,stability:4,contribution:8,adaptability:9,consistency:4}},
    ]},
    { text:'마감이 이틀 남았는데 기능이 아직 반도 안 됐다. 어떻게 반응하나요?', options:[
      {text:'오히려 흥분된다. 압박감이 있어야 집중이 잘 된다.', scores:{agility:10,stability:2,contribution:6,adaptability:7,consistency:2}},
      {text:'냉정하게 스코프를 줄이고 최소한의 동작을 보장한다.', scores:{agility:5,stability:8,contribution:7,adaptability:8,consistency:6}},
      {text:'팀원들에게 현황을 공유하고 도움을 요청하거나 역할을 나눈다.', scores:{agility:4,stability:5,contribution:10,adaptability:6,consistency:5}},
      {text:'당황스럽다. 처음부터 계획대로 했다면 이런 일이 없었을 텐데.', scores:{agility:2,stability:9,contribution:4,adaptability:3,consistency:10}},
    ]},
    { text:'일주일에 내가 커밋을 올리는 패턴은?', options:[
      {text:'매일 조금씩. 항상 일정한 페이스를 유지한다.', scores:{agility:4,stability:8,contribution:7,adaptability:5,consistency:10}},
      {text:'특정 날에 몰아서. 집중하면 하루에 수십 개도 올린다.', scores:{agility:10,stability:3,contribution:7,adaptability:6,consistency:2}},
      {text:'기능 단위로 완성될 때마다 올린다. 중간 단계는 별로 안 올린다.', scores:{agility:3,stability:9,contribution:6,adaptability:4,consistency:7}},
      {text:'다른 사람 PR 리뷰하고 머지하는 게 더 많다.', scores:{agility:3,stability:5,contribution:10,adaptability:5,consistency:6}},
    ]},
    { text:'버그 리포트가 들어왔을 때의 첫 반응은?', options:[
      {text:'원인을 끝까지 파고드는 게 재밌다. 깊이 들어간다.', scores:{agility:5,stability:6,contribution:7,adaptability:7,consistency:5}},
      {text:'일단 임시 패치로 막고, 근본 원인은 나중에 제대로 파본다.', scores:{agility:9,stability:3,contribution:6,adaptability:8,consistency:2}},
      {text:'로그, 재현 경로, 영향 범위를 먼저 파악한다.', scores:{agility:4,stability:9,contribution:7,adaptability:6,consistency:8}},
      {text:'버그가 난 부분을 작성한 사람과 함께 보면서 해결한다.', scores:{agility:3,stability:5,contribution:10,adaptability:5,consistency:5}},
    ]},
    { text:'팀에서 내가 자연스럽게 맡게 되는 역할은?', options:[
      {text:'새로운 기술 스택 도입이나 프로토타입 개발.', scores:{agility:10,stability:2,contribution:5,adaptability:9,consistency:2}},
      {text:'아키텍처 설계와 기술 방향 결정.', scores:{agility:4,stability:8,contribution:9,adaptability:6,consistency:7}},
      {text:'코드 품질 관리와 리팩터링.', scores:{agility:2,stability:10,contribution:7,adaptability:4,consistency:9}},
      {text:'코드 리뷰어 또는 팀의 기술 멘토.', scores:{agility:3,stability:5,contribution:10,adaptability:5,consistency:6}},
    ]},
    { text:'코드 리뷰할 때 가장 신경 쓰는 부분은?', options:[
      {text:'동작하는가? 엣지 케이스는 없는가?', scores:{agility:6,stability:7,contribution:7,adaptability:5,consistency:5}},
      {text:'더 나은 설계 방법은 없는가? 확장성은?', scores:{agility:4,stability:9,contribution:8,adaptability:6,consistency:8}},
      {text:'새로운 접근법이 있는가? 최신 방법론은 활용했는가?', scores:{agility:9,stability:3,contribution:5,adaptability:10,consistency:2}},
      {text:'팀원이 성장할 수 있는 피드백을 줄 수 있는가?', scores:{agility:3,stability:4,contribution:10,adaptability:5,consistency:4}},
    ]},
    { text:'이상적인 나의 하루 개발 루틴은?', options:[
      {text:'오전은 딥워크, 오후는 커뮤니케이션. 패턴이 정해져 있다.', scores:{agility:4,stability:8,contribution:6,adaptability:4,consistency:10}},
      {text:'그날그날 다르다. 재밌는 것 또는 급한 것부터 한다.', scores:{agility:10,stability:2,contribution:5,adaptability:9,consistency:1}},
      {text:'팀 스탠드업 후 우선순위 조율하고 협업에 집중한다.', scores:{agility:4,stability:5,contribution:10,adaptability:6,consistency:6}},
      {text:'이슈/PR 트래킹부터 시작해 안정성을 먼저 확인한다.', scores:{agility:2,stability:9,contribution:7,adaptability:4,consistency:8}},
    ]},
    { text:'3개월 뒤 내 코드를 본다면 어떤 상태이길 바라나요?', options:[
      {text:'그때보다 훨씬 더 나은 방식으로 교체되어 있다. (그게 발전이다)', scores:{agility:9,stability:2,contribution:4,adaptability:10,consistency:2}},
      {text:'그대로 돌아가고 있다. 안정성이 최고다.', scores:{agility:2,stability:10,contribution:5,adaptability:3,consistency:9}},
      {text:'주석과 테스트가 잘 달려있어서 팀원이 이어받기 쉽다.', scores:{agility:3,stability:7,contribution:10,adaptability:5,consistency:7}},
      {text:'새 기술이나 패턴으로 점진적으로 개선되어 있다.', scores:{agility:7,stability:6,contribution:6,adaptability:8,consistency:5}},
    ]},
  ];

  const types = {
    explorer:  { ko:'탐험가', en:'The Explorer', icon:'🧭', color:'#FBBF24', desc:'다양한 기술과 레포지토리를 넘나드는 호기심 넘치는 개발자에요. 새로운 것에 빠르게 적응하고 폭넓은 시야로 문제를 바라봐요.', traits:['높은 민첩성','광범위한 관심사','새로운 시도','실험적 성향'], profile:{agility:88,stability:40,contribution:65,adaptability:90,consistency:35} },
    sprinter:  { ko:'스프린터', en:'The Sprinter', icon:'⚡', color:'#F97316', desc:'짧고 강렬한 집중력으로 빠르게 결과를 만들어내는 개발자에요. 데드라인이 있을 때 진가를 발휘해요.', traits:['빠른 출시 속도','집중력 폭발','마감 강자','단기 목표 지향'], profile:{agility:90,stability:45,contribution:75,adaptability:70,consistency:30} },
    builder:   { ko:'빌더', en:'The Builder', icon:'🏗️', color:'#34D399', desc:'안정적이고 꾸준하게 코드를 쌓아가는 개발자에요. 속도보다 품질, 화려함보다 내구성을 추구하는 타입이에요.', traits:['높은 코드 품질','장기 안정성','꾸준한 기여','체계적 접근'], profile:{agility:47,stability:91,contribution:83,adaptability:65,consistency:78} },
    leader:    { ko:'리더', en:'The Leader', icon:'🎯', color:'#A78BFA', desc:'코드 리뷰, 멘토링, 아키텍처 설계를 통해 팀 전체의 방향을 이끄는 개발자에요.', traits:['코드 리뷰 마스터','팀 기여도 높음','아키텍처 설계','멘토링'], profile:{agility:60,stability:72,contribution:92,adaptability:75,consistency:68} },
    keeper:    { ko:'키퍼', en:'The Keeper', icon:'🛡️', color:'#38BDF8', desc:'기존 시스템을 유지하고 보호하는 데 탁월한 개발자에요. 기술 부채를 묵묵히 갚아나가는 팀의 숨은 영웅이에요.', traits:['유지보수 전문','기술 부채 해소','코드 이해력','시스템 수호'], profile:{agility:40,stability:88,contribution:70,adaptability:60,consistency:85} },
    fixer:     { ko:'픽서', en:'The Fixer', icon:'🔧', color:'#F87171', desc:'버그를 사냥하고 인시던트를 해결하는 것에서 희열을 느끼는 개발자에요. 위기 상황에서 가장 빛나는 타입이에요.', traits:['빠른 디버깅','문제 해결 집착','인시던트 대응','높은 집중력'], profile:{agility:75,stability:55,contribution:68,adaptability:80,consistency:50} },
  };

  db.prepare(`INSERT INTO polls (id, title, description, questions, settings, result_mode, types, created_by, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`).run(
    'aline-developer-type-quiz',
    '나는 어떤 개발자일까? — aline.team',
    '8개의 질문에 솔직하게 답하면 당신의 개발 스타일과 강점을 분석해드려요.',
    JSON.stringify(questions),
    JSON.stringify({ steps: 8, show_results: true, allow_multiple: false }),
    'type',
    JSON.stringify(types),
    'system',
    '2026-01-01T00:00:00.000Z'
  );

  console.log('  [Seed] Developer type quiz poll added');
}

seedDefaultPoll();

// -- Start -------------------------------------------------------------------
app.listen(PORT, () => {
  console.log(`\n  Poll Platform running at http://localhost:${PORT}`);
  console.log(`  Admin  : http://localhost:${PORT}/admin`);
  console.log(`  DB     : SQLite (data/poll.db)`);
  console.log(`  API    : /api/polls | /api/ai/generate | /api/short-url\n`);
});
