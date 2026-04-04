/**
 * Poll Platform / server.js
 * ──────────────────────────
 * Express 서버: 인증, 폴 생성/관리, AI 생성, 숏 URL, 결과 저장
 */

const express = require('express');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 4000;
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// -- Data directories -------------------------------------------------------
const DATA_DIR = path.join(__dirname, 'data');
const POLLS_FILE = path.join(DATA_DIR, 'polls.json');
const RESULTS_FILE = path.join(DATA_DIR, 'results.json');
const SHORT_URLS_FILE = path.join(DATA_DIR, 'short-urls.json');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');
const INVITES_FILE = path.join(DATA_DIR, 'invites.json');

// -- Middleware --------------------------------------------------------------
app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// -- Data helpers ------------------------------------------------------------
function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function loadJSON(file) {
  ensureDataDir();
  if (!fs.existsSync(file)) return [];
  try { return JSON.parse(fs.readFileSync(file, 'utf-8')); }
  catch { return []; }
}

function saveJSON(file, data) {
  ensureDataDir();
  fs.writeFileSync(file, JSON.stringify(data, null, 2), 'utf-8');
}

function loadPolls() { return loadJSON(POLLS_FILE); }
function savePolls(d) { saveJSON(POLLS_FILE, d); }
function loadResults() { return loadJSON(RESULTS_FILE); }
function saveResults(d) { saveJSON(RESULTS_FILE, d); }
function loadShortUrls() { return loadJSON(SHORT_URLS_FILE); }
function saveShortUrls(d) { saveJSON(SHORT_URLS_FILE, d); }
function loadUsers() { return loadJSON(USERS_FILE); }
function saveUsers(d) { saveJSON(USERS_FILE, d); }
function loadSessions() { return loadJSON(SESSIONS_FILE); }
function saveSessions(d) { saveJSON(SESSIONS_FILE, d); }
function loadInvites() { return loadJSON(INVITES_FILE); }
function saveInvites(d) { saveJSON(INVITES_FILE, d); }

// -- Short code generator ----------------------------------------------------
function toBase62(buf) {
  const chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
  let num = BigInt('0x' + buf.toString('hex'));
  let result = '';
  while (num > 0n) {
    result = chars[Number(num % 62n)] + result;
    num = num / 62n;
  }
  return result || chars[0];
}

function makeShortCode() {
  return toBase62(crypto.randomBytes(4)).slice(0, 7);
}

// ============================================================================
//  AUTH SYSTEM
// ============================================================================

// Clean expired sessions (older than 7 days)
function cleanSessions() {
  const sessions = loadSessions();
  const cutoff = Date.now() - 7 * 24 * 60 * 60 * 1000;
  const cleaned = sessions.filter(s => new Date(s.created_at).getTime() > cutoff);
  if (cleaned.length !== sessions.length) saveSessions(cleaned);
  return cleaned;
}

// Auth middleware
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Authentication required' });

  const sessions = cleanSessions();
  const session = sessions.find(s => s.token === token);
  if (!session) return res.status(401).json({ error: 'Invalid or expired session' });

  const users = loadUsers();
  const user = users.find(u => u.id === session.user_id);
  if (!user) return res.status(401).json({ error: 'User not found' });

  req.user = user;
  next();
}

// Owner-only middleware
function ownerOnly(req, res, next) {
  if (req.user.role !== 'owner') {
    return res.status(403).json({ error: 'Owner permission required' });
  }
  next();
}

// Check init status
app.get('/api/auth/status', (req, res) => {
  const users = loadUsers();
  res.json({ initialized: users.length > 0, user_count: users.length });
});

// Sign up -- first user = owner, others need invite code
app.post('/api/auth/signup', async (req, res) => {
  const { email, password, name, invite_code } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  const users = loadUsers();
  const isFirst = users.length === 0;

  if (users.find(u => u.email === email)) {
    return res.status(409).json({ error: 'Email already registered' });
  }

  // Non-first user requires invite
  if (!isFirst) {
    if (!invite_code) {
      return res.status(403).json({ error: 'Invite code required' });
    }
    const invites = loadInvites();
    const invite = invites.find(i => i.code === invite_code && !i.used);
    if (!invite) {
      return res.status(403).json({ error: 'Invalid or expired invite code' });
    }
    invite.used = true;
    invite.used_by = email;
    invite.used_at = new Date().toISOString();
    saveInvites(invites);
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = {
    id: uuidv4(),
    email,
    name: name || email.split('@')[0],
    password: hashedPassword,
    role: isFirst ? 'owner' : 'member',
    created_at: new Date().toISOString(),
  };

  users.push(user);
  saveUsers(users);

  // Auto-login
  const token = crypto.randomBytes(32).toString('hex');
  const sessions = loadSessions();
  sessions.push({ token, user_id: user.id, created_at: new Date().toISOString() });
  saveSessions(sessions);

  console.log(`[Auth] New user: ${user.email} (${user.role})`);
  res.json({
    success: true,
    token,
    user: { id: user.id, email: user.email, name: user.name, role: user.role },
  });
});

// Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ error: 'email and password are required' });
  }

  const users = loadUsers();
  const user = users.find(u => u.email === email);
  if (!user) return res.status(401).json({ error: 'Invalid email or password' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

  const token = crypto.randomBytes(32).toString('hex');
  const sessions = loadSessions();
  sessions.push({ token, user_id: user.id, created_at: new Date().toISOString() });
  saveSessions(sessions);

  console.log(`[Auth] Login: ${user.email}`);
  res.json({
    success: true,
    token,
    user: { id: user.id, email: user.email, name: user.name, role: user.role },
  });
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (token) {
    const sessions = loadSessions();
    saveSessions(sessions.filter(s => s.token !== token));
  }
  res.json({ success: true });
});

// Get current user
app.get('/api/auth/me', authMiddleware, (req, res) => {
  const { id, email, name, role } = req.user;
  res.json({ id, email, name, role });
});

// -- Invite system (owner only) ----------------------------------------------

app.post('/api/auth/invites', authMiddleware, ownerOnly, (req, res) => {
  const code = crypto.randomBytes(6).toString('hex');
  const invites = loadInvites();
  invites.push({
    code,
    created_by: req.user.id,
    created_at: new Date().toISOString(),
    used: false,
  });
  saveInvites(invites);
  res.json({ success: true, code });
});

app.get('/api/auth/invites', authMiddleware, ownerOnly, (req, res) => {
  const invites = loadInvites();
  res.json(invites.sort((a, b) => new Date(b.created_at) - new Date(a.created_at)));
});

// List members
app.get('/api/auth/members', authMiddleware, (req, res) => {
  const users = loadUsers();
  res.json(users.map(u => ({
    id: u.id, email: u.email, name: u.name, role: u.role, created_at: u.created_at,
  })));
});

// Remove member (owner only, not self)
app.delete('/api/auth/members/:id', authMiddleware, ownerOnly, (req, res) => {
  if (req.params.id === req.user.id) {
    return res.status(400).json({ error: 'Cannot remove yourself' });
  }
  let users = loadUsers();
  users = users.filter(u => u.id !== req.params.id);
  saveUsers(users);
  let sessions = loadSessions();
  sessions = sessions.filter(s => s.user_id !== req.params.id);
  saveSessions(sessions);
  res.json({ success: true });
});

// ============================================================================
//  POLL CRUD APIs (admin = auth required, read = public)
// ============================================================================

// Public: list & get polls (poll viewer needs these)
app.get('/api/polls', (req, res) => {
  const polls = loadPolls();
  res.json(polls.sort((a, b) => new Date(b.created_at) - new Date(a.created_at)));
});

app.get('/api/polls/:id', (req, res) => {
  const polls = loadPolls();
  const poll = polls.find(p => p.id === req.params.id);
  if (!poll) return res.status(404).json({ error: 'Poll not found' });
  res.json(poll);
});

// Protected: create poll
app.post('/api/polls', authMiddleware, (req, res) => {
  const { title, description, questions, settings } = req.body;
  if (!title || !questions || !questions.length) {
    return res.status(400).json({ error: 'title and questions are required' });
  }

  const poll = {
    id: uuidv4(),
    title,
    description: description || '',
    questions,
    settings: {
      steps: questions.length,
      show_results: settings?.show_results !== false,
      allow_multiple: settings?.allow_multiple || false,
      ...settings,
    },
    status: 'active',
    response_count: 0,
    created_by: req.user.id,
    created_at: new Date().toISOString(),
    updated_at: new Date().toISOString(),
  };

  const polls = loadPolls();
  polls.push(poll);
  savePolls(polls);

  console.log(`[Poll Created] ${poll.title} (${poll.id}) by ${req.user.email}`);
  res.json({ success: true, poll });
});

// Protected: update poll
app.put('/api/polls/:id', authMiddleware, (req, res) => {
  const polls = loadPolls();
  const idx = polls.findIndex(p => p.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'Poll not found' });

  const { title, description, questions, settings, status } = req.body;
  if (title) polls[idx].title = title;
  if (description !== undefined) polls[idx].description = description;
  if (questions) {
    polls[idx].questions = questions;
    polls[idx].settings.steps = questions.length;
  }
  if (settings) polls[idx].settings = { ...polls[idx].settings, ...settings };
  if (status) polls[idx].status = status;
  polls[idx].updated_at = new Date().toISOString();

  savePolls(polls);
  res.json({ success: true, poll: polls[idx] });
});

// Protected: delete poll
app.delete('/api/polls/:id', authMiddleware, (req, res) => {
  let polls = loadPolls();
  const before = polls.length;
  polls = polls.filter(p => p.id !== req.params.id);
  if (polls.length === before) return res.status(404).json({ error: 'Poll not found' });
  savePolls(polls);
  res.json({ success: true });
});

// ============================================================================
//  POLL RESPONSES (public)
// ============================================================================

app.post('/api/polls/:id/responses', (req, res) => {
  const polls = loadPolls();
  const poll = polls.find(p => p.id === req.params.id);
  if (!poll) return res.status(404).json({ error: 'Poll not found' });

  const { answers, session_id } = req.body;
  const record = {
    id: uuidv4(),
    poll_id: req.params.id,
    session_id: session_id || uuidv4(),
    answers,
    user_agent: req.headers['user-agent'] || null,
    created_at: new Date().toISOString(),
  };

  const results = loadResults();
  results.push(record);
  saveResults(results);

  const pidx = polls.findIndex(p => p.id === req.params.id);
  polls[pidx].response_count = (polls[pidx].response_count || 0) + 1;
  savePolls(polls);

  res.json({ success: true, id: record.id });
});

app.get('/api/polls/:id/responses', (req, res) => {
  const results = loadResults().filter(r => r.poll_id === req.params.id);
  const polls = loadPolls();
  const poll = polls.find(p => p.id === req.params.id);
  if (!poll) return res.status(404).json({ error: 'Poll not found' });

  const aggregated = {};
  poll.questions.forEach((q, qi) => {
    aggregated[qi] = {};
    q.options.forEach((opt, oi) => { aggregated[qi][oi] = 0; });
  });

  results.forEach(r => {
    if (r.answers) {
      Object.entries(r.answers).forEach(([qIdx, optIdx]) => {
        if (aggregated[qIdx]) {
          aggregated[qIdx][optIdx] = (aggregated[qIdx][optIdx] || 0) + 1;
        }
      });
    }
  });

  res.json({
    poll_id: req.params.id,
    total_responses: results.length,
    aggregated,
    latest: results.slice(-20).reverse(),
  });
});

// ============================================================================
//  LEGACY: Quiz results
// ============================================================================

app.post('/api/results', (req, res) => {
  const { session_id, result_type, scores, answers } = req.body;
  if (!result_type || !scores || !answers) {
    return res.status(400).json({ error: 'result_type, scores, answers are required' });
  }

  const record = {
    id: uuidv4(),
    session_id: session_id || uuidv4(),
    result_type,
    score_agility: scores.agility,
    score_stability: scores.stability,
    score_contribution: scores.contribution,
    score_adaptability: scores.adaptability,
    score_consistency: scores.consistency,
    answers,
    user_agent: req.headers['user-agent'] || null,
    created_at: new Date().toISOString(),
  };

  const results = loadResults();
  results.push(record);
  saveResults(results);
  res.json({ success: true, id: record.id, result_type: record.result_type });
});

app.get('/api/results', (req, res) => {
  const results = loadResults().filter(r => r.result_type);
  res.json({
    total: results.length,
    by_type: results.reduce((acc, r) => {
      acc[r.result_type] = (acc[r.result_type] || 0) + 1; return acc;
    }, {}),
    latest: results.slice(-10).reverse(),
  });
});

app.get('/api/results/:id', (req, res) => {
  const results = loadResults();
  const record = results.find(r => r.id === req.params.id);
  if (!record) return res.status(404).json({ error: 'Not found' });
  res.json(record);
});

// ============================================================================
//  AI POLL GENERATION (protected)
// ============================================================================

app.post('/api/ai/generate', authMiddleware, async (req, res) => {
  const { engine, title, description, steps, api_key } = req.body;

  if (!engine || !title || !api_key) {
    return res.status(400).json({ error: 'engine, title, api_key are required' });
  }

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
    if (engine === 'claude') {
      result = await callClaude(api_key, systemPrompt, userPrompt);
    } else if (engine === 'gemini') {
      result = await callGemini(api_key, systemPrompt, userPrompt);
    } else {
      return res.status(400).json({ error: 'Unsupported engine. Use "claude" or "gemini".' });
    }

    const jsonMatch = result.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      return res.status(500).json({ error: 'AI did not return valid JSON', raw: result });
    }

    const pollData = JSON.parse(jsonMatch[0]);
    res.json({ success: true, poll: pollData });
  } catch (err) {
    console.error('[AI Generate Error]', err.message);
    res.status(500).json({ error: err.message });
  }
});

async function callClaude(apiKey, systemPrompt, userPrompt) {
  const resp = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'x-api-key': apiKey,
      'anthropic-version': '2023-06-01',
    },
    body: JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: 4096,
      system: systemPrompt,
      messages: [{ role: 'user', content: userPrompt }],
    }),
  });

  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`Claude API error (${resp.status}): ${err}`);
  }
  const data = await resp.json();
  return data.content[0].text;
}

async function callGemini(apiKey, systemPrompt, userPrompt) {
  const resp = await fetch(
    `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        system_instruction: { parts: [{ text: systemPrompt }] },
        contents: [{ parts: [{ text: userPrompt }] }],
        generationConfig: { temperature: 0.8, maxOutputTokens: 4096 },
      }),
    }
  );

  if (!resp.ok) {
    const err = await resp.text();
    throw new Error(`Gemini API error (${resp.status}): ${err}`);
  }
  const data = await resp.json();
  return data.candidates[0].content.parts[0].text;
}

// ============================================================================
//  SHORT URL (protected create, public redirect)
// ============================================================================

app.post('/api/short-url', authMiddleware, (req, res) => {
  const { target_url, poll_id } = req.body;
  if (!target_url && !poll_id) {
    return res.status(400).json({ error: 'target_url or poll_id required' });
  }

  const urls = loadShortUrls();
  const code = makeShortCode();
  const targetUrl = target_url || `${BASE_URL}/p/${poll_id}`;

  urls.push({
    code,
    target_url: targetUrl,
    poll_id: poll_id || null,
    clicks: 0,
    created_by: req.user.id,
    created_at: new Date().toISOString(),
  });
  saveShortUrls(urls);

  res.json({ success: true, short_url: `${BASE_URL}/s/${code}`, code });
});

app.get('/api/short-urls', authMiddleware, (req, res) => {
  const urls = loadShortUrls();
  res.json(urls.sort((a, b) => new Date(b.created_at) - new Date(a.created_at)));
});

// Public redirect
app.get('/s/:code', (req, res) => {
  const urls = loadShortUrls();
  const entry = urls.find(u => u.code === req.params.code);
  if (!entry) return res.status(404).send('Short URL not found');

  entry.clicks = (entry.clicks || 0) + 1;
  saveShortUrls(urls);
  res.redirect(302, entry.target_url);
});

// ============================================================================
//  PAGE ROUTES
// ============================================================================

app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

app.get('/admin/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/p/:id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'poll.html'));
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// ============================================================================
//  SEED: Default developer type quiz poll
// ============================================================================
const SEED_POLL_ID = 'aline-developer-type-quiz';

function seedDefaultPoll() {
  const polls = loadPolls();
  if (polls.find(p => p.id === SEED_POLL_ID)) return;

  const defaultPoll = {
    id: SEED_POLL_ID,
    title: '나는 어떤 개발자일까? — aline.team',
    description: '8개의 질문에 솔직하게 답하면 당신의 개발 스타일과 강점을 분석해드려요. 코사인 유사도 기반 6가지 개발자 유형 진단.',
    questions: [
      {
        text: '새 프로젝트에 투입됐을 때, 가장 먼저 하는 행동은?',
        options: [
          { text: '바로 코드를 짜기 시작한다. 일단 돌아가게 만들고 보자.' },
          { text: '기존 코드베이스 전체를 꼼꼼히 읽고 구조를 파악한다.' },
          { text: '팀원들에게 히스토리와 아키텍처 결정 이유를 먼저 물어본다.' },
          { text: '문서와 이슈를 뒤져서 어디서부터 기여할 수 있는지 찾는다.' },
        ],
      },
      {
        text: '마감이 이틀 남았는데 기능이 아직 반도 안 됐다. 어떻게 반응하나요?',
        options: [
          { text: '오히려 흥분된다. 압박감이 있어야 집중이 잘 된다.' },
          { text: '냉정하게 스코프를 줄이고 최소한의 동작을 보장한다.' },
          { text: '팀원들에게 현황을 공유하고 도움을 요청하거나 역할을 나눈다.' },
          { text: '당황스럽다. 처음부터 계획대로 했다면 이런 일이 없었을 텐데.' },
        ],
      },
      {
        text: '일주일에 내가 커밋을 올리는 패턴은?',
        options: [
          { text: '매일 조금씩. 항상 일정한 페이스를 유지한다.' },
          { text: '특정 날에 몰아서. 집중하면 하루에 수십 개도 올린다.' },
          { text: '기능 단위로 완성될 때마다 올린다. 중간 단계는 별로 안 올린다.' },
          { text: '다른 사람 PR 리뷰하고 머지하는 게 더 많다.' },
        ],
      },
      {
        text: '버그 리포트가 들어왔을 때의 첫 반응은?',
        options: [
          { text: '원인을 끝까지 파고드는 게 재밌다. 깊이 들어간다.' },
          { text: '일단 임시 패치로 막고, 근본 원인은 나중에 제대로 파본다.' },
          { text: '로그, 재현 경로, 영향 범위를 먼저 파악한다.' },
          { text: '버그가 난 부분을 작성한 사람과 함께 보면서 해결한다.' },
        ],
      },
      {
        text: '팀에서 내가 자연스럽게 맡게 되는 역할은?',
        options: [
          { text: '새로운 기술 스택 도입이나 프로토타입 개발.' },
          { text: '아키텍처 설계와 기술 방향 결정.' },
          { text: '코드 품질 관리와 리팩터링.' },
          { text: '코드 리뷰어 또는 팀의 기술 멘토.' },
        ],
      },
      {
        text: '코드 리뷰할 때 가장 신경 쓰는 부분은?',
        options: [
          { text: '동작하는가? 엣지 케이스는 없는가?' },
          { text: '더 나은 설계 방법은 없는가? 확장성은?' },
          { text: '새로운 접근법이 있는가? 최신 방법론은 활용했는가?' },
          { text: '팀원이 성장할 수 있는 피드백을 줄 수 있는가?' },
        ],
      },
      {
        text: '이상적인 나의 하루 개발 루틴은?',
        options: [
          { text: '오전은 딥워크, 오후는 커뮤니케이션. 패턴이 정해져 있다.' },
          { text: '그날그날 다르다. 재밌는 것 또는 급한 것부터 한다.' },
          { text: '팀 스탠드업 후 우선순위 조율하고 협업에 집중한다.' },
          { text: '이슈/PR 트래킹부터 시작해 안정성을 먼저 확인한다.' },
        ],
      },
      {
        text: '3개월 뒤 내 코드를 본다면 어떤 상태이길 바라나요?',
        options: [
          { text: '그때보다 훨씬 더 나은 방식으로 교체되어 있다. (그게 발전이다)' },
          { text: '그대로 돌아가고 있다. 안정성이 최고다.' },
          { text: '주석과 테스트가 잘 달려있어서 팀원이 이어받기 쉽다.' },
          { text: '새 기술이나 패턴으로 점진적으로 개선되어 있다.' },
        ],
      },
    ],
    settings: {
      steps: 8,
      show_results: true,
      allow_multiple: false,
    },
    status: 'active',
    response_count: 0,
    created_by: 'system',
    created_at: '2026-01-01T00:00:00.000Z',
    updated_at: '2026-01-01T00:00:00.000Z',
  };

  polls.push(defaultPoll);
  savePolls(polls);
  console.log('  [Seed] Default developer type quiz poll added');
}

// -- Start -------------------------------------------------------------------
seedDefaultPoll();

app.listen(PORT, () => {
  console.log(`\n  Poll Platform running at http://localhost:${PORT}`);
  console.log(`  Admin  : http://localhost:${PORT}/admin`);
  console.log(`  Quiz   : http://localhost:${PORT}/`);
  console.log(`  API    : /api/polls | /api/ai/generate | /api/short-url\n`);
});
