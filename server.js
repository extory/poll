/**
 * aline-quiz / server.js
 * ──────────────────────
 * Express 서버: 퀴즈 결과를 JSON 파일로 저장
 * MySQL 마이그레이션을 위해 스키마 호환 구조로 설계
 *
 * MySQL DDL (마이그레이션 시 사용):
 * ──────────────────────────────────
 * CREATE TABLE quiz_results (
 *   id            VARCHAR(36)   NOT NULL PRIMARY KEY,
 *   session_id    VARCHAR(36)   NOT NULL,
 *   result_type   VARCHAR(20)   NOT NULL,
 *   score_agility      TINYINT UNSIGNED NOT NULL,
 *   score_stability    TINYINT UNSIGNED NOT NULL,
 *   score_contribution TINYINT UNSIGNED NOT NULL,
 *   score_adaptability TINYINT UNSIGNED NOT NULL,
 *   score_consistency  TINYINT UNSIGNED NOT NULL,
 *   answers       JSON          NOT NULL,
 *   user_agent    TEXT,
 *   created_at    DATETIME      NOT NULL DEFAULT CURRENT_TIMESTAMP,
 *   INDEX idx_result_type (result_type),
 *   INDEX idx_created_at  (created_at)
 * ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
 */

const express  = require('express');
const fs       = require('fs');
const path     = require('path');
const { v4: uuidv4 } = require('uuid');

const app  = express();
const PORT = process.env.PORT || 4000;
const DATA_DIR  = path.join(__dirname, 'data');
const DATA_FILE = path.join(DATA_DIR, 'results.json');

// ── Middleware ─────────────────────────────────────────────
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// CORS (개발 편의)
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

// ── Data helpers ───────────────────────────────────────────
function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
}

function loadResults() {
  ensureDataDir();
  if (!fs.existsSync(DATA_FILE)) return [];
  try {
    return JSON.parse(fs.readFileSync(DATA_FILE, 'utf-8'));
  } catch {
    return [];
  }
}

function saveResults(results) {
  ensureDataDir();
  fs.writeFileSync(DATA_FILE, JSON.stringify(results, null, 2), 'utf-8');
}

// ── POST /api/results ──────────────────────────────────────
app.post('/api/results', (req, res) => {
  const { session_id, result_type, scores, answers } = req.body;

  // Validation
  if (!result_type || !scores || !answers) {
    return res.status(400).json({ error: 'result_type, scores, answers are required' });
  }

  const record = {
    id:                   uuidv4(),
    session_id:           session_id || uuidv4(),
    result_type,                         // 'explorer' | 'sprinter' | 'builder' | 'leader' | 'keeper' | 'fixer'
    score_agility:        scores.agility,
    score_stability:      scores.stability,
    score_contribution:   scores.contribution,
    score_adaptability:   scores.adaptability,
    score_consistency:    scores.consistency,
    answers,                             // { q1: 'a', q2: 'c', ... }
    user_agent:           req.headers['user-agent'] || null,
    created_at:           new Date().toISOString(),
  };

  const results = loadResults();
  results.push(record);
  saveResults(results);

  console.log(`[${record.created_at}] Saved: ${record.result_type} (id: ${record.id})`);
  res.json({ success: true, id: record.id, result_type: record.result_type });
});

// ── GET /api/results ───────────────────────────────────────
app.get('/api/results', (req, res) => {
  const results = loadResults();
  const summary = {
    total: results.length,
    by_type: results.reduce((acc, r) => {
      acc[r.result_type] = (acc[r.result_type] || 0) + 1;
      return acc;
    }, {}),
    latest: results.slice(-10).reverse(),
  };
  res.json(summary);
});

// ── GET /api/results/:id ────────────────────────────────────
app.get('/api/results/:id', (req, res) => {
  const results = loadResults();
  const record  = results.find(r => r.id === req.params.id);
  if (!record) return res.status(404).json({ error: 'Not found' });
  res.json(record);
});

// ── Start ───────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🚀 Aline Quiz Server running at http://localhost:${PORT}`);
  console.log(`   Data file : ${DATA_FILE}`);
  console.log(`   API docs  : POST /api/results  |  GET /api/results\n`);
});
