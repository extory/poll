# Aline.team 개발자 유형 진단 퀴즈

모바일 중심 개발자 유형 진단 웹앱 + Express API 서버  
결과를 JSON으로 저장하며, MySQL 마이그레이션 가능한 구조로 설계되어 있습니다.

---

## 빠른 시작

```bash
npm install
npm start
# http://localhost:3000
```

---

## 프로젝트 구조

```
aline-quiz/
├── server.js          # Express API 서버
├── package.json
├── public/
│   └── index.html     # 퀴즈 SPA (모바일 최적화)
└── data/
    └── results.json   # 저장된 결과 (자동 생성)
```

---

## API

| Method | Endpoint           | 설명 |
|--------|--------------------|------|
| POST   | `/api/results`     | 결과 저장 |
| GET    | `/api/results`     | 전체 요약 + 최근 10건 |
| GET    | `/api/results/:id` | 단건 조회 |

### POST `/api/results` payload

```json
{
  "session_id":  "uuid-v4",
  "result_type": "builder",
  "scores": {
    "agility":      47,
    "stability":    91,
    "contribution": 83,
    "adaptability": 65,
    "consistency":  78
  },
  "answers": {
    "q1": "B",
    "q2": "B",
    "q3": "C",
    "q4": "C",
    "q5": "C",
    "q6": "B",
    "q7": "A",
    "q8": "B"
  }
}
```

---

## MySQL 마이그레이션

### 1. DDL

```sql
CREATE TABLE quiz_results (
  id                 VARCHAR(36)          NOT NULL PRIMARY KEY,
  session_id         VARCHAR(36)          NOT NULL,
  result_type        VARCHAR(20)          NOT NULL,
  score_agility      TINYINT UNSIGNED     NOT NULL,
  score_stability    TINYINT UNSIGNED     NOT NULL,
  score_contribution TINYINT UNSIGNED     NOT NULL,
  score_adaptability TINYINT UNSIGNED     NOT NULL,
  score_consistency  TINYINT UNSIGNED     NOT NULL,
  answers            JSON                 NOT NULL,
  user_agent         TEXT,
  created_at         DATETIME             NOT NULL DEFAULT CURRENT_TIMESTAMP,
  INDEX idx_result_type (result_type),
  INDEX idx_created_at  (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

### 2. JSON → MySQL 마이그레이션 스크립트

```js
// migrate.js
const fs    = require('fs');
const mysql = require('mysql2/promise');

async function migrate() {
  const conn = await mysql.createConnection({
    host: 'localhost', user: 'root', password: '', database: 'aline'
  });

  const data = JSON.parse(fs.readFileSync('./data/results.json', 'utf-8'));

  for (const r of data) {
    await conn.execute(
      `INSERT IGNORE INTO quiz_results
       (id, session_id, result_type,
        score_agility, score_stability, score_contribution,
        score_adaptability, score_consistency,
        answers, user_agent, created_at)
       VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
      [
        r.id, r.session_id, r.result_type,
        r.score_agility, r.score_stability, r.score_contribution,
        r.score_adaptability, r.score_consistency,
        JSON.stringify(r.answers), r.user_agent,
        new Date(r.created_at)
      ]
    );
  }

  console.log(`✅ ${data.length}건 마이그레이션 완료`);
  await conn.end();
}

migrate().catch(console.error);
```

```bash
npm install mysql2
node migrate.js
```

### 3. 유용한 쿼리 예시

```sql
-- 유형별 집계
SELECT result_type, COUNT(*) AS cnt,
       AVG(score_agility) AS avg_agility
FROM quiz_results
GROUP BY result_type ORDER BY cnt DESC;

-- 일별 응답 수
SELECT DATE(created_at) AS day, COUNT(*) AS cnt
FROM quiz_results GROUP BY day ORDER BY day DESC;
```

---

## 개발자 유형 스코어링 기준

| 유형 | Agility | Stability | Contribution | Adaptability | Consistency |
|------|---------|-----------|--------------|--------------|-------------|
| Explorer  | ★★★★★ | ★★      | ★★★        | ★★★★★      | ★★         |
| Sprinter  | ★★★★★ | ★★★     | ★★★★       | ★★★★       | ★★         |
| Builder   | ★★★   | ★★★★★   | ★★★★★      | ★★★        | ★★★★       |
| Leader    | ★★★   | ★★★★    | ★★★★★      | ★★★★       | ★★★        |
| Keeper    | ★★    | ★★★★★   | ★★★★       | ★★★        | ★★★★★      |
| Fixer     | ★★★★  | ★★★     | ★★★★       | ★★★★       | ★★★        |

코사인 유사도(Cosine Similarity)로 사용자 점수와 각 유형 프로파일을 매칭합니다.
