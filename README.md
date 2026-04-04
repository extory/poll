# Poll Platform

AI 기반 폴(설문) 생성, 관리, 공유 플랫폼  
Claude / Gemini 연동으로 폴을 자동 생성하고, 숏 URL과 소셜 공유를 지원합니다.

---

## 빠른 시작

```bash
npm install
npm start
# http://localhost:4000
```

---

## 주요 기능

- **어드민 대시보드** (`/admin`) — 폴 생성/편집/삭제/통계
- **AI 폴 생성** — Claude 또는 Gemini를 통해 제목+설명만으로 폴 자동 생성
- **폴 뷰어** (`/p/:id`) — 모바일 최적화된 폴 참여 화면
- **숏 URL** (`/s/:code`) — 클릭 추적이 가능한 짧은 링크
- **소셜 공유** — 카카오톡, Twitter/X, Facebook, LinkedIn
- **기존 퀴즈** (`/`) — aline.team 개발자 유형 진단 퀴즈 유지

---

## 프로젝트 구조

```
poll/
├── server.js           # Express API 서버 (CRUD, AI, Short URL)
├── package.json
├── public/
│   ├── index.html      # 기존 개발자 유형 퀴즈
│   ├���─ admin.html      # 어드민 대시보드
│   └── poll.html       # 폴 뷰어 (동적 렌더링)
└── data/
    ├���─ polls.json      # 폴 데이터 (자동 생성)
    ├── results.json    # 응답 데이터
    └── short-urls.json # 숏 URL 매핑
```

---

## API

### Polls

| Method | Endpoint                     | 설명              |
|--------|------------------------------|-------------------|
| GET    | `/api/polls`                 | 전체 폴 목록       |
| POST   | `/api/polls`                 | 새 폴 생성         |
| GET    | `/api/polls/:id`             | 폴 상세 조회        |
| PUT    | `/api/polls/:id`             | 폴 수정            |
| DELETE | `/api/polls/:id`             | 폴 삭제            |
| POST   | `/api/polls/:id/responses`   | 응답 제출           |
| GET    | `/api/polls/:id/responses`   | 응답 통계           |

### AI Generation

| Method | Endpoint           | 설명                          |
|--------|--------------------|-------------------------------|
| POST   | `/api/ai/generate` | Claude/Gemini로 폴 자동 생성    |

```json
{
  "engine": "claude",
  "title": "MZ세대 직장인 번아웃 진단",
  "description": "직장인들의 번아웃 수준을 진단합니다",
  "steps": 5,
  "api_key": "sk-ant-..."
}
```

### Short URL

| Method | Endpoint          | 설명           |
|--------|-------------------|----------------|
| POST   | `/api/short-url`  | 숏 URL 생성     |
| GET    | `/api/short-urls` | 숏 URL 목록     |
| GET    | `/s/:code`        | 리다이렉트       |

### Legacy (기존 퀴즈)

| Method | Endpoint           | 설명 |
|--------|--------------------|------|
| POST   | `/api/results`     | 퀴즈 결과 저장 |
| GET    | `/api/results`     | 전체 요약 |
| GET    | `/api/results/:id` | 단건 조회 |

---

## AI 엔진 설정

어드민 대시보드 → ⚙️ API 설정에서 키를 입력합니다.

- **Claude**: [Anthropic Console](https://console.anthropic.com/)에서 API 키 발급
- **Gemini**: [Google AI Studio](https://aistudio.google.com/)에서 API 키 발급

API 키는 브라우저 로컬스토리지에만 저장됩니다 (서버에 저장하지 않음).

---

## 환경 변수

| 변수       | 기본값                    | 설명              |
|-----------|--------------------------|-------------------|
| `PORT`    | `4000`                   | 서버 포트          |
| `BASE_URL`| `http://localhost:4000`  | 숏 URL 생성 시 기본 도메인 |
