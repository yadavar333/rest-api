# REST API with Authentication

Full auth lifecycle REST API — register, login, refresh token rotation, logout — plus CRUD on a protected posts resource with ownership checks and pagination.

## Stack
Node.js · Express · PostgreSQL · JWT · bcrypt · Joi · morgan · express-rate-limit · pg (raw driver, no ORM)

## Features
- Register / Login with bcrypt password hashing
- JWT access tokens (15 min) + refresh tokens (7 days)
- Refresh token rotation — old token invalidated on every refresh
- Logout invalidates refresh token in DB
- Protected `GET /me` endpoint
- Posts CRUD — create/update/delete restricted to owner
- Paginated `GET /posts`
- Joi validation on all request bodies
- Rate limiting on auth routes (20 req / 15 min per IP)
- Morgan request logging
- Centralised error handler

## Setup

```bash
npm install
cp .env.example .env        # fill in DATABASE_URL and secrets
psql -d your_db -f migrations/001_initial_schema.sql
npm run dev
```

## Endpoints

| Method | Path            | Auth     | Description                  |
|--------|-----------------|----------|------------------------------|
| POST   | /auth/register  | —        | Register new user            |
| POST   | /auth/login     | —        | Login, receive tokens        |
| POST   | /auth/refresh   | —        | Rotate refresh token         |
| POST   | /auth/logout    | —        | Invalidate refresh token     |
| GET    | /me             | Bearer   | Get current user             |
| GET    | /posts          | —        | List posts (paginated)       |
| GET    | /posts/:id      | —        | Get single post              |
| POST   | /posts          | Bearer   | Create post                  |
| PUT    | /posts/:id      | Bearer   | Update post (owner only)     |
| DELETE | /posts/:id      | Bearer   | Delete post (owner only)     |
| GET    | /health         | —        | Health check                 |

## Pagination

```
GET /posts?page=1&limit=10
```

Response includes `pagination.total`, `pagination.totalPages`.

## Token Flow

```
Register / Login  →  accessToken (15m) + refreshToken (7d)
Access expires    →  POST /auth/refresh  →  new pair issued, old refresh invalidated
Done              →  POST /auth/logout   →  refresh token deleted from DB
```
