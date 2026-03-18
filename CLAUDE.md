# MTProto Proxy Checker

## Overview
Система автоматического поиска и криптографической верификации FakeTLS MTProto прокси для Telegram.
Скрапит прокси с mtpro.xyz, проверяет реальными TLS handshake-ами с российского сервера 24/7, отдаёт только рабочие через веб-интерфейс.

## Architecture

### Files
- `app.py` — FastAPI сервер (uvicorn, порт 8080). Фоновый скрапинг каждые 30 мин. API: GET /api/proxies, GET /api/status
- `scraper.py` — Ядро. 3-этапный пайплайн: скрапинг → фильтрация FakeTLS → TCP фильтр → HMAC верификация
- `proxy_url.py` — Парсинг tg://proxy и https://t.me/proxy ссылок, нормализация секретов (hex/base64)
- `static/index.html` — SPA веб-интерфейс (vanilla JS, dark theme). Показывает только рабочие прокси.

### Proxy Verification
Только **FakeTLS (ee секреты)** — TLS Client Hello 517 байт с HMAC-SHA256(secret). Прокси верифицирует HMAC, отвечает Server Hello. 100% точность. Обходит DPI.

### Key Implementation Details
- FakeTLS: `build_client_hello()` строит ровно 517 байт. random = HMAC XOR (zeros[28] + timestamp_le[4]). SNI извлекается из секрета после 16 байт ключа.
- dd/plain прокси не поддерживаются — отфильтровываются на этапе парсинга секрета.
- Сортировка по пингу.
- Base64 секреты (из tg:// ссылок): после декода проверяем первый байт (0xEE=faketls).

## Tech Stack
- Python 3.11, FastAPI, uvicorn, aiohttp
- hashlib/hmac (SHA-256 для FakeTLS HMAC)
- asyncio (TCP sockets, TLS)

## Running
```bash
pip install fastapi uvicorn aiohttp
python app.py
# http://localhost:8080
```
