# MTProto Proxy Checker

## Overview
Система автоматического поиска и криптографической верификации FakeTLS MTProto прокси для Telegram.
Скрапит прокси с mtpro.xyz, проверяет реальными TLS handshake-ами 24/7, отдаёт только рабочие через веб-интерфейс.

## Architecture

### Files
- `app.py` — FastAPI сервер (uvicorn, порт 8080). Фоновый скрапинг каждые 30 мин. API: GET /api/proxies, GET /api/status
- `scraper.py` — Ядро. 3-этапный пайплайн: скрапинг → фильтрация FakeTLS → TCP фильтр → HMAC верификация
- `proxy_url.py` — Парсинг tg://proxy и https://t.me/proxy ссылок, нормализация секретов (hex/base64)
- `static/index.html` — SPA веб-интерфейс (vanilla JS, dark theme). Показывает только рабочие прокси.

### Proxy Verification
End-to-end FakeTLS проверка:
1. TLS Client Hello 517 байт с HMAC-SHA256(secret) → Server Hello
2. Obfuscated2 init (AES-256-CTR, intermediate protocol) через TLS Application Data
3. req_pq_multi → Telegram DC2 через прокси
4. resPQ ответ = прокси реально проксирует трафик до серверов Telegram
Только прокси, через которые Telegram реально отвечает, попадают в список.

### Key Implementation Details
- FakeTLS: `build_client_hello()` строит ровно 517 байт. random = HMAC XOR (zeros[28] + timestamp_le[4]). SNI извлекается из секрета после 16 байт ключа.
- dd/plain прокси не поддерживаются — отфильтровываются на этапе парсинга секрета.
- Base64 секреты (из tg:// ссылок): после декода проверяем первый байт (0xEE=faketls).

## Tech Stack
- Python 3.11, FastAPI, uvicorn, aiohttp, cryptography
- hashlib/hmac (SHA-256 для FakeTLS HMAC), AES-256-CTR (obfuscated2 туннель)
- asyncio (TCP sockets, TLS)

## Running
```bash
pip install fastapi uvicorn aiohttp cryptography
python app.py
# http://localhost:8080
```
