# MTProto Proxy Checker

## Overview
Система автоматического поиска и криптографической верификации MTProto прокси для Telegram.
Скрапит прокси с mtpro.xyz, проверяет реальными handshake-ами, отдаёт через веб-интерфейс.

## Architecture

### Files
- `app.py` — FastAPI сервер (uvicorn, порт 8080). Фоновый скрапинг каждые 30 мин. API: GET /api/proxies, GET /api/status, POST /api/check
- `scraper.py` — Ядро. 3-этапный пайплайн: скрапинг → TCP фильтр → криптографическая верификация
- `proxy_url.py` — Парсинг tg://proxy и https://t.me/proxy ссылок, нормализация секретов (hex/base64)
- `static/index.html` — SPA веб-интерфейс (vanilla JS, dark theme)

### Proxy Verification Methods
1. **FakeTLS (ee секреты)** — TLS Client Hello 517 байт с HMAC-SHA256(secret). Прокси верифицирует HMAC, отвечает Server Hello. 100% точность.
2. **Obfuscated2 (dd/plain секреты)** — AES-256-CTR handshake. Init-пакет 64 байта, encrypt_key = SHA256(init[8:40] + secret), шифруем только байты [56:64] с позиции 0 keystream. Прокси расшифровывает, пробрасывает к Telegram DC.
3. **Клиентская проверка (браузер)** — fetch/WebSocket probe из сети пользователя.

### Key Implementation Details
- FakeTLS: `build_client_hello()` строит ровно 517 байт. random = HMAC XOR (zeros[28] + timestamp_le[4]). SNI извлекается из секрета после 16 байт ключа.
- Obfs2: `_build_obfs2_init()` ставит 0xEFEFEFEF (abridged tag) в init[56:60]. Шифратор применяется ТОЛЬКО к [56:64] (не ко всему пакету — keystream offset 0).
- Сортировка: FakeTLS первые (обходят DPI), затем dd/plain, внутри по пингу.
- Base64 секреты (из tg:// ссылок): после декода проверяем первый байт (0xEE=faketls, 0xDD=dd).

## Tech Stack
- Python 3.11, FastAPI, uvicorn, aiohttp
- cryptography (AES-CTR для obfs2 handshake)
- hashlib/hmac (SHA-256 для FakeTLS HMAC)
- asyncio (TCP sockets, TLS)

## Running
```bash
pip install fastapi uvicorn aiohttp cryptography
python app.py
# http://localhost:8080
```

## Dependencies note
- TDLib (tdjson 1.8.62) была исследована но имеет баг в addProxy ("Proxy must be non-empty") — не используется. Вместо неё реализован нативный obfs2 handshake на Python.
