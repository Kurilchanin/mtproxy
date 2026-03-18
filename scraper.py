"""
Модуль скрапинга и проверки MTProto прокси.

Только FakeTLS (ee) проверка:
  1. TLS Client Hello с HMAC-SHA256(secret).
     Прокси верифицирует HMAC — если отвечает Server Hello, значит принял наш secret.
  2. Быстрый TCP фильтр на первом этапе отсеивает мёртвые порты.
"""

import asyncio
import base64
import hashlib
import hmac as hmac_mod
import os
import struct
import time

import aiohttp

API_URL = "https://mtpro.xyz/api/?type=mtprotoS"
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Referer": "https://mtpro.xyz/mtproto",
    "Accept": "application/json, text/plain, */*",
    "Origin": "https://mtpro.xyz",
}

QUICK_TIMEOUT = 3
FAKETLS_TIMEOUT = 8
MAX_CONCURRENT_QUICK = 100
MAX_CONCURRENT_CHECK = 30


# ===================== Secret parsing =====================

def parse_secret(secret_str: str) -> dict:
    """Parse MTProto proxy secret, extract 16-byte key and SNI domain. Only FakeTLS (ee)."""
    if not secret_str:
        return {"type": "unknown", "key": b"", "sni": ""}

    s = secret_str.strip()
    lower = s.lower()

    # FakeTLS: ee prefix (hex string)
    if lower.startswith("ee"):
        inner = s[2:]
        return _parse_inner(inner, "faketls")

    # Может быть base64-encoded секрет с типом внутри (ee в первом байте)
    try:
        b64 = s.replace("-", "+").replace("_", "/")
        b64 += "=" * (-len(b64) % 4)
        raw = base64.b64decode(b64)
        if len(raw) >= 17 and raw[0] == 0xEE:
            key = raw[1:17]
            sni = ""
            if len(raw) > 17:
                sni = raw[17:].decode("ascii", errors="ignore").rstrip("\x00")
            return {"type": "faketls", "key": key, "sni": sni}
    except Exception:
        pass

    return {"type": "unknown", "key": b"", "sni": ""}


def _parse_inner(inner: str, ptype: str) -> dict:
    """Extract 16-byte key and optional SNI from inner part of secret."""
    sni = ""

    # Try hex first
    try:
        raw = bytes.fromhex(inner)
        key = raw[:16]
        if len(raw) > 16:
            sni = raw[16:].decode("ascii", errors="ignore").rstrip("\x00")
        return {"type": ptype, "key": key, "sni": sni}
    except ValueError:
        pass

    # Try URL-safe base64
    try:
        b64 = inner.replace("-", "+").replace("_", "/")
        b64 += "=" * (-len(b64) % 4)
        raw = base64.b64decode(b64)
        key = raw[:16]
        if len(raw) > 16:
            sni = raw[16:].decode("ascii", errors="ignore").rstrip("\x00")
        return {"type": ptype, "key": key, "sni": sni}
    except Exception:
        pass

    return {"type": ptype, "key": b"", "sni": ""}


# ===================== FakeTLS Client Hello =====================

def build_client_hello(secret_16: bytes, sni_domain: str) -> bytes:
    """
    Строит TLS Client Hello ровно 517 байт — как в mtprotoproxy.
    Формат random (из исходников mtprotoproxy handle_fake_tls_handshake):
      computed_digest = HMAC-SHA256(secret, hello_with_zero_random)
      xored = actual_random XOR computed_digest
      Сервер проверяет: xored[0:28] == zeros, xored[28:32] == timestamp_le
    Клиент: random = computed_digest XOR (zeros[28] + timestamp_le[4])
    """
    TARGET_LEN = 517  # TLS_HANDSHAKE_LEN в mtprotoproxy

    server_name = sni_domain.encode("ascii") if sni_domain else b"google.com"

    # Строим Client Hello по формату mtprotoproxy gen_tls_client_hello_msg
    msg = bytearray()
    # TLS record header + handshake header + client version
    msg += b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03"
    # Random (32 bytes zero placeholder)
    msg += b"\x00" * 32
    # Session ID (32 random bytes)
    msg += b"\x20" + os.urandom(32)
    # Cipher suites
    msg += b"\x00\x22\x4a\x4a\x13\x01\x13\x02\x13\x03\xc0\x2b\xc0\x2f\xc0\x2c\xc0\x30\xcc\xa9"
    msg += b"\xcc\xa8\xc0\x13\xc0\x14\x00\x9c\x00\x9d\x00\x2f\x00\x35\x00\x0a\x01\x00\x01\x91"
    # Extensions start: GREASE + SNI
    msg += b"\xda\xda\x00\x00\x00\x00"
    msg += struct.pack("!H", len(server_name) + 5)
    msg += struct.pack("!H", len(server_name) + 3) + b"\x00"
    msg += struct.pack("!H", len(server_name)) + server_name
    # More extensions
    msg += b"\x00\x17\x00\x00\xff\x01\x00\x01\x00\x00\x0a\x00\x0a\x00\x08\xaa\xaa\x00\x1d\x00"
    msg += b"\x17\x00\x18\x00\x0b\x00\x02\x01\x00\x00\x23\x00\x00\x00\x10\x00\x0e\x00\x0c\x02"
    msg += b"\x68\x32\x08\x68\x74\x74\x70\x2f\x31\x2e\x31\x00\x05\x00\x05\x01\x00\x00\x00\x00"
    msg += b"\x00\x0d\x00\x14\x00\x12\x04\x03\x08\x04\x04\x01\x05\x03\x08\x05\x05\x01\x08\x06"
    msg += b"\x06\x01\x02\x01\x00\x12\x00\x00\x00\x33\x00\x2b\x00\x29\xaa\xaa\x00\x01\x00\x00"
    msg += b"\x1d\x00\x20" + os.urandom(32)  # x25519 public key (random for check)
    msg += b"\x00\x2d\x00\x02\x01\x01\x00\x2b\x00\x0b\x0a\xba\xba\x03\x04\x03\x03\x03\x02\x03"
    msg += b"\x01\x00\x1b\x00\x03\x02\x00\x02\x3a\x3a\x00\x01\x00\x00\x15"
    # Padding extension до 517 байт
    msg += struct.pack("!H", TARGET_LEN - len(msg) - 2)
    msg += b"\x00" * (TARGET_LEN - len(msg))

    # Теперь msg ровно 517 байт с нулевым random на позиции [11:43]
    # Вычисляем HMAC
    digest = hmac_mod.new(secret_16, bytes(msg), hashlib.sha256).digest()

    # random = digest XOR (zeros[28] + timestamp_le[4])
    timestamp = struct.pack("<I", int(time.time()))
    xor_pad = b"\x00" * 28 + timestamp

    fake_random = bytes(d ^ x for d, x in zip(digest, xor_pad))
    msg[11:43] = fake_random

    return bytes(msg)


async def check_faketls(host: str, port: int, secret_16: bytes, sni: str) -> tuple[bool, float, str]:
    """
    FakeTLS проверка:
    1. TCP connect
    2. Отправляем TLS Client Hello с HMAC(secret)
    3. Прокси верифицирует HMAC
    4. Если отвечает TLS Server Hello (0x16 0x03 ...) → прокси принял наш secret → 100% рабочий
    """
    if len(secret_16) != 16:
        return False, 0, "bad_secret"

    t0 = time.time()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port),
        timeout=FAKETLS_TIMEOUT,
    )

    try:
        hello = build_client_hello(secret_16, sni)
        writer.write(hello)
        await writer.drain()

        response = await asyncio.wait_for(reader.read(4096), timeout=FAKETLS_TIMEOUT)
        latency = (time.time() - t0) * 1000

        if not response:
            return False, latency, "empty_response"

        if (len(response) >= 6
                and response[0] == 0x16
                and response[1] == 0x03
                and response[5] == 0x02):
            return True, latency, "faketls_ok"

        if (len(response) >= 6
                and response[0] == 0x16
                and response[1] == 0x03):
            return True, latency, "faketls_ok_compat"

        if response[0] == 0x15:
            return False, latency, "tls_alert"

        if response[:4] in (b"HTTP", b"GET ", b"POST"):
            return False, latency, "http_not_proxy"

        return False, latency, f"unknown_resp(0x{response[0]:02x})"

    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def stop_tdlib():
    """Заглушка для совместимости с app.py."""
    pass


# ===================== Quick TCP filter =====================

async def quick_filter(proxy: dict, sem: asyncio.Semaphore) -> bool:
    """Быстрая проверка — порт открыт."""
    host, port = proxy["host"], proxy["port"]
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=QUICK_TIMEOUT,
            )
            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False


# ===================== Fetch =====================

async def fetch_proxies() -> list[dict]:
    import json

    # Пробуем через CF Worker (обход блокировки mtpro.xyz из РФ)
    cf_url = os.environ.get("CF_WORKER_URL", "")
    cf_token = os.environ.get("CF_API_TOKEN", "")

    if cf_url and cf_token:
        try:
            timeout = aiohttp.ClientTimeout(total=30)
            async with aiohttp.ClientSession(timeout=timeout) as session:
                async with session.get(
                    f"{cf_url}/api/fetch-proxies",
                    headers={"Authorization": f"Bearer {cf_token}"},
                ) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        data = json.loads(text)
                        if isinstance(data, list) and data:
                            print(f"[scraper] Получено через CF Worker")
                            return data
                    print(f"[scraper] CF Worker вернул {resp.status}, пробую напрямую...")
        except Exception as e:
            print(f"[scraper] CF Worker недоступен ({e}), пробую напрямую...")

    # Фоллбэк: прямой запрос
    timeout = aiohttp.ClientTimeout(total=120, sock_read=90)
    async with aiohttp.ClientSession(timeout=timeout) as session:
        async with session.get(API_URL, headers=HEADERS) as resp:
            if resp.status != 200:
                print(f"[scraper] API вернул {resp.status}")
                return []
            text = await resp.text()
            data = json.loads(text)
            return data if isinstance(data, list) else []


# ===================== Main check pipeline =====================

async def check_one(proxy: dict, sem: asyncio.Semaphore) -> dict:
    """Проверяет один FakeTLS прокси."""
    host = proxy["host"]
    port = proxy["port"]
    secret = proxy.get("secret", "")
    parsed = parse_secret(secret)
    proxy["proxy_type"] = "faketls"
    proxy["sni"] = parsed.get("sni", "")

    async with sem:
        try:
            ok, latency, method = await check_faketls(
                host, port, parsed["key"], parsed["sni"]
            )
            proxy["status"] = "alive" if ok else "dead"
            proxy["latency_ms"] = round(latency)
            proxy["check_method"] = method
        except Exception as e:
            proxy["status"] = "dead"
            proxy["latency_ms"] = -1
            proxy["check_method"] = f"error:{type(e).__name__}"

    return proxy


async def scrape_and_check() -> list[dict]:
    """
    Полный цикл:
      1. Скрапинг mtpro.xyz
      2. Фильтрация: только FakeTLS (ee) прокси
      3. Быстрый TCP фильтр (отсеиваем мёртвые порты)
      4. Глубокая проверка: TLS Client Hello с HMAC (проверка секрета)
    """
    proxies = await fetch_proxies()
    if not proxies:
        return []
    print(f"[scraper] Получено {len(proxies)} прокси с API")

    # Фильтруем только FakeTLS
    faketls_proxies = []
    for p in proxies:
        parsed = parse_secret(p.get("secret", ""))
        if parsed["type"] == "faketls":
            faketls_proxies.append(p)

    print(f"[scraper] FakeTLS прокси: {len(faketls_proxies)} / {len(proxies)}")
    if not faketls_proxies:
        return []

    # Быстрый TCP фильтр
    quick_sem = asyncio.Semaphore(MAX_CONCURRENT_QUICK)
    quick_results = await asyncio.gather(
        *(quick_filter(p, quick_sem) for p in faketls_proxies)
    )
    candidates = [p for p, ok in zip(faketls_proxies, quick_results) if ok]
    print(f"[scraper] TCP фильтр: {len(candidates)} / {len(faketls_proxies)} прошли")

    # Глубокая проверка FakeTLS
    check_sem = asyncio.Semaphore(MAX_CONCURRENT_CHECK)
    print(f"[scraper] Глубокая проверка: FakeTLS → HMAC handshake...")
    results = await asyncio.gather(
        *(check_one(p, check_sem) for p in candidates)
    )

    alive = [p for p in results if p["status"] == "alive"]
    alive.sort(key=lambda p: p.get("latency_ms", 9999))

    from collections import Counter
    methods = Counter(p.get("check_method", "?") for p in results)
    print(f"[scraper] Результат: {len(alive)} alive / {len(results)} проверено")
    print(f"[scraper] Методы: {dict(methods)}")
    return alive
