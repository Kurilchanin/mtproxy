"""
Модуль скрапинга и проверки MTProto прокси.

Три метода проверки:
  1. FakeTLS (ee) → TLS Client Hello с HMAC-SHA256(secret).
     Прокси верифицирует HMAC — если отвечает Server Hello, значит принял наш secret.
  2. dd/plain → MTProto obfuscated2 handshake с AES-CTR(secret).
     Отправляем настоящий init-пакет → прокси расшифровывает → пробрасывает к DC Telegram.
  3. Быстрый TCP фильтр на первом этапе отсеивает мёртвые порты.
"""

import asyncio
import base64
import hashlib
import hmac as hmac_mod
import os
import struct
import time

import aiohttp
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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
    """Parse MTProto proxy secret, extract type, 16-byte key, and SNI domain."""
    if not secret_str:
        return {"type": "plain", "key": b"", "sni": ""}

    s = secret_str.strip()
    lower = s.lower()

    # FakeTLS: ee prefix (hex string)
    if lower.startswith("ee"):
        inner = s[2:]
        return _parse_inner(inner, "faketls")

    # Obfuscated2: dd prefix (hex string)
    if lower.startswith("dd"):
        inner = s[2:]
        return _parse_inner(inner, "dd")

    # Может быть base64-encoded секрет с типом внутри (ee/dd в первом байте)
    # Такие секреты приходят из tg://proxy ссылок
    try:
        b64 = s.replace("-", "+").replace("_", "/")
        b64 += "=" * (-len(b64) % 4)
        raw = base64.b64decode(b64)
        if len(raw) >= 17:  # 1 byte type + 16 bytes key minimum
            detected = _detect_type_from_bytes(raw)
            if detected in ("faketls", "dd"):
                key = raw[1:17]
                sni = ""
                if len(raw) > 17:
                    sni = raw[17:].decode("ascii", errors="ignore").rstrip("\x00")
                return {"type": detected, "key": key, "sni": sni}
    except Exception:
        pass

    # No prefix → plain obfuscated
    return _parse_inner(s, "plain")


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


def _detect_type_from_bytes(raw: bytes) -> str:
    """Определяет тип прокси по первому байту декодированного секрета."""
    if len(raw) > 0:
        if raw[0] == 0xEE:
            return "faketls"
        if raw[0] == 0xDD:
            return "dd"
    return "plain"


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
    5. Если прокси форвардит на реальный домен или закрывает → секрет неверный или прокси мёртв
    """
    if len(secret_16) != 16:
        return False, 0, "bad_secret"

    t0 = time.time()
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port),
        timeout=FAKETLS_TIMEOUT,
    )

    try:
        # Отправляем Client Hello
        hello = build_client_hello(secret_16, sni)
        writer.write(hello)
        await writer.drain()

        # Читаем ответ — ждём TLS Server Hello
        response = await asyncio.wait_for(reader.read(4096), timeout=FAKETLS_TIMEOUT)
        latency = (time.time() - t0) * 1000

        if not response:
            return False, latency, "empty_response"

        # TLS record: type=0x16 (Handshake), version=0x03 0x03 (TLS 1.2)
        # Server Hello: handshake type = 0x02
        if (len(response) >= 6
                and response[0] == 0x16       # Handshake record
                and response[1] == 0x03       # TLS major version
                and response[5] == 0x02):     # Server Hello
            return True, latency, "faketls_ok"

        # Некоторые прокси отвечают TLS 1.0/1.1
        if (len(response) >= 6
                and response[0] == 0x16
                and response[1] == 0x03):
            return True, latency, "faketls_ok_compat"

        # Alert record (0x15) — прокси отклонил (неверный HMAC → форвард на домен)
        if response[0] == 0x15:
            return False, latency, "tls_alert"

        # HTTP response — это не MTProxy, а обычный веб-сервер
        if response[:4] in (b"HTTP", b"GET ", b"POST"):
            return False, latency, "http_not_proxy"

        return False, latency, f"unknown_resp(0x{response[0]:02x})"

    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


# ===================== Obfuscated2 handshake (dd/plain) =====================

OBFS2_TIMEOUT = 10

# Запрещённые первые 4 байта init-пакета (не должны совпадать с другими протоколами)
_FORBIDDEN_FIRST = {0x44414548, 0x54534F50, 0x20544547, 0x4954504F, 0x02010316, 0xDDDDDDDD, 0xEEEEEEEE}


def _build_obfs2_init(secret_16: bytes) -> tuple[bytes, object, object]:
    """
    Строит 64-байтный obfuscated2 init-пакет.

    Протокол (из исходников mtprotoproxy + Telegram Android):
      1. Генерируем 64 случайных байта
      2. init[56:60] = 0xEFEFEFEF (abridged protocol tag)
      3. Derive ключи:
         encrypt_key = SHA256(init[8:40] + secret)
         encrypt_iv  = init[40:56]
         decrypt_key = SHA256(reversed(init[8:40]) + secret)
         decrypt_iv  = reversed(init[40:56])
      4. Шифруем init[56:64] с AES-CTR(encrypt_key, encrypt_iv)
      5. Заменяем init[56:64] зашифрованной версией

    Returns: (init_packet, encrypt_cipher, decrypt_cipher)
    """
    while True:
        init = bytearray(os.urandom(64))

        # Первые 4 байта не должны совпадать с другими протоколами
        first4 = struct.unpack("<I", init[:4])[0]
        if first4 in _FORBIDDEN_FIRST:
            continue
        # Вторые 4 байта не должны быть 0x00000000
        if init[4:8] == b"\x00\x00\x00\x00":
            continue
        break

    # Protocol tag: 0xEFEFEFEF = abridged (как делает Telegram клиент)
    init[56:60] = b"\xef\xef\xef\xef"

    # Derive encryption keys (client → proxy)
    enc_key_data = bytes(init[8:40]) + secret_16
    enc_key = hashlib.sha256(enc_key_data).digest()
    enc_iv = bytes(init[40:56])

    # Derive decryption keys (proxy → client) — обратный порядок
    dec_key_data = bytes(reversed(init[8:40])) + secret_16
    dec_key = hashlib.sha256(dec_key_data).digest()
    dec_iv = bytes(reversed(init[40:56]))

    # Создаём AES-CTR шифратор и дешифратор
    enc_cipher = Cipher(algorithms.AES(enc_key), modes.CTR(enc_iv)).encryptor()
    dec_cipher = Cipher(algorithms.AES(dec_key), modes.CTR(dec_iv)).decryptor()

    # Шифруем ТОЛЬКО байты [56:64] — keystream с позиции 0
    # (сервер делает то же: создаёт cipher и сразу дешифрует [56:64])
    encrypted_tail = enc_cipher.update(bytes(init[56:64]))
    init[56:64] = encrypted_tail

    # Для дальнейшей отправки данных через прокси нужен НОВЫЙ шифратор,
    # т.к. текущий enc_cipher уже использовал 8 байт keystream.
    # Но для проверки достаточно только init-пакета.

    return bytes(init), enc_cipher, dec_cipher


async def check_obfuscated2(host: str, port: int, secret_16: bytes) -> tuple[bool, float, str]:
    """
    Obfuscated2 handshake — настоящая проверка как в Telegram клиенте.

    1. TCP connect
    2. Отправляем 64-байтный init-пакет (зашифрованный AES-CTR с секретом)
    3. Прокси расшифровывает → видит DC ID → пробрасывает к Telegram DC
    4. DC отвечает → прокси пересылает нам → мы дешифруем
    5. Если получили данные от DC — прокси 100% рабочий с этим секретом
    """
    if len(secret_16) != 16:
        return False, 0, "bad_secret"

    t0 = time.time()

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port),
        timeout=OBFS2_TIMEOUT,
    )
    latency = (time.time() - t0) * 1000

    try:
        # Строим и отправляем init
        init_packet, enc_cipher, dec_cipher = _build_obfs2_init(secret_16)
        writer.write(init_packet)
        await writer.drain()

        # Ждём ответ от прокси (который пришёл от Telegram DC)
        response = await asyncio.wait_for(reader.read(4096), timeout=OBFS2_TIMEOUT)

        if not response:
            return False, latency, "empty_response"

        # Расшифровываем ответ
        decrypted = dec_cipher.update(response)

        # Telegram DC отвечает пакетом MTProto.
        # Первые 4 байта = длина, затем данные.
        # Если длина выглядит разумно (< 1MB, кратна 4) — это MTProto ответ.
        if len(decrypted) >= 4:
            pkt_len = struct.unpack("<I", decrypted[:4])[0]
            if 8 <= pkt_len <= 1_000_000 and pkt_len % 4 == 0:
                return True, latency, "obfs2_ok"
            # Не MTProto формат, но данные пришли — возможно прокси работает
            # но DC ответил ошибкой или это другой формат
            if len(decrypted) >= 8:
                return True, latency, "obfs2_data"

        # Получили данные но не MTProto — подозрительно
        return False, latency, f"obfs2_bad_resp({len(response)}b)"

    except asyncio.TimeoutError:
        # Прокси не ответил — либо секрет неверный (прокси дропнул),
        # либо прокси не смог связаться с DC
        return False, latency, "obfs2_timeout"
    except (ConnectionResetError, BrokenPipeError, ConnectionError):
        # Прокси закрыл соединение — секрет неверный или прокси сломан
        return False, latency, "obfs2_reset"
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
    """Быстрая проверка — порт открыт и ведёт себя как прокси."""
    host, port = proxy["host"], proxy["port"]
    async with sem:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=QUICK_TIMEOUT,
            )
            # Для non-FakeTLS: проверяем тишину
            parsed = parse_secret(proxy.get("secret", ""))
            if parsed["type"] != "faketls":
                try:
                    data = await asyncio.wait_for(reader.read(64), timeout=1.5)
                    writer.close()
                    await writer.wait_closed()
                    return not data  # баннер = не прокси
                except asyncio.TimeoutError:
                    pass

            writer.close()
            await writer.wait_closed()
            return True
        except Exception:
            return False


# ===================== Fetch =====================

async def fetch_proxies() -> list[dict]:
    async with aiohttp.ClientSession() as session:
        async with session.get(API_URL, headers=HEADERS) as resp:
            if resp.status != 200:
                return []
            data = await resp.json()
            return data if isinstance(data, list) else []


# ===================== Main check pipeline =====================

async def check_one(proxy: dict, sem: asyncio.Semaphore) -> dict:
    """Проверяет один прокси подходящим методом."""
    host = proxy["host"]
    port = proxy["port"]
    secret = proxy.get("secret", "")
    parsed = parse_secret(secret)
    proxy["proxy_type"] = parsed["type"]
    proxy["sni"] = parsed.get("sni", "")

    async with sem:
        try:
            if parsed["type"] == "faketls":
                ok, latency, method = await check_faketls(
                    host, port, parsed["key"], parsed["sni"]
                )
            else:
                ok, latency, method = await check_obfuscated2(host, port, parsed["key"])

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
      2. Быстрый TCP фильтр (отсеиваем мёртвые порты)
      3. Глубокая проверка:
         - FakeTLS → TLS Client Hello с HMAC (проверка секрета)
         - dd/plain → Telethon connect (реальный MTProto handshake с TG)
    """
    proxies = await fetch_proxies()
    if not proxies:
        return []
    print(f"[scraper] Получено {len(proxies)} прокси с API")

    # Быстрый фильтр
    quick_sem = asyncio.Semaphore(MAX_CONCURRENT_QUICK)
    quick_results = await asyncio.gather(
        *(quick_filter(p, quick_sem) for p in proxies)
    )
    candidates = [p for p, ok in zip(proxies, quick_results) if ok]
    print(f"[scraper] TCP фильтр: {len(candidates)} / {len(proxies)} прошли")

    # Глубокая проверка
    check_sem = asyncio.Semaphore(MAX_CONCURRENT_CHECK)
    print(f"[scraper] Глубокая проверка: FakeTLS→HMAC handshake, dd/plain→obfs2 handshake...")
    results = await asyncio.gather(
        *(check_one(p, check_sem) for p in candidates)
    )

    alive = [p for p in results if p["status"] == "alive"]
    # FakeTLS первые (надёжнее, обходят DPI), внутри по пингу
    type_priority = {"faketls": 0, "dd": 1, "plain": 2}
    alive.sort(key=lambda p: (type_priority.get(p.get("proxy_type"), 9), p.get("latency_ms", 9999)))

    from collections import Counter
    methods = Counter(p.get("check_method", "?") for p in results)
    print(f"[scraper] Результат: {len(alive)} alive / {len(results)} проверено")
    print(f"[scraper] Методы: {dict(methods)}")
    return alive


async def check_single_proxy(server: str, port: int, secret: str) -> dict:
    """
    Проверка одного прокси по параметрам.
    Используется для ручной проверки через API.
    Возвращает подробный результат с диагностикой.
    """
    from proxy_url import build_proxy_url

    proxy = {"host": server, "port": port, "secret": secret}
    parsed = parse_secret(secret)
    result = {
        "server": server,
        "port": port,
        "proxy_type": parsed["type"],
        "sni": parsed.get("sni", ""),
        "tg_link": build_proxy_url(server, port, secret),
    }

    # Быстрый TCP фильтр
    quick_sem = asyncio.Semaphore(1)
    tcp_ok = await quick_filter(proxy, quick_sem)
    result["tcp_open"] = tcp_ok

    if not tcp_ok:
        result["status"] = "dead"
        result["latency_ms"] = -1
        result["check_method"] = "tcp_closed"
        result["error"] = "CONNECTION_REFUSED: TCP port is closed or unreachable"
        return result

    # Глубокая проверка
    try:
        if parsed["type"] == "faketls":
            ok, latency, method = await check_faketls(
                server, port, parsed["key"], parsed["sni"]
            )
        else:
            ok, latency, method = await check_obfuscated2(server, port, parsed["key"])

        result["status"] = "alive" if ok else "dead"
        result["latency_ms"] = round(latency)
        result["check_method"] = method

        if not ok:
            result["error"] = method
    except Exception as e:
        result["status"] = "dead"
        result["latency_ms"] = -1
        result["check_method"] = f"error:{type(e).__name__}"
        result["error"] = f"{type(e).__name__}: {e}"

    return result
