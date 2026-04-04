"""
Модуль скрапинга и проверки MTProto прокси.

End-to-end FakeTLS проверка:
  1. TLS Client Hello с HMAC-SHA256(secret) → Server Hello
  2. Obfuscated2 init через TLS туннель
  3. req_pq_multi → Telegram DC через прокси
  4. resPQ ответ = прокси реально проксирует трафик до Telegram
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
    """Parse MTProto proxy secret, extract 16-byte key and SNI domain. Only FakeTLS (ee)."""
    if not secret_str:
        return {"type": "unknown", "key": b"", "sni": ""}

    s = secret_str.strip()
    lower = s.lower()

    # Сначала пробуем весь секрет как base64 (tg:// ссылки, и секреты вида eeXXX...
    # где ee — часть base64, а не hex-префикс)
    try:
        b64 = s.replace("-", "+").replace("_", "/")
        b64 += "=" * (-len(b64) % 4)
        raw = base64.b64decode(b64)
        if len(raw) >= 17 and raw[0] == 0xEE:
            key = raw[1:17]
            sni = ""
            if len(raw) > 17:
                sni = raw[17:].decode("ascii", errors="ignore").rstrip("\x00")
            return {"type": "faketls", "key": key, "sni": sni, "raw": raw}
    except Exception:
        pass

    # FakeTLS: ee prefix (hex string)
    if lower.startswith("ee"):
        inner = s[2:]
        result = _parse_inner(inner, "faketls")
        if len(result["key"]) == 16:
            return result

    return {"type": "unknown", "key": b"", "sni": "", "raw": b""}


def _parse_inner(inner: str, ptype: str) -> dict:
    """Extract 16-byte key and optional SNI from inner part of secret."""
    sni = ""

    # Try hex first
    try:
        raw = bytes.fromhex(inner)
        key = raw[:16]
        if len(raw) > 16:
            sni = raw[16:].decode("ascii", errors="ignore").rstrip("\x00")
        return {"type": ptype, "key": key, "sni": sni, "raw": b"\xee" + raw}
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
        return {"type": ptype, "key": key, "sni": sni, "raw": b"\xee" + raw}
    except Exception:
        pass

    return {"type": ptype, "key": b"", "sni": "", "raw": b""}


# ===================== FakeTLS Client Hello =====================

def build_client_hello(secret_raw: bytes, sni_domain: str) -> bytes:
    """
    Строит TLS Client Hello ровно 517 байт — как в mtprotoproxy.
    secret_raw: полный секрет (ee + key + sni) — используется как HMAC ключ.
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
    digest = hmac_mod.new(secret_raw, bytes(msg), hashlib.sha256).digest()

    # random = digest XOR (zeros[28] + timestamp_le[4])
    timestamp = struct.pack("<I", int(time.time()))
    xor_pad = b"\x00" * 28 + timestamp

    fake_random = bytes(d ^ x for d, x in zip(digest, xor_pad))
    msg[11:43] = fake_random

    return bytes(msg)


# ===================== Obfuscated2 + MTProto helpers =====================

MTPROTO_DC2 = 2  # Telegram DC2 (149.154.167.51)


def _tls_appdata(payload: bytes) -> bytes:
    """Оборачивает payload в TLS Application Data record."""
    return b"\x17\x03\x03" + struct.pack("!H", len(payload)) + payload


def _parse_tls_appdata(data: bytes) -> bytes:
    """Извлекает payload из TLS Application Data records."""
    payload = b""
    pos = 0
    while pos + 5 <= len(data):
        rec_type = data[pos]
        rec_len = struct.unpack("!H", data[pos + 3 : pos + 5])[0]
        if rec_type == 0x17:  # Application Data
            end = min(pos + 5 + rec_len, len(data))
            payload += data[pos + 5 : end]
        pos += 5 + rec_len
    return payload


async def _read_tls_handshake(reader, timeout: float, max_bytes: int = 32768) -> bytes:
    """Вычитывает полный TLS handshake response (все records полностью)."""
    buf = bytearray()
    while len(buf) < max_bytes:
        chunk = await asyncio.wait_for(reader.read(8192), timeout=timeout)
        if not chunk:
            break
        buf.extend(chunk)
        # Проверяем: все TLS records полностью вычитаны?
        pos = 0
        while pos + 5 <= len(buf):
            rec_len = struct.unpack("!H", buf[pos + 3 : pos + 5])[0]
            pos += 5 + rec_len
        if pos == len(buf) and pos > 0:
            break  # все records ровно вычитаны
    return bytes(buf)


def _build_obfuscated2_init(dc_idx: int = MTPROTO_DC2) -> bytearray:
    """Генерирует 64-байтный obfuscated2 init header."""
    while True:
        init = bytearray(os.urandom(64))
        if init[0] == 0xEF:
            continue
        first4 = bytes(init[:4])
        if first4 in (b"\xee\xee\xee\xee", b"\xdd\xdd\xdd\xdd",
                       b"POST", b"GET ", b"HEAD", b"OPTI"):
            continue
        if init[4:8] == b"\x00\x00\x00\x00":
            continue
        break
    # Intermediate protocol tag
    init[56:60] = b"\xee\xee\xee\xee"
    # DC index (signed int16 LE)
    struct.pack_into("<h", init, 60, dc_idx)
    init[62:64] = b"\x00\x00"
    return init


def _build_req_pq_multi() -> bytes:
    """Строит unencrypted req_pq_multi — первый MTProto запрос."""
    nonce = os.urandom(16)
    msg_id = int(time.time() * (1 << 32))
    msg_id -= msg_id % 4
    return (
        b"\x00" * 8                          # auth_key_id = 0
        + struct.pack("<q", msg_id)           # message_id
        + struct.pack("<i", 20)               # message_data_length
        + struct.pack("<I", 0xBE7E8EF1)      # req_pq_multi constructor
        + nonce                               # 16-byte nonce
    )


# ===================== Deep FakeTLS check =====================

async def check_faketls(host: str, port: int, secret_raw: bytes, secret_16: bytes, sni: str) -> tuple[bool, str]:
    """
    End-to-end FakeTLS проверка:
    1. TLS ClientHello с HMAC(secret) → ServerHello
    2. Obfuscated2 init через TLS Application Data
    3. req_pq_multi → Telegram DC через прокси
    4. resPQ ответ = прокси реально работает

    secret_raw: полный секрет (ee + key + sni bytes) — используется как HMAC ключ
    secret_16: 16-байт ключ — используется для obfuscated2
    """
    if len(secret_16) != 16:
        return False, f"bad_secret(len={len(secret_16)})"

    reader, writer = await asyncio.wait_for(
        asyncio.open_connection(host, port),
        timeout=FAKETLS_TIMEOUT,
    )

    try:
        # --- Step 1: FakeTLS handshake ---
        hello = build_client_hello(secret_raw, sni)
        writer.write(hello)
        await writer.drain()

        hs_resp = await _read_tls_handshake(reader, timeout=FAKETLS_TIMEOUT)

        if not hs_resp or len(hs_resp) < 6:
            return False, "empty_response"
        if hs_resp[0] == 0x15:
            return False, "tls_alert"
        if hs_resp[0] != 0x16 or hs_resp[1] != 0x03:
            return False, f"bad_tls(0x{hs_resp[0]:02x})"

        # --- Step 2: Client CCS (прокси пропустит его) ---
        writer.write(b"\x14\x03\x03\x00\x01\x01")
        await writer.drain()

        # --- Step 3: Obfuscated2 init ---
        init = _build_obfuscated2_init()

        # Ключ шифрования (client → proxy)
        # obfuscated2 использует 16-byte key для key derivation
        enc_key = hashlib.sha256(bytes(init[8:40]) + secret_16).digest()
        enc_iv = bytes(init[40:56])

        # Ключ дешифрования (proxy → client): reversed prekey+iv
        rev = bytes(init[8:56])[::-1]
        dec_key = hashlib.sha256(rev[:32] + secret_16).digest()
        dec_iv = rev[32:]

        enc_cipher = Cipher(algorithms.AES(enc_key), modes.CTR(enc_iv)).encryptor()
        dec_cipher = Cipher(algorithms.AES(dec_key), modes.CTR(dec_iv)).decryptor()

        # Шифруем init: байты 0-55 остаются, 56+ шифруются
        # (но весь блок прогоняем через cipher для сдвига состояния на 64 байта)
        enc_full = enc_cipher.update(bytes(init))
        send_init = bytes(init[:56]) + enc_full[56:]

        writer.write(_tls_appdata(send_init))
        await writer.drain()

        # --- Step 4: req_pq_multi через прокси ---
        req_pq = _build_req_pq_multi()
        # Intermediate transport frame: [4 bytes length LE] [payload]
        frame = struct.pack("<I", len(req_pq)) + req_pq
        enc_frame = enc_cipher.update(frame)

        writer.write(_tls_appdata(enc_frame))
        await writer.drain()

        # --- Step 5: Читаем ответ от Telegram через прокси ---
        # Читаем в цикле: первый read может вернуть CCS/Finished от хэндшейка,
        # а Application Data придёт следующим TCP-сегментом.
        buf = bytearray()
        deadline = asyncio.get_event_loop().time() + FAKETLS_TIMEOUT
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                break
            try:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=remaining)
            except asyncio.TimeoutError:
                break
            if not chunk:
                break
            buf.extend(chunk)
            # Проверяем: достаточно ли Application Data для MTProto ответа
            # resPQ в intermediate transport: минимум ~60 байт
            app_payload = _parse_tls_appdata(bytes(buf))
            if len(app_payload) >= 60:
                break

        if not buf:
            return False, "no_relay_response"

        app_payload = _parse_tls_appdata(bytes(buf))
        if not app_payload:
            # Логируем что пришло вместо Application Data
            rec_types = []
            pos = 0
            while pos + 5 <= len(buf):
                rec_types.append(f"0x{buf[pos]:02x}")
                rec_len = struct.unpack("!H", buf[pos + 3 : pos + 5])[0]
                pos += 5 + rec_len
            return False, f"no_appdata(got={','.join(rec_types)},len={len(buf)})"

        decrypted = dec_cipher.update(app_payload)

        # Intermediate frame: [4 bytes length LE] [MTProto message]
        # MTProto: auth_key_id(8) + message_id(8) + msg_data_len(4) + constructor(4)
        if len(decrypted) >= 28:
            constructor = struct.unpack("<I", decrypted[24:28])[0]
            if constructor == 0x05162463:  # resPQ
                return True, "mtproto_ok"
            return False, f"bad_mtproto(0x{constructor:08x},dec_len={len(decrypted)})"

        return False, f"bad_mtproto_response(dec_len={len(decrypted)},hex={decrypted[:28].hex()})"

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
            ok, method = await check_faketls(
                host, port, parsed["raw"], parsed["key"], parsed["sni"]
            )
            proxy["status"] = "alive" if ok else "dead"
            proxy["check_method"] = method
            if "bad_secret" in method:
                print(f"[scraper] bad_secret: host={host} secret={secret[:40]}... key_len={len(parsed['key'])}")
        except Exception as e:
            proxy["status"] = "dead"
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
    print(f"[scraper] Глубокая проверка: FakeTLS → HMAC + MTProto end-to-end...")
    results = await asyncio.gather(
        *(check_one(p, check_sem) for p in candidates)
    )

    alive = [p for p in results if p["status"] == "alive"]

    from collections import Counter
    methods = Counter(p.get("check_method", "?") for p in results)
    print(f"[scraper] Результат: {len(alive)} alive / {len(results)} проверено")
    print(f"[scraper] Методы: {dict(methods)}")
    return alive
