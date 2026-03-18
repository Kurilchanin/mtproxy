"""
Парсинг и нормализация MTProto proxy ссылок.

Поддерживаемые форматы:
  - tg://proxy?server=...&port=...&secret=...
  - https://t.me/proxy?server=...&port=...&secret=...
  - Сырые параметры: server:port:secret
"""

import base64
import re
from urllib.parse import parse_qs


def parse_proxy_url(url: str) -> dict:
    """
    Парсит proxy-ссылку в dict с полями server, port, secret.

    Поддерживает:
      - tg://proxy?server=X&port=Y&secret=Z
      - https://t.me/proxy?server=X&port=Y&secret=Z
      - X:Y:Z (server:port:secret)

    Raises ValueError при невалидном формате.
    """
    url = url.strip()

    # tg://proxy?...
    tg_match = re.match(r"^tg://proxy\?(.+)$", url, re.IGNORECASE)
    if tg_match:
        return _parse_query(tg_match.group(1))

    # https://t.me/proxy?...
    web_match = re.match(r"^https?://(www\.)?t\.me/proxy\?(.+)$", url, re.IGNORECASE)
    if web_match:
        return _parse_query(web_match.group(2))

    # server:port:secret
    parts = url.split(":")
    if len(parts) == 3:
        server, port_str, secret = parts
        port = _validate_port(port_str)
        if not server:
            raise ValueError("Empty server address")
        if not secret:
            raise ValueError("Empty secret")
        return {"server": server, "port": port, "secret": secret}

    raise ValueError(
        "Invalid proxy URL format. Expected: "
        "tg://proxy?server=...&port=...&secret=... or "
        "https://t.me/proxy?server=...&port=...&secret=..."
    )


def _parse_query(query_string: str) -> dict:
    """Парсит query string прокси-ссылки."""
    params = parse_qs(query_string, keep_blank_values=False)

    server = params.get("server", [None])[0]
    port_str = params.get("port", [None])[0]
    secret = params.get("secret", [None])[0]

    if not server:
        raise ValueError("Missing 'server' parameter")
    if not port_str:
        raise ValueError("Missing 'port' parameter")
    if not secret:
        raise ValueError("Missing 'secret' parameter")

    port = _validate_port(port_str)
    return {"server": server, "port": port, "secret": secret}


def _validate_port(port_str: str) -> int:
    """Валидация порта."""
    try:
        port = int(port_str)
    except ValueError:
        raise ValueError(f"Invalid port: {port_str}")
    if port < 1 or port > 65535:
        raise ValueError(f"Port out of range: {port}")
    return port


def normalize_secret(secret: str) -> str:
    """
    Нормализует secret в lowercase hex строку.
    Принимает hex и URL-safe base64 форматы.
    """
    s = secret.strip()

    # Проверяем hex
    if re.fullmatch(r"[0-9a-fA-F]+", s):
        if len(s) % 2 != 0:
            raise ValueError("Odd-length hex secret")
        return s.lower()

    # URL-safe base64
    b64 = s.replace("-", "+").replace("_", "/")
    b64 += "=" * (-len(b64) % 4)
    try:
        raw = base64.b64decode(b64)
        return raw.hex()
    except Exception:
        raise ValueError(f"Cannot decode secret: not hex and not base64")


def build_proxy_url(server: str, port: int, secret: str) -> str:
    """Генерирует tg://proxy ссылку."""
    return f"tg://proxy?server={server}&port={port}&secret={secret}"


def build_web_url(server: str, port: int, secret: str) -> str:
    """Генерирует https://t.me/proxy ссылку."""
    return f"https://t.me/proxy?server={server}&port={port}&secret={secret}"
