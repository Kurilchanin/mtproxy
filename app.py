#!/usr/bin/env python3
"""
MTProto Proxy Checker — Web Application
Автоматическая проверка прокси 24/7 с российского сервера.
Показывает только рабочие прокси. Отправляет лучшие в CF Worker KV.
"""

import asyncio
import os
import time
from contextlib import asynccontextmanager

import aiohttp
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from scraper import scrape_and_check, stop_tdlib

proxy_store: dict = {
    "proxies": [],
    "last_update": 0,
    "updating": False,
}

# Интервал обновления — 10 минут
UPDATE_INTERVAL = 600

# Cloudflare Worker
CF_WORKER_URL = os.environ.get("CF_WORKER_URL", "")
CF_API_TOKEN = os.environ.get("CF_API_TOKEN", "")

MIN_PING = 50
MAX_PING = 500


async def push_to_cf(proxies: list[dict]):
    """Отправляет отфильтрованные прокси (ping 50-500ms) в CF Worker KV."""
    if not CF_WORKER_URL or not CF_API_TOKEN:
        print("[cf] CF_WORKER_URL или CF_API_TOKEN не заданы — пропускаю отправку")
        return

    # Фильтруем по пингу 50-500ms
    filtered = [
        p for p in proxies
        if MIN_PING <= p.get("latency_ms", -1) <= MAX_PING
    ]
    # Сортируем по пингу
    filtered.sort(key=lambda p: p.get("latency_ms", 9999))

    # Отправляем только нужные поля
    payload = [
        {
            "host": p["host"],
            "port": p["port"],
            "secret": p["secret"],
            "ping": p.get("latency_ms", 0),
            "country": p.get("country", ""),
            "sni": p.get("sni", ""),
        }
        for p in filtered
    ]

    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"{CF_WORKER_URL}/api/proxies",
                json={"proxies": payload},
                headers={"Authorization": f"Bearer {CF_API_TOKEN}"},
                timeout=aiohttp.ClientTimeout(total=10),
            ) as resp:
                result = await resp.json()
                print(f"[cf] Отправлено {len(payload)} прокси (ping {MIN_PING}-{MAX_PING}ms) → {resp.status}: {result}")
    except Exception as e:
        print(f"[cf] Ошибка отправки: {e}")


async def update_proxies():
    """Фоновая задача: скрапинг + серверная проверка 24/7."""
    while True:
        if not proxy_store["updating"]:
            proxy_store["updating"] = True
            try:
                print("[scraper] Обновление списка прокси...")
                t0 = time.time()
                alive = await scrape_and_check()
                if alive:
                    proxy_store["proxies"] = alive
                    proxy_store["last_update"] = time.time()
                    print(f"[scraper] Готово: {len(alive)} alive за {time.time()-t0:.1f}s")
                    # Отправляем в CF Worker
                    await push_to_cf(alive)
                else:
                    print(f"[scraper] Пустой результат — оставляю предыдущий список ({len(proxy_store['proxies'])} прокси)")
            except Exception as e:
                import traceback
                print(f"[scraper] Ошибка (список не затронут, {len(proxy_store['proxies'])} прокси сохранены): {e}")
                traceback.print_exc()
            finally:
                proxy_store["updating"] = False
        await asyncio.sleep(UPDATE_INTERVAL)


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(update_proxies())
    yield
    task.cancel()
    await stop_tdlib()


app = FastAPI(title="MTProto Proxy Checker", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/api/proxies")
async def get_proxies(country: str | None = None):
    proxies = proxy_store["proxies"]
    if country:
        proxies = [p for p in proxies if p.get("country", "").upper() == country.upper()]
    return {
        "count": len(proxies),
        "last_update": proxy_store["last_update"],
        "proxies": proxies,
    }


@app.get("/api/status")
async def status():
    return {
        "total_alive": len(proxy_store["proxies"]),
        "last_update": proxy_store["last_update"],
        "updating": proxy_store["updating"],
    }


@app.get("/", response_class=HTMLResponse)
async def index():
    with open("static/index.html") as f:
        return f.read()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=5234)
