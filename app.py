#!/usr/bin/env python3
"""
MTProto Proxy Checker — Web Application
Автоматическая проверка прокси 24/7 с российского сервера.
Показывает только рабочие прокси.
"""

import asyncio
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles

from scraper import scrape_and_check, stop_tdlib

proxy_store: dict = {
    "proxies": [],
    "last_update": 0,
    "updating": False,
}

# Интервал обновления — 30 минут
UPDATE_INTERVAL = 1800


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
    uvicorn.run("app:app", host="0.0.0.0", port=8080, reload=True)
