import asyncio
import os
import aiohttp

async def test():
    url = os.environ.get("CF_WORKER_URL")
    token = os.environ.get("CF_API_TOKEN")
    print(f"URL: {url}")
    print(f"TOKEN: {token}")
    if not url or not token:
        print("ERROR: переменные не заданы!")
        return
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(
                f"{url}/api/fetch-proxies",
                headers={"Authorization": f"Bearer {token}"},
                timeout=aiohttp.ClientTimeout(total=30),
            ) as r:
                print(f"Status: {r.status}")
                text = await r.text()
                print(f"Body (first 300 chars): {text[:300]}")
    except Exception as e:
        print(f"Exception: {type(e).__name__}: {e}")

asyncio.run(test())
