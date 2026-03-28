import asyncio
import aiosqlite
import os

DB_FILE = os.path.join(r"C:\Users\user\Desktop\PIL\backend", "pil_identities.db")

async def test_db():
    try:
        async with aiosqlite.connect(DB_FILE) as db:
            await db.execute('SELECT 1')
            print('DB OK')
    except Exception as e:
        print(f'DB ERROR: {e}')

asyncio.run(test_db())
