import asyncio, traceback
from main import generate_identity
async def run():
    try:
        resp = await generate_identity()
        print('SUCCESS:', resp)
    except Exception as e:
        print('EXCEPTION:')
        traceback.print_exc()
asyncio.run(run())
