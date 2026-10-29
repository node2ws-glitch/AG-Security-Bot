import asyncio, secrets, argparse
from database import init_db, SessionLocal
from models import License
from security import key_digest

async def main(label):
    await init_db()
    key = "AG-" + secrets.token_urlsafe(32)
    async with SessionLocal() as session:
        session.add(License(key_hash=key_digest(key), label=label, active=True))
        await session.commit()
    print("Copy this key now; it cannot be recovered from the database:")
    print(key)
    print("Set it as BOT_LICENSE_KEY in .env.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", default="primary")
    args = parser.parse_args()
    asyncio.run(main(args.label))
