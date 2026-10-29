import os
from dotenv import load_dotenv
load_dotenv()

def required(name: str) -> str:
    value = os.getenv(name, "").strip()
    if not value or value == "replace_me" or value.startswith("replace_with_"):
        raise RuntimeError(f"Set {name} in .env")
    return value

def csv_set(name: str) -> set[str]:
    return {x.strip().lower().rstrip(".") for x in os.getenv(name, "").split(",") if x.strip()}

def admin_ids() -> set[int]:
    return {int(x.strip()) for x in os.getenv("BOT_ADMIN_IDS", "").split(",") if x.strip().isdigit()}
