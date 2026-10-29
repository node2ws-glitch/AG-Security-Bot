import os, asyncio, hashlib, logging
import aiohttp
import discord
from discord import app_commands
from sqlalchemy import select
from dotenv import load_dotenv
from config import required, admin_ids, csv_set
from database import SessionLocal, init_db
from models import License, SecurityEvent
from security import key_digest, parse_public_ip, resolve_domain, validate_authorized_https_url

load_dotenv()
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
log = logging.getLogger("ag-security-bot")
TOKEN = required("DISCORD_BOT_TOKEN")
LICENSE_KEY = required("BOT_LICENSE_KEY")
ADMINS = admin_ids()
AUTHORIZED_DOMAINS = csv_set("AUTHORIZED_TEST_DOMAINS")
client = discord.Client(intents=discord.Intents.default())
tree = app_commands.CommandTree(client)

async def audit(interaction, command, outcome, details=""):
    try:
        async with SessionLocal() as session:
            session.add(SecurityEvent(guild_id=str(interaction.guild_id or "DM"),
                actor_id=str(interaction.user.id), command=command, outcome=outcome, details=details[:1500]))
            await session.commit()
    except Exception:
        log.exception("Audit write failed")

async def license_valid():
    async with SessionLocal() as session:
        result = await session.execute(select(License).where(
            License.key_hash == key_digest(LICENSE_KEY), License.active.is_(True)))
        return result.scalar_one_or_none() is not None

def admin_check(interaction):
    return interaction.user.id in ADMINS

@client.event
async def on_ready():
    await init_db()
    await tree.sync()
    log.info("Logged in as %s", client.user)

@tree.command(name="ping", description="Check bot latency and license")
async def ping(interaction: discord.Interaction):
    ok = await license_valid()
    await interaction.response.send_message(
        f"Pong: {round(client.latency*1000)} ms | License: {'active' if ok else 'inactive'}", ephemeral=True)
    await audit(interaction, "ping", "ok" if ok else "license_inactive")

@tree.command(name="ipcheck", description="Look up a public IP address")
@app_commands.describe(ip="Public IPv4 or IPv6 address")
async def ipcheck(interaction: discord.Interaction, ip: str):
    await interaction.response.defer(ephemeral=True, thinking=True)
    try:
        ip = parse_public_ip(ip)
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(f"https://ipwho.is/{ip}") as response:
                data = await response.json(content_type=None)
        if data.get("success") is False:
            raise ValueError("Lookup provider returned an error.")
        conn = data.get("connection") or {}
        embed = discord.Embed(title="Public IP Lookup", color=discord.Color.blurple())
        for name, value in [("IP", data.get("ip", ip)), ("Country", data.get("country", "Unknown")),
            ("Region", data.get("region", "Unknown")), ("City", data.get("city", "Unknown")),
            ("ISP", conn.get("isp", "Unknown")), ("ASN", conn.get("asn", "Unknown"))]:
            embed.add_field(name=name, value=str(value)[:200], inline=True)
        await interaction.followup.send(embed=embed, ephemeral=True)
        await audit(interaction, "ipcheck", "ok", ip)
    except Exception as exc:
        await interaction.followup.send(f"Lookup failed: {str(exc)[:250]}", ephemeral=True)
        await audit(interaction, "ipcheck", "error", str(exc))

@tree.command(name="domain", description="Look up public DNS records")
@app_commands.describe(domain="Domain name, without a URL or path")
async def domain_cmd(interaction: discord.Interaction, domain: str):
    await interaction.response.defer(ephemeral=True, thinking=True)
    try:
        records = await asyncio.to_thread(resolve_domain, domain)
        lines = [f"**{k}:** " + ", ".join(v) for k, v in records.items() if v]
        embed = discord.Embed(title=f"DNS Lookup: {domain}", description="\n".join(lines)[:4000] or "No common records found.")
        await interaction.followup.send(embed=embed, ephemeral=True)
        await audit(interaction, "domain", "ok", domain)
    except Exception as exc:
        await interaction.followup.send(f"Lookup failed: {str(exc)[:250]}", ephemeral=True)
        await audit(interaction, "domain", "error", str(exc))

@tree.command(name="headers", description="Check HTTPS headers on an authorized domain")
@app_commands.describe(url="HTTPS URL on a domain in AUTHORIZED_TEST_DOMAINS")
async def headers(interaction: discord.Interaction, url: str):
    await interaction.response.defer(ephemeral=True, thinking=True)
    try:
        safe_url = await asyncio.to_thread(validate_authorized_https_url, url, AUTHORIZED_DOMAINS)
        timeout = aiohttp.ClientTimeout(total=8)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.get(safe_url, allow_redirects=False) as response:
                h = response.headers
                checks = ["Strict-Transport-Security", "Content-Security-Policy",
                          "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]
                lines = [f"HTTP status: **{response.status}**"]
                lines += [f"{'✅' if h.get(k) else '⚠️'} **{k}:** {h.get(k, 'Not present')}" for k in checks]
        await interaction.followup.send("\n".join(lines)[:1900], ephemeral=True)
        await audit(interaction, "headers", "ok", safe_url)
    except Exception as exc:
        await interaction.followup.send(f"Check blocked or failed: {str(exc)[:250]}", ephemeral=True)
        await audit(interaction, "headers", "error", str(exc))

@tree.command(name="hash", description="Calculate SHA-256 of text")
@app_commands.describe(text="Text to hash; do not enter passwords or secrets")
async def hash_cmd(interaction: discord.Interaction, text: str):
    result = hashlib.sha256(text.encode()).hexdigest()
    await interaction.response.send_message(f"SHA-256: `{result}`", ephemeral=True)
    await audit(interaction, "hash", "ok", "Input not stored")

@tree.command(name="license_status", description="Check configured bot license")
async def license_status(interaction: discord.Interaction):
    ok = await license_valid()
    await interaction.response.send_message("License active." if ok else "License inactive.", ephemeral=True)
    await audit(interaction, "license_status", "ok" if ok else "license_inactive")

@tree.command(name="securitylog", description="View recent audit events (bot admins only)")
@app_commands.check(admin_check)
@app_commands.describe(limit="Number of events, from 1 to 10")
async def securitylog(interaction: discord.Interaction, limit: app_commands.Range[int, 1, 10] = 5):
    async with SessionLocal() as session:
        result = await session.execute(select(SecurityEvent).order_by(SecurityEvent.created_at.desc()).limit(limit))
        events = result.scalars().all()
    message = "\n".join(f"`{e.created_at:%Y-%m-%d %H:%M} UTC` **{e.command}** — {e.outcome} (user `{e.actor_id}`)"
                         for e in events) or "No events yet."
    await interaction.response.send_message(message[:1900], ephemeral=True)
    await audit(interaction, "securitylog", "ok", f"Viewed {len(events)} events")

@securitylog.error
async def securitylog_error(interaction, error):
    msg = "You are not authorized to use this command." if isinstance(error, app_commands.CheckFailure) else "Command failed."
    if interaction.response.is_done():
        await interaction.followup.send(msg, ephemeral=True)
    else:
        await interaction.response.send_message(msg, ephemeral=True)

async def main():
    await init_db()
    if not await license_valid():
        raise RuntimeError("Invalid/inactive license. Run scripts/create_license.py and set BOT_LICENSE_KEY.")
    await client.start(TOKEN)

if __name__ == "__main__":
    asyncio.run(main())
