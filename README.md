# AG Security Bot

Python Discord security toolkit: public IP/DNS lookup, HTTPS header checks for allowlisted domains, admin-only audit command, hashed license keys, PostgreSQL logs, and a protected FastAPI dashboard.

## Requirements
- Python 3.11+
- PostgreSQL
- Discord application/bot

## Windows setup
1. Create PostgreSQL database and user:
   ```sql
   CREATE USER agbot WITH PASSWORD 'use-a-long-random-password';
   CREATE DATABASE agsecurity OWNER agbot;
   ```
2. Copy `.env.example` to `.env`, then set your bot token, database URL, Discord admin user ID, dashboard token (32+ random characters), and domains you are authorized to test.
3. Install:
   ```powershell
   py -3.11 -m venv .venv
   .\.venv\Scripts\Activate.ps1
   pip install -r requirements.txt
   ```
4. Create a license:
   ```powershell
   python scripts/create_license.py --label primary
   ```
   Copy the printed key to `BOT_LICENSE_KEY` in `.env`. The key is shown only once.
5. Start the bot:
   ```powershell
   python bot.py
   ```
6. Start dashboard in another terminal:
   ```powershell
   uvicorn dashboard:app --host 127.0.0.1 --port 8000
   ```
   `/health` is public. For `/`, `/events`, and `/licenses`, send `Authorization: Bearer <DASHBOARD_TOKEN>`. Keep the dashboard bound to localhost unless you add HTTPS, reverse proxy, and network access controls.

## Discord Developer Portal
1. Create an application at https://discord.com/developers/applications.
2. Under **Bot**, create the bot and copy its token into `.env`. Never publish it.
3. Under **OAuth2 → URL Generator**, select `bot` and `applications.commands`.
4. Invite it to your own test server. Grant only necessary permissions; slash-command tools do not require Administrator.
5. Enable Developer Mode in Discord, right-click your profile, choose **Copy User ID**, and set it in `BOT_ADMIN_IDS`.
6. Start the bot; global slash commands may take a short time to appear.

## Commands
- `/ping` — latency and license status
- `/ipcheck <ip>` — public IP location/ISP lookup via ipwho.is
- `/domain <domain>` — public A, AAAA, MX, NS, TXT records
- `/headers <url>` — HTTPS header check for allowlisted domains only
- `/hash <text>` — SHA-256 digest; do not enter passwords/secrets
- `/license_status` — license status
- `/securitylog [limit]` — recent events; restricted to `BOT_ADMIN_IDS`

## Safety notes
The IP lookup only accepts global IP addresses. Header checks require HTTPS, an explicit domain allowlist, block non-public resolved addresses, and do not follow redirects. License keys are stored as hashes. Do not commit `.env`. The dashboard has read-only license listing; revocation should be added as an authenticated admin-only action before production deployment. This starter does not include credential theft, password cracking, unauthorized exploitation, or stealth monitoring.
