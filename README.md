# Nodekeep — Remote Website Monitoring & Operations

A **working, self-hosted single-operator managed-services application**, not a fictional dashboard. Built with FastAPI, SQLite, a DNS-pinned HTTPS probe, incident management, optional email alerts, and a responsive private admin panel.

### What actually works

- Add and remove **real clients**, service plan labels and quoted monthly fees. No sample data or fabricated revenue.
- Add authorized **public HTTP(S) monitors** on ports 80 and 443; run checks immediately or on a schedule (default five minutes).
- DNS-pinned checks connect only to validated **public IP addresses** and preserve the original TLS hostname, with no redirect following, reducing SSRF and DNS-rebinding exposure. Outbound requests and errors are bounded.
- Automatic incident opening after two consecutive failures (configurable), incident acknowledgement, and automatic closure after recovery.
- Record historical check timestamps, HTTP statuses, latency, TLS expiry days, and events in persistent SQLite storage.
- Email operator on new incidents or recovery when SMTP credentials are configured; send a test alert from the dashboard.
- Generate a printable report using actual observed checks.
- Basic Auth operator login and optional private SSH tunnel, not publicly exposed by default.
- Backup script using SQLite's online backup API.

**Limits:** This is an operational MVP for one trusted owner, **not** a production-hardened multi-tenant MSP/SaaS service, full RMM platform, payment gateway, or security product. No client agents, patch management, backup verification, 24/7 escalation, self-service customer accounts, real invoicing, SLA guarantees, or multi-region synthetic checks. Do not promise those features to customers. HTTP checks alone do not prove whole-app health. Run behind an SSH tunnel or independently reviewed TLS + access-control gateway. Use independently hosted probes for sites hosted behind your home Spectrum router to avoid NAT loopback false failures. Third-party domain owners must authorize your checks.

## Install on `yeet` (without touching Reboot Syndicate)

```bash
# Extract package into your server home directory, then:
cd ~/nodekeep
cp .env.example .env
# Set a new random password. This command substitutes only the placeholder:
python3 - <<'PY'
from pathlib import Path
import secrets
p=Path('.env')
p.write_text(p.read_text().replace('REPLACE_WITH_A_LONG_RANDOM_PASSWORD', secrets.token_urlsafe(36)))
print('New random admin password stored in .env; use a local text editor to view it privately.')
PY
chmod 600 .env
docker compose up -d --build
docker compose ps
```

To read the password **on your own terminal**, run `grep '^ADMIN_PASSWORD=' .env` and do not paste it into chat. The default username is `operator`.

This project uses its own Docker Compose namespace `nodekeep`, volume `nodekeep_nodekeep_data`, and `127.0.0.1:8290`, independent of Reboot Syndicate.

**From Fedora** (in a separate shell): `ssh -N -L 8290:127.0.0.1:8290 yeet`, then open `http://localhost:8290`. Enter your `.env` administrator credentials when the browser prompts.

Do **not** add a Spectrum router port forward to port 8290. HTTP Basic credentials must not traverse unencrypted networks; the SSH tunnel is encrypted.

### Optional SMTP alerts

Set `SMTP_HOST`, `SMTP_FROM`, `ALERT_EMAIL`, and usually `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD` in `.env`; then `docker compose up -d --force-recreate`. Use an app-specific SMTP credential or separate service account. Test using **Operations → Send test alert**. Without SMTP, incidents are still recorded and visible in the dashboard but no external alerts are delivered.

### Commands

```bash
docker compose ps
docker compose logs --tail=100 operator
./scripts/backup.sh  # save a private SQLite backup, excluded from Git
# Stop container without deleting saved data:
docker compose down
```

**Do not run `docker compose down -v`** unless deliberately deleting Nodekeep's client history and monitor data.

### Billing and contracts

Monthly amounts are **quoted service fees**, not money earned. Connect real billing and signed service agreements separately. In particular, monitoring checks do not imply 24/7 remediation or alert response times. Do not store passwords or financial data in client names or URLs.

### Deploying beyond a private operator MVP

Before serving multiple real paying clients, add proper access-control roles, independent cloud-based multi-region checks, a job queue and durable alert retries, observability, automated encrypted offsite backups and restores, security review, audit logs, legal agreements, retention policies, incident procedures and insurance. Run redundant probes outside home infrastructure.

## Tests

With Python 3.11+ and dependencies installed:

```bash
ADMIN_USER=operator ADMIN_PASSWORD=TemporaryTestPassword12345 DATABASE_PATH=/tmp/nodekeep-test.sqlite3 \
  python -m unittest discover -s tests -v
```

## Publish to GitHub

Because GitHub repository creation is not available through the connected GitHub integration, publish using GitHub CLI from your own authenticated machine:

```bash
cd ~/nodekeep
git init -b main
git add .
git commit -m "Launch Nodekeep real remote operations monitoring MVP"
gh repo create nodekeep --private --source=. --remote=origin --push
```

If the name is already taken in your account, use `gh repo create nodekeep-remote-operations --private --source=. --remote=origin --push`. Never commit `.env`. Change `--private` to `--public` only when you intentionally want the code publicly visible. You can also run `./scripts/publish_github.sh` to perform these steps with safety checks.
