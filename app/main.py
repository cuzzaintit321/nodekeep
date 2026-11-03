"""Nodekeep: authenticated, real HTTP(S) availability monitoring operator console.

Single-owner MVP: one worker, SQLite, real checks and incidents; no dummy customers.
Never use this as an unaudited, public multi-tenant monitoring service.
"""
import asyncio
import hmac
import ipaddress
import os
import re
import smtplib
import socket
import sqlite3
import ssl
import time
from contextlib import asynccontextmanager, contextmanager
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parent
DB_FILE = os.environ.get("DATABASE_PATH", "/data/nodekeep.sqlite3")
INTERVAL = max(60, int(os.environ.get("CHECK_INTERVAL_SECONDS", "300")))
FAILURE_THRESHOLD = max(1, int(os.environ.get("FAILURE_THRESHOLD", "2")))
RETENTION_DAYS = max(7, int(os.environ.get("RETENTION_DAYS", "90")))
PLANS = {"essential": 99, "managed": 249, "complete": 499}
security = HTTPBasic(auto_error=False)
_probe_locks: dict[int, asyncio.Lock] = {}


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@contextmanager
def connect():
    connection = sqlite3.connect(DB_FILE, timeout=12)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA busy_timeout=12000")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def init_db():
    Path(DB_FILE).parent.mkdir(parents=True, exist_ok=True)
    with connect() as c:
        c.executescript("""
        PRAGMA journal_mode=WAL;
        CREATE TABLE IF NOT EXISTS clients (
            id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT NOT NULL DEFAULT '',
            industry TEXT NOT NULL DEFAULT '', plan TEXT NOT NULL,
            monthly_quote INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS monitors (
            id INTEGER PRIMARY KEY, client_id INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
            name TEXT NOT NULL, url TEXT NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
            state TEXT NOT NULL DEFAULT 'pending', consecutive_failures INTEGER NOT NULL DEFAULT 0,
            http_code INTEGER, latency_ms INTEGER, cert_days INTEGER, error TEXT,
            last_checked TEXT, created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS checks (
            id INTEGER PRIMARY KEY, monitor_id INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
            state TEXT NOT NULL, http_code INTEGER, latency_ms INTEGER, cert_days INTEGER,
            error TEXT, checked_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS checks_m_date ON checks(monitor_id,checked_at DESC);
        CREATE TABLE IF NOT EXISTS incidents (
            id INTEGER PRIMARY KEY, monitor_id INTEGER NOT NULL REFERENCES monitors(id) ON DELETE CASCADE,
            title TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'open',
            opened_at TEXT NOT NULL, acknowledged_at TEXT, resolved_at TEXT
        );
        CREATE INDEX IF NOT EXISTS incidents_m_state ON incidents(monitor_id,state);
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY, client_id INTEGER, message TEXT NOT NULL,
            kind TEXT NOT NULL, created_at TEXT NOT NULL
        );
        """)


def log_event(c, message, kind="info", client_id=None):
    c.execute("INSERT INTO events(client_id,message,kind,created_at) VALUES(?,?,?,?)",
              (client_id, message[:300], kind, utc()))


def auth(credentials: HTTPBasicCredentials | None = Depends(security)):
    user = os.getenv("ADMIN_USER", "")
    password = os.getenv("ADMIN_PASSWORD", "")
    if not user or len(password) < 16:
        raise HTTPException(503, "Administrator credentials have not been configured")
    if (not credentials or not hmac.compare_digest(credentials.username, user)
            or not hmac.compare_digest(credentials.password, password)):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Administrator login required",
                            headers={"WWW-Authenticate": 'Basic realm="Nodekeep operator"'})
    return credentials.username


async def safe_destination(raw_url):
    """Resolve a public domain, return IP pinned for TLS connection (DNS rebinding resistant).

    No redirects, no literal IPs, no nonstandard ports or credentials. DNS may be
    untrusted; pinning the validated global IP for the actual socket is essential.
    """
    try:
        u = urlsplit(raw_url)
        if (u.scheme not in ("http", "https") or not u.hostname or u.username
                or u.password or u.fragment or any(ord(ch)<32 for ch in raw_url)):
            raise ValueError("Use a public http(s) website URL without credentials or fragments")
        port = u.port or (443 if u.scheme == "https" else 80)
        if (u.scheme == "https" and port != 443) or (u.scheme == "http" and port != 80):
            raise ValueError("Only ports 80 and 443 are supported")
        host = u.hostname.lower().rstrip(".")
        if (len(host) > 253 or not re.fullmatch(r"(?=.{4,253}$)[a-z0-9-]+(?:\.[a-z0-9-]+)+",host)
                or any(not label or label.startswith("-") or label.endswith("-") or len(label)>63 for label in host.split("."))):
            raise ValueError("Enter a valid public domain name")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            pass
        else:
            raise ValueError("IP addresses are not accepted; enter a public domain")
        if host.endswith((".local", ".localhost", ".internal", ".test", ".example", ".invalid")):
            raise ValueError("Use a real public domain")
        addrs = await asyncio.wait_for(asyncio.get_running_loop().getaddrinfo(
            host,port,type=socket.SOCK_STREAM),timeout=5)
        ips = {entry[4][0] for entry in addrs}
        if not ips or any(not ipaddress.ip_address(ip).is_global for ip in ips):
            raise ValueError("Domain resolves to non-public IP addresses")
        chosen = sorted(ips, key=lambda x: (":" in x, x))[0]
        path = u.path or "/"
        if u.query:
            path += "?" + u.query
        if len(path) > 1600:
            raise ValueError("URL is too long")
        return host,chosen,port,path,u.scheme
    except (ValueError, TypeError, OSError, TimeoutError, UnicodeError) as exc:
        raise ValueError(str(exc)) from exc


async def probe(url):
    """Make a real, bounded HTTP/1.1 GET using a TLS hostname and DNS-pinned public IP."""
    start = time.monotonic()
    writer = None
    try:
        host,ip,port,path,scheme = await safe_destination(url)
        context = ssl.create_default_context() if scheme == "https" else None
        reader,writer = await asyncio.wait_for(asyncio.open_connection(
            host=ip,port=port,ssl=context,server_hostname=host if context else None),timeout=8)
        writer.write((f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Nodekeep-monitor/1.0\r\n"
                      "Accept: */*\r\nConnection: close\r\n\r\n").encode("ascii"))
        await asyncio.wait_for(writer.drain(),timeout=5)
        line = await asyncio.wait_for(reader.readline(),timeout=8)
        if len(line)>512:
            raise ValueError("Invalid response line")
        match = re.match(rb"HTTP/1\.[01] (\d{3})\b",line)
        if not match:
            raise ValueError("Invalid HTTP status line")
        code = int(match.group(1))
        cert_days = None
        if context:
            sock = writer.get_extra_info("ssl_object")
            cert = sock.getpeercert() if sock else None
            if cert and cert.get("notAfter"):
                seconds = ssl.cert_time_to_seconds(cert["notAfter"])-time.time()
                cert_days = int(seconds//86400)
        return {"state":"up" if code<400 else "down", "http_code":code,
                "latency_ms":round((time.monotonic()-start)*1000),"cert_days":cert_days,
                "error":None if code<400 else f"HTTP {code}"}
    except Exception as exc:
        # Never log raw internal stack traces or URL credentials; URLs are validated separately.
        return {"state":"down","http_code":None,"latency_ms":None,"cert_days":None,
                "error":f"{type(exc).__name__}: {str(exc)[:100]}"}
    finally:
        if writer:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(),timeout=2)
            except Exception:
                pass


def email_available():
    return bool(os.getenv("SMTP_HOST") and os.getenv("SMTP_FROM") and os.getenv("ALERT_EMAIL"))


def send_alert(subject, content):
    if not email_available():
        return False
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = os.environ["SMTP_FROM"]
    message["To"] = os.environ["ALERT_EMAIL"]
    message.set_content(content)
    hostname=os.environ["SMTP_HOST"]
    port=int(os.getenv("SMTP_PORT","587"))
    if os.getenv("SMTP_SSL","").lower() in ("1","true","yes"):
        server = smtplib.SMTP_SSL(hostname,port,timeout=10)
    else:
        server = smtplib.SMTP(hostname,port,timeout=10)
    try:
        if os.getenv("SMTP_STARTTLS","true").lower() in ("1","true","yes") and not isinstance(server,smtplib.SMTP_SSL):
            server.starttls(context=ssl.create_default_context())
        if os.getenv("SMTP_USER"):
            server.login(os.environ["SMTP_USER"],os.environ.get("SMTP_PASSWORD",""))
        server.send_message(message)
    finally:
        server.quit()
    return True


def notify_background(subject, body):
    try:
        send_alert(subject,body)
    except Exception as exc:
        print("Nodekeep alert delivery error:", type(exc).__name__,flush=True)


def save_check(monitor_id, result):
    notifications=[]
    with connect() as c:
        m=c.execute("SELECT m.*,c.name client_name FROM monitors m JOIN clients c ON c.id=m.client_id WHERE m.id=?",(monitor_id,)).fetchone()
        if not m or not m["enabled"]:
            raise HTTPException(404,"Enabled monitor not found")
        failures=(m["consecutive_failures"]+1) if result["state"]=="down" else 0
        new_state="down" if failures>=FAILURE_THRESHOLD else "degraded" if failures>0 else "up"
        now=utc()
        c.execute("UPDATE monitors SET state=?, consecutive_failures=?, http_code=?,latency_ms=?,cert_days=?,error=?,last_checked=? WHERE id=?",
                  (new_state, failures, result["http_code"], result["latency_ms"], result["cert_days"], result["error"],now,monitor_id))
        c.execute("INSERT INTO checks(monitor_id,state,http_code,latency_ms,cert_days,error,checked_at) VALUES(?,?,?,?,?,?,?)",
                  (monitor_id,new_state,result["http_code"],result["latency_ms"],result["cert_days"],result["error"],now))
        open_incident=c.execute("SELECT * FROM incidents WHERE monitor_id=? AND state!='resolved' ORDER BY id DESC LIMIT 1",(monitor_id,)).fetchone()
        if new_state=="down" and not open_incident:
            c.execute("INSERT INTO incidents(monitor_id,title,state,opened_at) VALUES(?,?,?,?)",
                      (monitor_id,f'{m["name"]}: availability failed',"open",now))
            log_event(c,f'OUTAGE: {m["client_name"]} / {m["name"]}',"alert",m["client_id"])
            notifications.append((f'Nodekeep outage: {m["name"]}',f'Client: {m["client_name"]}\nMonitor: {m["name"]}\nURL: {m["url"]}\nLast error: {result["error"] or "No response"}\nUTC: {now}'))
        elif new_state=="up" and open_incident:
            c.execute("UPDATE incidents SET state='resolved', resolved_at=? WHERE id=?",(now,open_incident["id"]))
            log_event(c,f'RECOVERED: {m["client_name"]} / {m["name"]}',"success",m["client_id"])
            notifications.append((f'Nodekeep recovery: {m["name"]}',f'Client: {m["client_name"]}\nMonitor: {m["name"]}\nService restored at {now} UTC'))
        elif new_state=="degraded" and m["state"]!="degraded":
            log_event(c,f'First failed check: {m["name"]}; waiting for confirmation',"warning",m["client_id"])
        elif new_state=="up" and m["state"] in ("pending","degraded"):
            log_event(c,f'Healthy: {m["name"]} ({result["http_code"]})',"success",m["client_id"])
    return {**result,"state":new_state,"failures":failures,"notifications":notifications}


async def check_one(monitor_id):
    lock=_probe_locks.setdefault(monitor_id,asyncio.Lock())
    async with lock:
        with connect() as c:
            m=c.execute("SELECT id,url,enabled FROM monitors WHERE id=?",(monitor_id,)).fetchone()
        if not m or not m["enabled"]:raise HTTPException(404,"Enabled monitor not found")
        outcome=save_check(monitor_id,await probe(m["url"]))
        for title,body in outcome.pop("notifications"):
            asyncio.create_task(asyncio.to_thread(notify_background,title,body))
        return outcome


async def scheduler():
    await asyncio.sleep(5)
    while True:
        try:
            due_before=(datetime.now(timezone.utc)-timedelta(seconds=INTERVAL)).isoformat(timespec="seconds")
            with connect() as c:
                ids=[x[0] for x in c.execute("SELECT id FROM monitors WHERE enabled=1 AND (last_checked IS NULL OR last_checked<=?)",(due_before,))]
                c.execute("DELETE FROM checks WHERE checked_at < ?",((datetime.now(timezone.utc)-timedelta(days=RETENTION_DAYS)).isoformat(timespec="seconds"),))
                c.execute("DELETE FROM events WHERE created_at < ?",((datetime.now(timezone.utc)-timedelta(days=RETENTION_DAYS)).isoformat(timespec="seconds"),))
            semaphore=asyncio.Semaphore(5)
            async def limited(mid):
                async with semaphore:
                    try:await check_one(mid)
                    except Exception as exc:print(f"Nodekeep monitor {mid} failed: {type(exc).__name__}",flush=True)
            await asyncio.gather(*(limited(mid) for mid in ids))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            print("Nodekeep scheduler error:",type(exc).__name__,flush=True)
        await asyncio.sleep(15)


@asynccontextmanager
async def lifespan(app):
    if not os.getenv("ADMIN_USER") or len(os.getenv("ADMIN_PASSWORD", ""))<16:
        raise RuntimeError("Set ADMIN_USER and a strong ADMIN_PASSWORD of at least 16 characters in .env")
    init_db()
    task=asyncio.create_task(scheduler())
    yield
    task.cancel()
    try:await task
    except asyncio.CancelledError:pass


app=FastAPI(title="Nodekeep Remote Monitoring",lifespan=lifespan,docs_url=None,redoc_url=None,openapi_url=None)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    if request.method in ("POST","PATCH","PUT","DELETE"):
        # Browser CSRF protection: no credentials-bearing cross-origin writes.
        origin=request.headers.get("origin")
        if origin and (urlsplit(origin).netloc != request.headers.get("host") or urlsplit(origin).scheme not in ("http","https")):
            return JSONResponse({"detail":"Cross-origin writes are blocked"},status_code=403)
        if not origin and request.headers.get("sec-fetch-site") == "cross-site":
            return JSONResponse({"detail":"Cross-site writes are blocked"},status_code=403)
    response=await call_next(request)
    response.headers["X-Content-Type-Options"]="nosniff"
    response.headers["X-Frame-Options"]="DENY"
    response.headers["Referrer-Policy"]="no-referrer"
    response.headers["Cache-Control"]="no-store"
    response.headers["Content-Security-Policy"]="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    return response


@app.get("/health")
def health():return {"ok":True,"service":"nodekeep"}


@app.get("/")
def homepage(_=Depends(auth)):
    return FileResponse(ROOT/"static"/"index.html")

@app.get("/static/style.css")
def style(_=Depends(auth)):
    return FileResponse(ROOT/"static"/"style.css",media_type="text/css")

@app.get("/static/app.js")
def js(_=Depends(auth)):
    return FileResponse(ROOT/"static"/"app.js",media_type="text/javascript")


class ClientInput(BaseModel):
    name:str=Field(min_length=2,max_length=100)
    email:str=Field(default="",max_length=160)
    industry:str=Field(default="",max_length=60)
    plan:str=Field(default="essential")
    monthly_quote:int=Field(default=0,ge=0,le=100000)

class MonitorInput(BaseModel):
    client_id:int=Field(gt=0)
    name:str=Field(min_length=2,max_length=100)
    url:str=Field(min_length=10,max_length=1600)
    authorized:bool=Field(description="Operator confirms authorization to monitor this website")


@app.get("/api/bootstrap")
def bootstrap(_=Depends(auth)):
    with connect() as c:
        clients=[dict(x) for x in c.execute("SELECT * FROM clients ORDER BY id DESC")]
        monitors=[dict(x) for x in c.execute("SELECT m.*,c.name client_name FROM monitors m JOIN clients c ON c.id=m.client_id ORDER BY m.id DESC")]
        incidents=[dict(x) for x in c.execute("SELECT i.*,m.name monitor_name,c.name client_name FROM incidents i JOIN monitors m ON m.id=i.monitor_id JOIN clients c ON c.id=m.client_id ORDER BY i.id DESC LIMIT 100")]
        events=[dict(x) for x in c.execute("SELECT * FROM events ORDER BY id DESC LIMIT 35")]
        checks=[dict(x) for x in c.execute("SELECT ch.*,m.name monitor_name FROM checks ch JOIN monitors m ON m.id=ch.monitor_id ORDER BY ch.id DESC LIMIT 200")]
    return {"clients":clients,"monitors":monitors,"incidents":incidents,"events":events,"checks":checks,
            "plans":PLANS,"email_alerts":email_available(),"check_interval_seconds":INTERVAL,
            "failure_threshold":FAILURE_THRESHOLD,"now":utc(),"billing_connected":False}


@app.post("/api/clients",status_code=201)
def create_client(item:ClientInput,_=Depends(auth)):
    if item.plan not in PLANS:raise HTTPException(422,"Unknown plan")
    with connect() as c:
        cur=c.execute("INSERT INTO clients(name,email,industry,plan,monthly_quote,created_at) VALUES (?,?,?,?,?,?)",
                      (item.name.strip(),item.email.strip(),item.industry.strip(),item.plan,item.monthly_quote,utc()))
        log_event(c,f'Client added: {item.name.strip()}',client_id=cur.lastrowid)
        return {"id":cur.lastrowid,"ok":True}


@app.delete("/api/clients/{client_id}")
def delete_client(client_id:int,_=Depends(auth)):
    with connect() as c:
        row=c.execute("SELECT name FROM clients WHERE id=?",(client_id,)).fetchone()
        if not row:raise HTTPException(404,"Client not found")
        c.execute("DELETE FROM clients WHERE id=?",(client_id,))
        log_event(c,f'Client removed: {row["name"]}')
    return {"ok":True}


@app.post("/api/monitors",status_code=201)
async def create_monitor(item:MonitorInput,_=Depends(auth)):
    if not item.authorized:raise HTTPException(422,"Monitoring authorization must be confirmed")
    try:await safe_destination(item.url)
    except ValueError as exc:raise HTTPException(422,str(exc)) from exc
    with connect() as c:
        if not c.execute("SELECT id FROM clients WHERE id=?",(item.client_id,)).fetchone():raise HTTPException(404,"Client not found")
        cur=c.execute("INSERT INTO monitors(client_id,name,url,created_at) VALUES(?,?,?,?)",
                      (item.client_id,item.name.strip(),item.url.strip(),utc()))
        log_event(c,f'Monitor added: {item.name.strip()}',client_id=item.client_id)
    return {"id":cur.lastrowid,"ok":True}


@app.post("/api/monitors/{monitor_id}/check")
async def manual_check(monitor_id:int,_=Depends(auth)):
    with connect() as c:
        mon=c.execute("SELECT last_checked FROM monitors WHERE id=?",(monitor_id,)).fetchone()
    if not mon:raise HTTPException(404,"Monitor not found")
    if mon["last_checked"] and (datetime.now(timezone.utc)-datetime.fromisoformat(mon["last_checked"])).total_seconds()<10:
        raise HTTPException(429,"Please wait ten seconds between checks")
    return {"ok":True,"result":await check_one(monitor_id)}


@app.patch("/api/monitors/{monitor_id}/enabled")
def change_monitor(monitor_id:int,enabled:bool,_=Depends(auth)):
    with connect() as c:
        if not c.execute("SELECT id FROM monitors WHERE id=?",(monitor_id,)).fetchone():raise HTTPException(404,"Monitor not found")
        c.execute("UPDATE monitors SET enabled=? WHERE id=?",(int(enabled),monitor_id))
        log_event(c,f'Monitor {monitor_id}: {"enabled" if enabled else "paused"}')
    return {"ok":True}


@app.delete("/api/monitors/{monitor_id}")
def delete_monitor(monitor_id:int,_=Depends(auth)):
    with connect() as c:
        if not c.execute("SELECT id FROM monitors WHERE id=?",(monitor_id,)).fetchone():raise HTTPException(404,"Monitor not found")
        c.execute("DELETE FROM monitors WHERE id=?",(monitor_id,))
        log_event(c,f'Monitor {monitor_id} removed')
    return {"ok":True}


@app.post("/api/incidents/{incident_id}/ack")
def acknowledge(incident_id:int,_=Depends(auth)):
    with connect() as c:
        row=c.execute("SELECT state FROM incidents WHERE id=?",(incident_id,)).fetchone()
        if not row:raise HTTPException(404,"Incident not found")
        if row["state"]=="resolved":raise HTTPException(422,"Already resolved")
        c.execute("UPDATE incidents SET state='acknowledged', acknowledged_at=? WHERE id=?",(utc(),incident_id))
        log_event(c,f'Incident {incident_id} acknowledged')
    return {"ok":True}


@app.get("/api/report/{client_id}")
def report(client_id:int,_=Depends(auth)):
    with connect() as c:
        client=c.execute("SELECT * FROM clients WHERE id=?",(client_id,)).fetchone()
        if not client:raise HTTPException(404,"Client not found")
        monitors=[dict(x) for x in c.execute("SELECT * FROM monitors WHERE client_id=? ORDER BY id",(client_id,))]
        checks=[dict(x) for x in c.execute("SELECT ch.* FROM checks ch JOIN monitors m ON m.id=ch.monitor_id WHERE m.client_id=? ORDER BY ch.id DESC LIMIT 500",(client_id,))]
        incidents=[dict(x) for x in c.execute("SELECT i.*,m.name monitor_name FROM incidents i JOIN monitors m ON m.id=i.monitor_id WHERE m.client_id=? ORDER BY i.id DESC LIMIT 100",(client_id,))]
    return {"client":dict(client),"monitors":monitors,"checks":checks,"incidents":incidents,
            "generated_at":utc(),"note":"Observed HTTP check samples only; not a validated monthly uptime SLA. Billing is external."}


@app.post("/api/alerts/test")
async def test_email(_=Depends(auth)):
    if not email_available():raise HTTPException(422,"Configure SMTP_HOST, SMTP_FROM and ALERT_EMAIL in .env first")
    try:await asyncio.to_thread(send_alert,"Nodekeep test alert","This is a test email from your Nodekeep monitoring instance.")
    except Exception as exc:raise HTTPException(502,f"SMTP delivery error: {type(exc).__name__}") from exc
    return {"ok":True,"message":"Test email submitted to SMTP server"}
