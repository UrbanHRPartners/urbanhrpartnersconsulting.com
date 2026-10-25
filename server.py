"""UrbanHRPartners Consulting public site and governed access gateway.

Uses only Python's standard library. Business records stay in UrbanHRPartners;
this service stores website leads, assessments, access/audit data, and an outbox
for governed delivery to CRM/Company360.
"""
from __future__ import annotations

import argparse, getpass, hashlib, hmac, ipaddress, json, mimetypes, os, re, secrets, sqlite3, threading, time
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parent
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
ROLE_SET = {"admin", "consultant", "client", "learner"}
MARKET_SET = {"usa", "colombia", "both", "north-america", "central-america", "south-america", "europe", "asia", "africa", "oceania", "global"}

def now(): return datetime.now(timezone.utc).isoformat()
def password_hash(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 600_000)
    return f"pbkdf2_sha256$600000${salt.hex()}${digest.hex()}"
def password_ok(password: str, stored: str) -> bool:
    try:
        _, rounds, salt, expected = stored.split("$")
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(rounds)).hex()
        return hmac.compare_digest(actual, expected)
    except (ValueError, TypeError): return False

class ClosingSQLiteConnection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()

class Store:
    def __init__(self, path: Path):
        self.path=path; path.parent.mkdir(parents=True, exist_ok=True); self.lock=threading.RLock(); self.init()
    def connect(self):
        db=sqlite3.connect(self.path,timeout=10,factory=ClosingSQLiteConnection); db.row_factory=sqlite3.Row; db.execute("PRAGMA foreign_keys=ON"); db.execute("PRAGMA busy_timeout=10000"); return db
    def init(self):
        schema="""
        CREATE TABLE IF NOT EXISTS tenants(id TEXT PRIMARY KEY,name TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL REFERENCES tenants(id),email TEXT NOT NULL UNIQUE,name TEXT NOT NULL,role TEXT NOT NULL,password_hash TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,mfa_state TEXT NOT NULL DEFAULT 'not_enrolled',created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),csrf_token TEXT NOT NULL,created_at TEXT NOT NULL,expires_at INTEGER NOT NULL,ip_hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit_log(id INTEGER PRIMARY KEY AUTOINCREMENT,created_at TEXT NOT NULL,actor_id TEXT,event TEXT NOT NULL,tenant_id TEXT,subject TEXT NOT NULL,ip_hash TEXT NOT NULL,detail TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS leads(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,name TEXT NOT NULL,company TEXT NOT NULL,email TEXT NOT NULL,market TEXT NOT NULL,need TEXT NOT NULL,consent INTEGER NOT NULL,status TEXT NOT NULL,source TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS assessments(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,language TEXT NOT NULL,answers TEXT NOT NULL,status TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS recruiting_requests(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,company TEXT NOT NULL,contact_name TEXT NOT NULL,email TEXT NOT NULL,role_title TEXT NOT NULL,market TEXT NOT NULL,timeline TEXT NOT NULL,context TEXT NOT NULL,status TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS applications(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,job_id TEXT NOT NULL,name TEXT NOT NULL,email TEXT NOT NULL,phone TEXT NOT NULL,location TEXT NOT NULL,profile_url TEXT NOT NULL,note TEXT NOT NULL,status TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS whatsapp_intents(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,country TEXT NOT NULL,purpose TEXT NOT NULL,message TEXT NOT NULL,language TEXT NOT NULL,status TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS analytics_events(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,visitor_hash TEXT NOT NULL,event TEXT NOT NULL,path TEXT NOT NULL,language TEXT NOT NULL,region TEXT NOT NULL,detail TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS advice_requests(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,visitor_hash TEXT NOT NULL,industry TEXT NOT NULL,region TEXT NOT NULL,need TEXT NOT NULL,language TEXT NOT NULL,service TEXT NOT NULL,answer TEXT NOT NULL,status TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS universal_intakes(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,customer_type TEXT NOT NULL,country TEXT NOT NULL,industry TEXT NOT NULL,need TEXT NOT NULL,complexity TEXT NOT NULL,service_id TEXT NOT NULL,governance TEXT NOT NULL,delivery_model TEXT NOT NULL,route TEXT NOT NULL,status TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS service_requests(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,template_id TEXT NOT NULL,template_version TEXT NOT NULL,service TEXT NOT NULL,name TEXT NOT NULL,company TEXT NOT NULL,email TEXT NOT NULL,country TEXT NOT NULL,answers TEXT NOT NULL,governance TEXT NOT NULL,status TEXT NOT NULL,source TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS integration_outbox(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,kind TEXT NOT NULL,source_id TEXT NOT NULL,destination TEXT NOT NULL,status TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,last_error TEXT);
        CREATE TABLE IF NOT EXISTS password_reset_tokens(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),expires_at INTEGER NOT NULL,used_at TEXT);
        CREATE TABLE IF NOT EXISTS anonymous_csrf(visitor_hash TEXT PRIMARY KEY,token TEXT NOT NULL,expires_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS rate_events(id TEXT PRIMARY KEY,bucket TEXT NOT NULL,visitor_hash TEXT NOT NULL,occurred_at INTEGER NOT NULL);
        CREATE INDEX IF NOT EXISTS rate_events_lookup_idx ON rate_events(bucket,visitor_hash,occurred_at);
        """
        with self.lock,self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript(schema)
    def execute(self,sql,args=()):
        with self.lock,self.connect() as db:
            cur=db.execute(sql,args); return cur.lastrowid
    def one(self,sql,args=()):
        with self.connect() as db:
            row=db.execute(sql,args).fetchone(); return dict(row) if row else None
    def all(self,sql,args=()):
        with self.connect() as db: return [dict(x) for x in db.execute(sql,args)]
    def audit(self,event,subject,ip,actor=None,tenant=None,detail=None):
        self.execute("INSERT INTO audit_log(created_at,actor_id,event,tenant_id,subject,ip_hash,detail) VALUES(?,?,?,?,?,?,?)",(now(),actor,event,tenant,subject,hashlib.sha256(ip.encode()).hexdigest(),json.dumps(detail or {},separators=(',',':'))))
    def create_user(self,email,name,password,role="admin",tenant_id="urbanhr",tenant_name="UrbanHRPartners Consulting"):
        if role not in ROLE_SET: raise ValueError("Invalid role")
        if len(password)<12 or not re.search(r"[A-Za-z]",password) or not re.search(r"\d",password): raise ValueError("Password must be at least 12 characters with letters and numbers")
        uid="USR-"+secrets.token_hex(8)
        with self.lock,self.connect() as db:
            db.execute("INSERT OR IGNORE INTO tenants(id,name) VALUES(?,?)",(tenant_id,tenant_name))
            db.execute("INSERT INTO users(id,tenant_id,email,name,role,password_hash,created_at) VALUES(?,?,?,?,?,?,?)",(uid,tenant_id,email.lower(),name,role,password_hash(password),now()))
        self.audit("user.created",uid,"local-cli",uid,tenant_id,{"role":role}); return uid

class PostgresConnection:
    def __init__(self,connection):self.connection=connection
    @staticmethod
    def adapt(sql):
        sql=sql.replace("datetime('now','-5 minutes')","(CURRENT_TIMESTAMP - INTERVAL '5 minutes')")
        if sql.startswith("INSERT OR IGNORE INTO tenants"):
            sql=sql.replace("INSERT OR IGNORE INTO tenants","INSERT INTO tenants")+" ON CONFLICT (id) DO NOTHING"
        return sql.replace("?","%s")
    def execute(self,sql,args=()):return self.connection.execute(self.adapt(sql),args)
    def __enter__(self):self.connection.__enter__();return self
    def __exit__(self,*args):return self.connection.__exit__(*args)

class PostgresStore(Store):
    """RDS/Aurora PostgreSQL store used by multi-instance production hosts."""
    def __init__(self,database_url):
        self.database_url=database_url;self.lock=threading.RLock()
        try:
            import psycopg
            from psycopg.rows import dict_row
        except ImportError as exc:
            raise RuntimeError("PostgreSQL requires the psycopg package from requirements.txt") from exc
        self.psycopg=psycopg;self.dict_row=dict_row;self.init()
    def connect(self):
        return PostgresConnection(self.psycopg.connect(self.database_url,row_factory=self.dict_row,connect_timeout=10))
    def init(self):
        schema="""
        CREATE TABLE IF NOT EXISTS tenants(id TEXT PRIMARY KEY,name TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1);
        CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,tenant_id TEXT NOT NULL REFERENCES tenants(id),email TEXT NOT NULL UNIQUE,name TEXT NOT NULL,role TEXT NOT NULL,password_hash TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 1,mfa_state TEXT NOT NULL DEFAULT 'not_enrolled',created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),csrf_token TEXT NOT NULL,created_at TEXT NOT NULL,expires_at BIGINT NOT NULL,ip_hash TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit_log(id BIGSERIAL PRIMARY KEY,created_at TEXT NOT NULL,actor_id TEXT,event TEXT NOT NULL,tenant_id TEXT,subject TEXT NOT NULL,ip_hash TEXT NOT NULL,detail TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS leads(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,name TEXT NOT NULL,company TEXT NOT NULL,email TEXT NOT NULL,market TEXT NOT NULL,need TEXT NOT NULL,consent INTEGER NOT NULL,status TEXT NOT NULL,source TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS assessments(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,language TEXT NOT NULL,answers TEXT NOT NULL,status TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS recruiting_requests(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,company TEXT NOT NULL,contact_name TEXT NOT NULL,email TEXT NOT NULL,role_title TEXT NOT NULL,market TEXT NOT NULL,timeline TEXT NOT NULL,context TEXT NOT NULL,status TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS applications(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,job_id TEXT NOT NULL,name TEXT NOT NULL,email TEXT NOT NULL,phone TEXT NOT NULL,location TEXT NOT NULL,profile_url TEXT NOT NULL,note TEXT NOT NULL,status TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS whatsapp_intents(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,country TEXT NOT NULL,purpose TEXT NOT NULL,message TEXT NOT NULL,language TEXT NOT NULL,status TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS analytics_events(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,visitor_hash TEXT NOT NULL,event TEXT NOT NULL,path TEXT NOT NULL,language TEXT NOT NULL,region TEXT NOT NULL,detail TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS advice_requests(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,visitor_hash TEXT NOT NULL,industry TEXT NOT NULL,region TEXT NOT NULL,need TEXT NOT NULL,language TEXT NOT NULL,service TEXT NOT NULL,answer TEXT NOT NULL,status TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS universal_intakes(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,customer_type TEXT NOT NULL,country TEXT NOT NULL,industry TEXT NOT NULL,need TEXT NOT NULL,complexity TEXT NOT NULL,service_id TEXT NOT NULL,governance TEXT NOT NULL,delivery_model TEXT NOT NULL,route TEXT NOT NULL,status TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS service_requests(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,template_id TEXT NOT NULL,template_version TEXT NOT NULL,service TEXT NOT NULL,name TEXT NOT NULL,company TEXT NOT NULL,email TEXT NOT NULL,country TEXT NOT NULL,answers TEXT NOT NULL,governance TEXT NOT NULL,status TEXT NOT NULL,source TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS integration_outbox(id TEXT PRIMARY KEY,created_at TEXT NOT NULL,kind TEXT NOT NULL,source_id TEXT NOT NULL,destination TEXT NOT NULL,status TEXT NOT NULL,attempts INTEGER NOT NULL DEFAULT 0,last_error TEXT);
        CREATE TABLE IF NOT EXISTS password_reset_tokens(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),expires_at BIGINT NOT NULL,used_at TEXT);
        CREATE TABLE IF NOT EXISTS anonymous_csrf(visitor_hash TEXT PRIMARY KEY,token TEXT NOT NULL,expires_at BIGINT NOT NULL);
        CREATE TABLE IF NOT EXISTS rate_events(id TEXT PRIMARY KEY,bucket TEXT NOT NULL,visitor_hash TEXT NOT NULL,occurred_at BIGINT NOT NULL);
        CREATE INDEX IF NOT EXISTS analytics_events_created_idx ON analytics_events(created_at);
        CREATE INDEX IF NOT EXISTS integration_outbox_status_idx ON integration_outbox(status,created_at);
        CREATE INDEX IF NOT EXISTS audit_log_tenant_created_idx ON audit_log(tenant_id,created_at);
        CREATE INDEX IF NOT EXISTS rate_events_lookup_idx ON rate_events(bucket,visitor_hash,occurred_at);
        """
        with self.lock,self.connect() as db:
            for statement in schema.split(";"):
                if statement.strip():db.execute(statement)
    def execute(self,sql,args=()):
        with self.lock,self.connect() as db:db.execute(sql,args)
    def one(self,sql,args=()):
        with self.connect() as db:
            row=db.execute(sql,args).fetchone();return dict(row) if row else None
    def all(self,sql,args=()):
        with self.connect() as db:return [dict(x) for x in db.execute(sql,args).fetchall()]

@dataclass
class App:
    root: Path
    store: Store | PostgresStore
    config: dict
    csrf: dict
    rate: dict
    production: bool
    trusted_hosts: set[str]

def load_app(root=ROOT,data_path=None):
    root=Path(root).resolve(); cfg=json.loads((root/"config/site.json").read_text(encoding="utf-8"))
    production=os.getenv("UHR_PRODUCTION","0")=="1"
    configured_base=os.getenv("UHR_INTEGRATION_BASE_URL","").strip()
    if configured_base:cfg["integration_base_url"]=configured_base.rstrip("/")
    domain=cfg["brand"]["domain"].lower()
    trusted={x.strip().lower() for x in os.getenv("UHR_TRUSTED_HOSTS",f"{domain},www.{domain}").split(",") if x.strip()}
    if production and os.getenv("UHR_SECURE_COOKIES","0")!="1":raise RuntimeError("Production requires UHR_SECURE_COOKIES=1")
    database_url=os.getenv("DATABASE_URL","").strip();postgres_configured=bool(database_url or os.getenv("PGHOST",""))
    store=Store(Path(data_path or os.getenv("UHR_SITE_DB",root/"data/site.db"))) if data_path or not postgres_configured else PostgresStore(database_url)
    return App(root,store,cfg,{}, {},production,trusted)

class Handler(BaseHTTPRequestHandler):
    server_version="UrbanGateway"
    sys_version=""
    def log_message(self,fmt,*args): pass
    @property
    def app(self): return self.server.app
    def security_headers(self,content_type="application/json; charset=utf-8"):
        self.send_header("Content-Type",content_type); self.send_header("X-Content-Type-Options","nosniff"); self.send_header("X-Frame-Options","DENY"); self.send_header("Referrer-Policy","strict-origin-when-cross-origin"); self.send_header("Permissions-Policy","camera=(), microphone=(), geolocation=()")
        self.send_header("Content-Security-Policy","default-src 'self'; img-src 'self' data:; media-src 'self'; style-src 'self'; script-src 'self'; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
        self.send_header("Cross-Origin-Opener-Policy","same-origin"); self.send_header("Cross-Origin-Resource-Policy","same-origin")
        if self.app.production:self.send_header("Strict-Transport-Security","max-age=31536000; includeSubDomains")
        self.send_header("Cache-Control","no-store" if self.path.startswith("/api/") else "public, max-age=300")
    def json(self,status,payload,cookie=None):
        body=json.dumps(payload,ensure_ascii=False).encode(); self.send_response(status); self.security_headers(); self.send_header("Content-Length",str(len(body)))
        if cookie:self.send_header("Set-Cookie",cookie)
        self.end_headers(); self.wfile.write(body)
    def body(self,limit=32_768):
        try:size=int(self.headers.get("Content-Length","0"))
        except ValueError:raise ValueError("Invalid content length")
        if size>limit:raise ValueError("Request too large")
        return json.loads(self.rfile.read(size) or b"{}")
    def ip(self):
        remote=self.client_address[0]
        if os.getenv("UHR_TRUST_PROXY","0")!="1":return remote
        candidate=self.headers.get("X-Forwarded-For","").split(",",1)[0].strip()
        try:return ipaddress.ip_address(candidate).compressed if candidate else remote
        except ValueError:return remote
    def host_allowed(self):
        if not self.app.production:return True
        host=self.headers.get("Host","").split(":",1)[0].strip().lower()
        return host in self.app.trusted_hosts
    def cookie(self,name):
        c=SimpleCookie(); c.load(self.headers.get("Cookie","")); return c[name].value if name in c else ""
    def session(self):
        raw=self.cookie("uhr_session")
        if not raw:return None
        th=hashlib.sha256(raw.encode()).hexdigest(); row=self.app.store.one("SELECT s.*,u.email,u.name,u.role,u.tenant_id,t.name tenant_name,u.active,u.mfa_state FROM sessions s JOIN users u ON u.id=s.user_id JOIN tenants t ON t.id=u.tenant_id WHERE s.token_hash=?",(th,))
        if not row or row["expires_at"]<int(time.time()) or not row["active"]: return None
        return row
    def csrf_token(self,create=False):
        s=self.session()
        if s:return s["csrf_token"]
        visitor=self.cookie("uhr_visitor")
        if not re.fullmatch(r"[A-Za-z0-9_-]{43}",visitor):
            if not create:return ""
            visitor=secrets.token_urlsafe(32)
            secure="; Secure" if os.getenv("UHR_SECURE_COOKIES","0")=="1" else ""
            self._visitor_cookie=f"uhr_visitor={visitor}; Path=/; HttpOnly; SameSite=Lax; Max-Age=600{secure}"
        key=hashlib.sha256(visitor.encode()).hexdigest();current=int(time.time())
        record=self.app.store.one("SELECT token,expires_at FROM anonymous_csrf WHERE visitor_hash=?",(key,))
        if record and record["expires_at"]>=current:return record["token"]
        if not create:return ""
        token=secrets.token_urlsafe(24);expires=current+600
        self.app.store.execute("INSERT INTO anonymous_csrf(visitor_hash,token,expires_at) VALUES(?,?,?) ON CONFLICT(visitor_hash) DO UPDATE SET token=excluded.token,expires_at=excluded.expires_at WHERE anonymous_csrf.expires_at<?",(key,token,expires,current))
        return self.app.store.one("SELECT token FROM anonymous_csrf WHERE visitor_hash=?",(key,))["token"]
    def require_csrf(self):
        supplied=self.headers.get("X-CSRF-Token",""); expected=self.csrf_token()
        if not supplied or not expected or not hmac.compare_digest(supplied,expected):raise PermissionError("Request verification failed")
    def rate_limit(self,bucket,limit,window):
        visitor=hashlib.sha256(self.ip().encode()).hexdigest();current=int(time.time());cutoff=current-window
        self.app.store.execute("DELETE FROM rate_events WHERE occurred_at<?",(cutoff,))
        row=self.app.store.one("SELECT COUNT(*) AS total FROM rate_events WHERE bucket=? AND visitor_hash=? AND occurred_at>=?",(bucket,visitor,cutoff))
        if row and int(row["total"])>=limit:return False
        self.app.store.execute("INSERT INTO rate_events(id,bucket,visitor_hash,occurred_at) VALUES(?,?,?,?)",("RATE-"+secrets.token_hex(12),bucket,visitor,current));return True
    def do_GET(self):
        path=urlparse(self.path).path
        if path!="/api/health" and not self.host_allowed():return self.json(421,{"error":"Unrecognized host"})
        if path=="/api/health":
            integration_base=self.app.config.get("integration_base_url","")
            connected=integration_base.startswith("https://") and "127.0.0.1" not in integration_base and "localhost" not in integration_base
            return self.json(200,{"status":"ok","service":"UrbanHRPartners Consulting gateway","time":now(),"production":self.app.production,"integrations":"configured" if connected else "connector-required"})
        if path=="/api/auth/csrf":
            token=self.csrf_token(create=True)
            return self.json(200,{"csrf_token":token},getattr(self,"_visitor_cookie",None))
        if path=="/api/jobs":
            catalog=json.loads((self.app.root/"config/jobs.json").read_text(encoding="utf-8"));return self.json(200,{"jobs":[x for x in catalog["jobs"] if x.get("status")=="published"]})
        if path=="/api/analytics/public-summary":return self.public_summary()
        if path=="/api/catalog":return self.json(200,json.loads((self.app.root/"config/capabilities.json").read_text(encoding="utf-8")))
        if path=="/api/service-intake-templates":return self.json(200,json.loads((self.app.root/"config/service-intake-templates.json").read_text(encoding="utf-8")))
        if path=="/api/analytics/report":
            s=self.session()
            if not s or s["role"] not in {"admin","consultant"}:return self.json(403,{"error":"Authorized analytics role required"})
            return self.json(200,{"events":self.app.store.all("SELECT event,region,language,count(*) total FROM analytics_events GROUP BY event,region,language ORDER BY total DESC"),"advice":self.app.store.all("SELECT industry,region,service,status,count(*) total FROM advice_requests GROUP BY industry,region,service,status ORDER BY total DESC")})
        if path=="/api/admin/users":
            s=self.session()
            if not s:return self.json(401,{"error":"Authentication required"})
            if s["role"]!="admin":return self.json(403,{"error":"Administrator access required"})
            users=self.app.store.all("SELECT u.id,u.tenant_id,t.name tenant_name,u.email,u.name,u.role,u.active,u.mfa_state,u.created_at FROM users u JOIN tenants t ON t.id=u.tenant_id ORDER BY t.name,u.name,u.email")
            return self.json(200,{"users":users,"count":len(users)})
        if path=="/api/portal":
            s=self.session()
            if not s:return self.json(401,{"error":"Authentication required"})
            integration_base=self.app.config.get("integration_base_url","")
            integration_ready=integration_base.startswith("https://") and "127.0.0.1" not in integration_base and "localhost" not in integration_base
            allowed=[]
            if integration_ready:
                for item in self.app.config["integrations"]:
                    if s["role"] in item["roles"]:
                        allowed.append({**item,"url":self.app.config["integration_base_url"]+item["path"]})
            return self.json(200,{"user":{"name":s["name"],"email":s["email"],"role":s["role"],"tenant_id":s["tenant_id"],"tenant_name":s["tenant_name"],"mfa_state":s["mfa_state"]},"integrations":allowed,"integration_status":"configured" if integration_ready else "connector-required"})
        if path=="/api/media":
            cat=json.loads((self.app.root/"media/catalog.json").read_text(encoding="utf-8")); return self.json(200,{"assets":[x for x in cat["assets"] if x["publication_state"]=="published"]})
        return self.static(path)
    def do_POST(self):
        if not self.host_allowed():return self.json(421,{"error":"Unrecognized host"})
        path=urlparse(self.path).path
        try:
            self.require_csrf()
            if path=="/api/service-requests":return self.service_request()
            if path=="/api/leads":return self.lead()
            if path=="/api/assessments":return self.assessment()
            if path=="/api/recruiting/requests":return self.recruiting_request()
            if path=="/api/jobs/apply":return self.job_application()
            if path=="/api/whatsapp/intents":return self.whatsapp_intent()
            if path=="/api/analytics/events":return self.analytics_event()
            if path=="/api/advice":return self.advice_request()
            if path=="/api/intake/classify":return self.classify_intake()
            if path=="/api/auth/login":return self.login()
            if path=="/api/auth/logout":return self.logout()
            return self.json(404,{"error":"Not found"})
        except PermissionError as e:return self.json(403,{"error":str(e)})
        except (ValueError,KeyError,json.JSONDecodeError) as e:return self.json(400,{"error":str(e)})
    def service_request(self):
        if not self.rate_limit("service-request",10,3600):return self.json(429,{"error":"Please wait before sending another service request"})
        b=self.body();template_id=str(b.get("template_id","")).strip()[:80];template_version=str(b.get("template_version","")).strip()[:40];service=str(b.get("service","")).strip()[:180]
        common={k:str(b.get(k,"")).strip() for k in ("name","company","email","country")}
        answers=b.get("answers",{})
        if not template_id or not template_version or not service or not all(common.values()) or not EMAIL_RE.match(common["email"]):raise ValueError("Complete the service identity and contact fields with a valid email")
        if str(b.get("consent","")).lower() not in {"on","true","1"}:raise ValueError("Consent is required")
        if not isinstance(answers,dict):raise ValueError("Service answers must be an object")
        templates=json.loads((self.app.root/"config/service-intake-templates.json").read_text(encoding="utf-8"));catalog=json.loads((self.app.root/"config/capabilities.json").read_text(encoding="utf-8"))
        if template_version!=str(templates.get("version")):raise ValueError("This service template has changed; reload and try again")
        template=next((x for x in templates.get("templates",[]) if x.get("id")==template_id and x.get("service")==service),None)
        capability=next((x for x in catalog.get("capabilities",[]) if x.get("name")==service),None)
        if not template or not capability:raise ValueError("Unknown service workflow")
        if common["country"] not in catalog.get("jurisdictions",[]):raise ValueError("Invalid country or jurisdiction")
        validated={}
        for field in template.get("questions",[]):
            key=str(field.get("name","")).strip();value=answers.get(key)
            if field.get("required") and (value is None or str(value).strip()==""):raise ValueError("Complete required service field: "+str(field.get("label") or key))
            if value is None or str(value).strip()=="":continue
            text=str(value).strip()
            if len(text)>2000:raise ValueError("A service answer is too long")
            if field.get("type")=="select" and text not in field.get("options",[]):raise ValueError("Invalid selection for "+str(field.get("label") or key))
            if field.get("type")=="number":
                try:number=float(text)
                except ValueError:raise ValueError("Enter a valid number for "+str(field.get("label") or key))
                if number<float(field.get("min",0)) or number>float(field.get("max",10**12)):raise ValueError("Number outside the allowed range for "+str(field.get("label") or key))
            validated[key]=text
        rid="SRV-"+secrets.token_hex(8);oid="OUT-"+secrets.token_hex(8);governance=str(capability.get("governance","qualification-required"));destination="UrbanOne / "+service+" / CRM"
        with self.app.store.lock,self.app.store.connect() as db:
            db.execute("INSERT INTO service_requests VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",(rid,now(),template_id,template_version,service,common["name"][:100],common["company"][:150],common["email"][:254].lower(),common["country"][:100],json.dumps(validated,ensure_ascii=False,separators=(',',':')),governance,"qualified-pending-review","capability-workflow"))
            db.execute("INSERT INTO integration_outbox(id,created_at,kind,source_id,destination,status) VALUES(?,?,?,?,?,?)",(oid,now(),"service.request.created",rid,destination,"pending-connector"))
        self.app.store.audit("service.request.created",rid,self.ip(),detail={"template_id":template_id,"template_version":template_version,"service":service,"country":common["country"],"governance":governance,"outbox_id":oid})
        return self.json(201,{"id":rid,"service":service,"template_id":template_id,"governance":governance,"status":"qualified-pending-review","integration_status":"pending-connector"})
    def analytics_event(self):
        if not self.rate_limit("analytics",120,3600):return self.json(429,{"error":"Analytics rate limit reached"})
        b=self.body();event=str(b.get("event",""))[:60];path=str(b.get("path","/"))[:300];language=str(b.get("language","en"))[:8];region=str(b.get("region","unknown"))[:80];detail=b.get("detail",{})
        if not event or not isinstance(detail,dict):raise ValueError("Invalid analytics event")
        session_id=str(b.get("session_id","")).strip()[:100]
        if session_id and not re.fullmatch(r"[A-Za-z0-9_-]{16,100}",session_id):raise ValueError("Invalid analytics session")
        eid="EVT-"+secrets.token_hex(8);visitor=hashlib.sha256((session_id or self.ip()+self.headers.get("User-Agent","")).encode()).hexdigest()
        self.app.store.execute("INSERT INTO analytics_events VALUES(?,?,?,?,?,?,?,?)",(eid,now(),visitor,event,path,language,region,json.dumps(detail,ensure_ascii=False)[:2000]));return self.json(201,{"id":eid,"status":"recorded"})
    def classify_intake(self):
        if not self.rate_limit("intake",20,3600):return self.json(429,{"error":"Please wait before submitting another need"})
        b=self.body();need=str(b.get("need","")).strip()[:2000];customer=str(b.get("customer_type","company"))[:30];country=str(b.get("country","Global / Multi-country"))[:100];industry=str(b.get("industry","Other / Emerging Industry"))[:120];complexity=str(b.get("complexity","unsure"))[:30]
        if len(need)<8:raise ValueError("Describe what you need in at least 8 characters")
        catalog=json.loads((self.app.root/"config/capabilities.json").read_text(encoding="utf-8"));low=need.lower();matches=[]
        for service in catalog["service_families"]:
            score=sum(1 for k in service["keywords"] if k in low)
            if score:matches.append((score,service))
        service=max(matches,key=lambda x:x[0])[1] if matches else next(x for x in catalog["service_families"] if x["id"]=="custom")
        governance=service["governance"];delivery="Professional consultation"
        if governance in {"ai-assisted","automatable"}:delivery="Guided DIY"
        elif governance=="custom-build":delivery="Custom build"
        elif service["id"]=="talent":delivery="Staffing"
        route="UrbanOne qualification → "+service["name"]
        iid="INT-"+secrets.token_hex(8);oid="OUT-"+secrets.token_hex(8)
        with self.app.store.lock,self.app.store.connect() as db:
            db.execute("INSERT INTO universal_intakes VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",(iid,now(),customer,country,industry,need,complexity,service["id"],governance,delivery,route,"qualified-preliminary"));db.execute("INSERT INTO integration_outbox(id,created_at,kind,source_id,destination,status) VALUES(?,?,?,?,?,?)",(oid,now(),"intake.classified",iid,"Urban360 / UrbanOne / CRM","pending-connector"))
        self.app.store.audit("intake.classified",iid,self.ip(),detail={"country":country,"industry":industry,"service":service["id"],"governance":governance,"outbox_id":oid});return self.json(201,{"id":iid,"service":{"id":service["id"],"name":service["name"]},"governance":governance,"delivery_model":delivery,"route":route,"status":"qualified-preliminary","integration_status":"pending-connector"})
    def advice_request(self):
        if not self.rate_limit("advice",15,3600):return self.json(429,{"error":"Please wait before requesting more advice"})
        b=self.body();industry=str(b.get("industry","")).strip()[:100];region=str(b.get("region","")).strip()[:100];need=str(b.get("need","")).strip()[:1200];language=str(b.get("language","en"))[:8]
        if not industry or not region or len(need)<8:raise ValueError("Complete industry, region and advice need")
        low=need.lower();service="Workforce & HR Strategy"
        if any(x in low for x in ("hire","recruit","talent","contratar","reclut")):service="Global Recruiting & ATS"
        elif any(x in low for x in ("safety","osha","sg-sst","risk","seguridad")):service="Safety & Compliance"
        elif any(x in low for x in ("train","academy","learning","capacita")):service="Urban Academy & Development"
        elif any(x in low for x in ("data","analytics","360","kpi","report")):service="Company Intelligence & Urban360"
        localized_services={"fr":{"Workforce & HR Strategy":"Stratégie RH et effectifs","Global Recruiting & ATS":"Recrutement mondial et ATS","Safety & Compliance":"Sécurité et conformité","Urban Academy & Development":"Urban Academy et développement","Company Intelligence & Urban360":"Intelligence d’entreprise et Urban360"},"pt":{"Workforce & HR Strategy":"Estratégia de RH e força de trabalho","Global Recruiting & ATS":"Recrutamento global e ATS","Safety & Compliance":"Segurança e conformidade","Urban Academy & Development":"Urban Academy e desenvolvimento","Company Intelligence & Urban360":"Inteligência empresarial e Urban360"},"de":{"Workforce & HR Strategy":"Personal- und HR-Strategie","Global Recruiting & ATS":"Globales Recruiting und ATS","Safety & Compliance":"Sicherheit und Compliance","Urban Academy & Development":"Urban Academy und Entwicklung","Company Intelligence & Urban360":"Unternehmensintelligenz und Urban360"},"it":{"Workforce & HR Strategy":"Strategia HR e forza lavoro","Global Recruiting & ATS":"Selezione globale e ATS","Safety & Compliance":"Sicurezza e conformità","Urban Academy & Development":"Urban Academy e sviluppo","Company Intelligence & Urban360":"Intelligence aziendale e Urban360"}}
        localized_service=localized_services.get(language,{}).get(service,service)
        answers={"es":f"Tu necesidad se alinea con {service}. Hemos creado una solicitud gobernada para el equipo asesor de {region}; el siguiente paso es validar alcance, jurisdicción y prioridad.","fr":f"Votre besoin correspond à {localized_service}. Une demande gouvernée a été créée pour l’équipe conseil de {region}; la prochaine étape valide le périmètre, la juridiction et la priorité.","pt":f"Sua necessidade está alinhada a {localized_service}. Criamos uma solicitação governada para a equipe de {region}; o próximo passo valida escopo, jurisdição e prioridade.","de":f"Ihr Bedarf entspricht {localized_service}. Für das Beratungsteam in {region} wurde eine gesteuerte Anfrage erstellt; als Nächstes werden Umfang, Rechtsordnung und Priorität geprüft.","it":f"La vostra esigenza corrisponde a {localized_service}. È stata creata una richiesta governata per il team di consulenza di {region}; il passo successivo convalida ambito, giurisdizione e priorità."}
        answer=answers.get(language,f"Your need aligns with {service}. A governed request has been created for the {region} advisory team; the next step validates scope, jurisdiction and priority.")
        aid="ADV-"+secrets.token_hex(8);oid="OUT-"+secrets.token_hex(8);visitor=hashlib.sha256((self.ip()+self.headers.get("User-Agent","")).encode()).hexdigest()
        with self.app.store.lock,self.app.store.connect() as db:
            db.execute("INSERT INTO advice_requests VALUES(?,?,?,?,?,?,?,?,?,?)",(aid,now(),visitor,industry,region,need,language,service,answer,"queued"));db.execute("INSERT INTO integration_outbox(id,created_at,kind,source_id,destination,status) VALUES(?,?,?,?,?,?)",(oid,now(),"advice.requested",aid,"UrbanOne / Advisory Agent Queue","pending-connector"))
        self.app.store.audit("advice.requested",aid,self.ip(),detail={"industry":industry,"region":region,"service":service,"outbox_id":oid});return self.json(201,{"id":aid,"industry":industry,"service":service,"answer":answer,"agent_status":"pending-connector"})
    def public_summary(self):
        visits=self.app.store.one("SELECT count(DISTINCT visitor_hash) total FROM analytics_events WHERE event='visit'")["total"];advice=self.app.store.one("SELECT count(*) total FROM advice_requests")["total"];regions=self.app.store.one("SELECT count(DISTINCT region) total FROM analytics_events WHERE region!='unknown'")["total"];services=self.app.store.one("SELECT count(DISTINCT service) total FROM advice_requests")["total"]
        active=self.app.store.one("SELECT count(DISTINCT visitor_hash) total FROM analytics_events WHERE created_at>=datetime('now','-5 minutes')")["total"];pageviews=self.app.store.one("SELECT count(*) total FROM analytics_events WHERE event='page_view'")["total"];region_data=self.app.store.all("SELECT region,count(DISTINCT visitor_hash) sessions FROM analytics_events WHERE region!='unknown' GROUP BY region ORDER BY sessions DESC LIMIT 25")
        recent=self.app.store.all("SELECT event,region,created_at FROM analytics_events ORDER BY created_at DESC LIMIT 5");feed=[{"label":x["event"].replace("_"," ").title(),"region":x["region"],"time":x["created_at"][11:16]+" UTC"} for x in recent]
        return self.json(200,{"visits":visits,"active_sessions":active,"pageviews":pageviews,"advice":advice,"regions":regions,"services":services,"region_data":region_data,"feed":feed})
    def lead(self):
        if not self.rate_limit("lead",5,3600):return self.json(429,{"error":"Please wait before sending another request"})
        b=self.body()
        if b.get("website"):return self.json(202,{"status":"accepted"})
        fields={k:str(b.get(k,"")).strip() for k in ("name","company","email","market","need")}
        if not all(fields.values()) or not EMAIL_RE.match(fields["email"]):raise ValueError("Complete all required fields with a valid email")
        if fields["market"] not in MARKET_SET:raise ValueError("Invalid market")
        if str(b.get("consent","")).lower() not in {"on","true","1"}:raise ValueError("Consent is required")
        if len(fields["need"])>1500:raise ValueError("Request is too long")
        lid="LEAD-"+secrets.token_hex(8); oid="OUT-"+secrets.token_hex(8)
        with self.app.store.lock,self.app.store.connect() as db:
            db.execute("INSERT INTO leads VALUES(?,?,?,?,?,?,?,?,?,?)",(lid,now(),fields["name"][:100],fields["company"][:150],fields["email"][:254].lower(),fields["market"],fields["need"],1,"queued","website"))
            db.execute("INSERT INTO integration_outbox(id,created_at,kind,source_id,destination,status) VALUES(?,?,?,?,?,?)",(oid,now(),"lead.created",lid,"UrbanHRPartners CRM / Company360","pending-connector"))
        self.app.store.audit("lead.created",lid,self.ip(),detail={"market":fields["market"],"outbox_id":oid});return self.json(201,{"id":lid,"status":"queued","integration_status":"pending-connector"})
    def assessment(self):
        if not self.rate_limit("assessment",10,3600):return self.json(429,{"error":"Please wait before sending another assessment"})
        b=self.body(); answers=b.get("answers")
        if b.get("language") not in {"en","es"} or not isinstance(answers,dict) or not 1<=len(answers)<=10:raise ValueError("Invalid assessment")
        aid="ASSESS-"+secrets.token_hex(8); self.app.store.execute("INSERT INTO assessments VALUES(?,?,?,?,?)",(aid,now(),b["language"],json.dumps(answers,ensure_ascii=False),"preliminary"));self.app.store.audit("assessment.created",aid,self.ip());return self.json(201,{"id":aid,"status":"preliminary"})
    def recruiting_request(self):
        if not self.rate_limit("recruiting",6,3600):return self.json(429,{"error":"Please wait before sending another recruiting request"})
        b=self.body();fields={k:str(b.get(k,"")).strip() for k in ("company","contact_name","email","role_title","market","timeline","context")}
        if not all(fields.values()) or not EMAIL_RE.match(fields["email"]):raise ValueError("Complete all recruiting fields with a valid email")
        if fields["market"] not in MARKET_SET or fields["timeline"] not in {"urgent","standard","planning"}:raise ValueError("Invalid recruiting selection")
        if str(b.get("consent","")).lower() not in {"on","true","1"}:raise ValueError("Consent is required")
        rid="RECRUIT-"+secrets.token_hex(8);oid="OUT-"+secrets.token_hex(8)
        with self.app.store.lock,self.app.store.connect() as db:
            db.execute("INSERT INTO recruiting_requests VALUES(?,?,?,?,?,?,?,?,?,?)",(rid,now(),fields["company"][:150],fields["contact_name"][:100],fields["email"][:254].lower(),fields["role_title"][:150],fields["market"],fields["timeline"],fields["context"][:1500],"queued"))
            db.execute("INSERT INTO integration_outbox(id,created_at,kind,source_id,destination,status) VALUES(?,?,?,?,?,?)",(oid,now(),"recruiting.requested",rid,"UrbanHRPartners ATS / CRM","pending-connector"))
        self.app.store.audit("recruiting.requested",rid,self.ip(),detail={"market":fields["market"],"outbox_id":oid});return self.json(201,{"id":rid,"status":"queued","ats_status":"pending-connector"})
    def job_application(self):
        if not self.rate_limit("application",8,3600):return self.json(429,{"error":"Please wait before sending another application"})
        b=self.body();fields={k:str(b.get(k,"")).strip() for k in ("job_id","name","email","phone","location","profile_url","note")}
        catalog=json.loads((self.app.root/"config/jobs.json").read_text(encoding="utf-8"));published={x["id"] for x in catalog["jobs"] if x.get("status")=="published"}
        if not all(fields.values()) or not EMAIL_RE.match(fields["email"]) or fields["job_id"] not in published:raise ValueError("Complete the application with a valid role and email")
        if not fields["profile_url"].startswith(("https://","http://")):raise ValueError("Provide a valid resume or LinkedIn URL")
        if str(b.get("consent","")).lower() not in {"on","true","1"}:raise ValueError("Consent is required")
        aid="APP-"+secrets.token_hex(8);oid="OUT-"+secrets.token_hex(8)
        with self.app.store.lock,self.app.store.connect() as db:
            db.execute("INSERT INTO applications VALUES(?,?,?,?,?,?,?,?,?,?)",(aid,now(),fields["job_id"],fields["name"][:100],fields["email"][:254].lower(),fields["phone"][:40],fields["location"][:100],fields["profile_url"][:500],fields["note"][:1200],"queued"))
            db.execute("INSERT INTO integration_outbox(id,created_at,kind,source_id,destination,status) VALUES(?,?,?,?,?,?)",(oid,now(),"ats.application.created",aid,"UrbanHRPartners ATS","pending-connector"))
        self.app.store.audit("ats.application.created",aid,self.ip(),detail={"job_id":fields["job_id"],"outbox_id":oid});return self.json(201,{"id":aid,"status":"queued","ats_status":"pending-connector"})
    def whatsapp_intent(self):
        if not self.rate_limit("whatsapp",20,3600):return self.json(429,{"error":"Please wait before opening another conversation"})
        b=self.body();country=str(b.get("country","")).lower();purpose=str(b.get("purpose","")).lower();message=str(b.get("message","")).strip()[:500];language=str(b.get("language","en"))
        purposes={"consultation","executive-advisory","recruiting","compliance","safety","systems","academy","candidate","client"};languages={"en","es","fr","pt","de","it"}
        if country not in {"colombia","usa"} or purpose not in purposes or language not in languages:raise ValueError("Invalid WhatsApp routing selection")
        purpose_labels={
            "en":{"consultation":"an enterprise consultation","executive-advisory":"executive HR and organizational advisory","recruiting":"recruiting and workforce solutions","compliance":"compliance and employee relations","safety":"SG-SST, OSHA/EHS and workplace safety","systems":"HR systems, analytics and Company360","academy":"training, leadership and Urban Academy","candidate":"candidate support","client":"existing client support"},
            "es":{"consultation":"una consulta empresarial","executive-advisory":"consultoría ejecutiva de RR. HH. y organización","recruiting":"reclutamiento y soluciones de fuerza laboral","compliance":"cumplimiento y relaciones laborales","safety":"SG-SST, OSHA/EHS y seguridad laboral","systems":"sistemas de RR. HH., analítica y Company360","academy":"formación, liderazgo y Urban Academy","candidate":"soporte para candidatos","client":"soporte para clientes actuales"},
            "fr":{"consultation":"une consultation d’entreprise","executive-advisory":"le conseil exécutif RH et organisationnel","recruiting":"le recrutement et les solutions de main-d’œuvre","compliance":"la conformité et les relations avec les employés","safety":"SG-SST, OSHA/EHS et la sécurité au travail","systems":"les systèmes RH, l’analytique et Company360","academy":"la formation, le leadership et Urban Academy","candidate":"l’assistance aux candidats","client":"l’assistance aux clients existants"},
            "pt":{"consultation":"uma consultoria empresarial","executive-advisory":"consultoria executiva de RH e organização","recruiting":"recrutamento e soluções de força de trabalho","compliance":"conformidade e relações trabalhistas","safety":"SG-SST, OSHA/EHS e segurança do trabalho","systems":"sistemas de RH, análise e Company360","academy":"treinamento, liderança e Urban Academy","candidate":"suporte ao candidato","client":"suporte ao cliente existente"},
            "de":{"consultation":"eine Unternehmensberatung","executive-advisory":"Executive HR- und Organisationsberatung","recruiting":"Recruiting- und Workforce-Lösungen","compliance":"Compliance und Mitarbeiterbeziehungen","safety":"SG-SST, OSHA/EHS und Arbeitssicherheit","systems":"HR-Systeme, Analytik und Company360","academy":"Schulung, Führung und Urban Academy","candidate":"Bewerberunterstützung","client":"Bestandskunden-Support"},
            "it":{"consultation":"una consulenza aziendale","executive-advisory":"consulenza executive HR e organizzativa","recruiting":"selezione e soluzioni per la forza lavoro","compliance":"conformità e relazioni con i dipendenti","safety":"SG-SST, OSHA/EHS e sicurezza sul lavoro","systems":"sistemi HR, analisi e Company360","academy":"formazione, leadership e Urban Academy","candidate":"supporto candidati","client":"supporto clienti esistenti"}}
        greetings={"en":"Hello. I would like an executive consultation regarding","es":"Hola. Deseo una consulta empresarial sobre","fr":"Bonjour. Je souhaite une consultation d’entreprise concernant","pt":"Olá. Desejo uma consultoria empresarial sobre","de":"Guten Tag. Ich wünsche eine Unternehmensberatung zu","it":"Buongiorno. Desidero una consulenza aziendale su"}
        number=self.app.config["contacts"][country]["whatsapp"];label=purpose_labels.get(language,purpose_labels["en"]).get(purpose,purpose.replace("-"," "));default=f"{greetings[language]} {label}."
        text=message or default;wid="WA-"+secrets.token_hex(8);oid="OUT-"+secrets.token_hex(8)
        with self.app.store.lock,self.app.store.connect() as db:
            db.execute("INSERT INTO whatsapp_intents VALUES(?,?,?,?,?,?,?)",(wid,now(),country,purpose,text,language,"opened"))
            db.execute("INSERT INTO integration_outbox(id,created_at,kind,source_id,destination,status) VALUES(?,?,?,?,?,?)",(oid,now(),"whatsapp.intent",wid,"UrbanHRPartners CRM communications","pending-connector"))
        from urllib.parse import quote
        self.app.store.audit("whatsapp.intent",wid,self.ip(),detail={"country":country,"purpose":purpose,"outbox_id":oid});return self.json(201,{"id":wid,"url":f"https://wa.me/{number}?text={quote(text)}","crm_status":"pending-connector"})
    def login(self):
        if not self.rate_limit("login",8,900):return self.json(429,{"error":"Too many attempts. Try again later."})
        b=self.body(); email=str(b.get("email","")).lower().strip(); user=self.app.store.one("SELECT * FROM users WHERE email=?",(email,))
        if not user or not user["active"] or not password_ok(str(b.get("password","")),user["password_hash"]):
            self.app.store.audit("auth.failed",email or "unknown",self.ip());time.sleep(.15);return self.json(401,{"error":"Invalid email or password"})
        if user["mfa_state"]=="enabled":return self.json(503,{"error":"MFA verifier is not configured; access denied safely"})
        raw=secrets.token_urlsafe(32);th=hashlib.sha256(raw.encode()).hexdigest();csrf=secrets.token_urlsafe(24);exp=int(time.time())+8*3600;iph=hashlib.sha256(self.ip().encode()).hexdigest()
        self.app.store.execute("INSERT INTO sessions VALUES(?,?,?,?,?,?)",(th,user["id"],csrf,now(),exp,iph));self.app.store.audit("auth.login",user["id"],self.ip(),user["id"],user["tenant_id"])
        secure="; Secure" if os.getenv("UHR_SECURE_COOKIES","0")=="1" else "";return self.json(200,{"status":"authenticated","role":user["role"]},f"uhr_session={raw}; Path=/; HttpOnly; SameSite=Lax; Max-Age=28800{secure}")
    def logout(self):
        raw=self.cookie("uhr_session");s=self.session()
        if raw:self.app.store.execute("DELETE FROM sessions WHERE token_hash=?",(hashlib.sha256(raw.encode()).hexdigest(),))
        if s:self.app.store.audit("auth.logout",s["user_id"],self.ip(),s["user_id"],s["tenant_id"])
        return self.json(200,{"status":"signed_out"},"uhr_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
    def static(self,path):
        rel="index.html" if path in {"","/"} else path.lstrip("/"); dest=(self.app.root/rel).resolve()
        if self.app.root!=dest and self.app.root not in dest.parents:return self.json(403,{"error":"Invalid path"})
        if any(part.startswith(".") for part in Path(rel).parts) or dest.suffix.lower() in {".py",".db",".sqlite3",".pem",".p7m",".log",".yml",".yaml",".bak"}:return self.json(403,{"error":"Internal file is not publicly served"})
        if not dest.is_file():return self.json(404,{"error":"Not found"})
        if "assets/media/source" in dest.as_posix():return self.json(403,{"error":"Internal reference media is not publicly served"})
        body=dest.read_bytes();self.send_response(200);self.security_headers(mimetypes.guess_type(dest.name)[0] or "application/octet-stream");self.send_header("Content-Length",str(len(body)));self.end_headers();self.wfile.write(body)

def serve(app,host="127.0.0.1",port=8787):
    class UrbanServer(ThreadingHTTPServer):daemon_threads=True;allow_reuse_address=True
    server=UrbanServer((host,port),Handler);server.app=app;return server
def main():
    p=argparse.ArgumentParser();p.add_argument("--host",default=os.getenv("HOST","127.0.0.1"));p.add_argument("--port",type=int,default=int(os.getenv("PORT","8787")));p.add_argument("--create-admin",action="store_true");args=p.parse_args();app=load_app()
    if args.create_admin:
        email=input("Admin email: ").strip();name=input("Admin name: ").strip();pw=getpass.getpass("Password: ");app.store.create_user(email,name,pw);print("Admin created.");return
    print(f"UrbanHRPartners Consulting ready at http://{args.host}:{args.port}");serve(app,args.host,args.port).serve_forever()
if __name__=="__main__":main()
