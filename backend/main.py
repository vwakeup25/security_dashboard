import os
import json
import time
import hashlib
import socket
import random
import logging
from datetime import datetime, timedelta
from typing import Optional, List, Generator
from io import BytesIO

# --- FastAPI and related imports ---
from fastapi import FastAPI, Depends, HTTPException, Query, Response, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer

# --- Security and Auth ---
from jose import JWTError, jwt
from passlib.context import CryptContext

# --- Data and Settings ---
from pydantic import BaseModel
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# --- Database ---
from sqlmodel import SQLModel, Field, Session, create_engine, select
from sqlalchemy.orm import Session as DBSession

# --- Cryptography ---
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

# --- Logging ---
from pythonjsonlogger import jsonlogger

# =================== Logging Setup ===================
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logHandler = logging.FileHandler("app_security_local.log")
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(message)s')
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)
# =======================================================

# Optional libs (best-effort)
try:
    from river import anomaly
    RIVER_OK = True
except ImportError:
    RIVER_OK = False

try:
    from scapy.all import sniff, IP
    SCAPY_OK = True
except ImportError:
    SCAPY_OK = False

try:
    import geoip2.database
    GEO_OK = True
except ImportError:
    GEO_OK = False

try:
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    REPORTLAB_OK = True
except ImportError:
    REPORTLAB_OK = False


# ------------------- Robust Configuration -------------------
class Settings(BaseSettings):
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    CORS_ORIGINS: str = "*"
    JWT_SECRET: str
    JWT_ALGO: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 12 * 60
    ADMIN_USER: str
    ADMIN_PASS_HASH: str
    DB_URL: str
    FERNET_KEY_PATH: str = "fernet.key"
    ED25519_PRIV_PATH: str = "ed25519_private.key"
    ED25519_PUB_PATH: str = "ed25519_public.key"
    GEOLITE_DB: str = "GeoLite2-City.mmdb"

    class Config:
        env_file = ".env"

settings = Settings()

# ------------------- Global Setup -------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# Database
engine = create_engine(settings.DB_URL, connect_args={"check_same_thread": False} if settings.DB_URL.startswith("sqlite") else {})

# Fernet
with open(settings.FERNET_KEY_PATH, "rb") as f:
    FERNET = Fernet(f.read())

# Ed25519 keys
with open(settings.ED25519_PRIV_PATH, "rb") as f:
    PRIV_KEY = serialization.load_pem_private_key(f.read(), password=None)
with open(settings.ED25519_PUB_PATH, "rb") as f:
    PUB_KEY = serialization.load_pem_public_key(f.read())

# GeoIP reader (optional)
GEO_READER = None
if GEO_OK and os.path.exists(settings.GEOLITE_DB):
    try:
        GEO_READER = geoip2.database.Reader(settings.GEOLITE_DB)
    except Exception:
        GEO_READER = None

# ------------------- Models -------------------
class Block(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    index: int
    timestamp: str
    previous_hash: str
    hash: str
    signature_hex: str
    src_ip: str
    dst_ip: str
    size: int
    severity: str
    attack_type: str
    detected_by: str
    ml_confidence: float
    hostname: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None
    enc_data: bytes

class LogsResponse(BaseModel):
    items: List[dict]
    page: int
    pages: int
    total: int

class Token(BaseModel):
    access_token: str
    token_type: str

# Create DB Tables
SQLModel.metadata.create_all(engine)

# ------------------- Dependencies -------------------
def get_db() -> Generator[Session, None, None]:
    """Dependency to get a DB session for a request."""
    db = Session(engine)
    try:
        yield db
    finally:
        db.close()

def get_current_user(token: str = Depends(oauth2_scheme)):
    """Dependency to validate token and return the current user."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGO])
        username: Optional[str] = payload.get("sub")
        if username is None or username != settings.ADMIN_USER:
            raise credentials_exception
        return username
    except JWTError:
        raise credentials_exception

# ------------------- App Instance -------------------
app = FastAPI(title="Smart Security Dashboard (Secure)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.CORS_ORIGINS] if settings.CORS_ORIGINS != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------- Helper Functions -------------------
def calculate_hash(index: int, timestamp: str, data_text: str, previous_hash: str) -> str:
    raw = f"{index}{timestamp}{data_text}{previous_hash}".encode()
    return hashlib.sha256(raw).hexdigest()

def sign_bytes(b: bytes) -> str:
    sig = PRIV_KEY.sign(b)
    return sig.hex()

def verify_signature(b: bytes, sig_hex: str) -> bool:
    try:
        PUB_KEY.verify(bytes.fromhex(sig_hex), b)
        return True
    except Exception:
        return False

def encrypt_json(d: dict) -> bytes:
    return FERNET.encrypt(json.dumps(d).encode())

def decrypt_json(blob: bytes) -> dict:
    return json.loads(FERNET.decrypt(blob).decode())

def hostname_of(ip: str) -> Optional[str]:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None

def geo_of(ip: str):
    if ip.startswith(("10.", "192.168.", "127.", "0.", "169.254.")) or ip.startswith("172."):
        return (None, None, None)
    if GEO_READER:
        try:
            r = GEO_READER.city(ip)
            return (r.country.name or None, r.city.name or None, None)
        except Exception:
            return (None, None, None)
    return (None, None, None)

RATE_WINDOW = 30
_rate_times: List[float] = []

def push_rate():
    now = time.time()
    _rate_times.append(now)
    cutoff = now - RATE_WINDOW
    while _rate_times and _rate_times[0] < cutoff:
        _rate_times.pop(0)

def current_rate():
    if len(_rate_times) < 2:
        return 0.0
    span = _rate_times[-1] - _rate_times[0]
    return (len(_rate_times) - 1) / span if span > 0 else 0.0

def rate_history():
    now = time.time()
    cutoff = now - RATE_WINDOW
    pts = [t for t in _rate_times if t >= cutoff]
    if not pts: return []
    buckets, hist = 10, []
    width = RATE_WINDOW / buckets
    for i in range(buckets):
        start = cutoff + i * width
        end = start + width
        count = sum(1 for t in pts if start <= t < end)
        hist.append({"ts": int(start), "count": count})
    return hist

if RIVER_OK:
    HST = anomaly.HalfSpaceTrees(seed=42)
else:
    HST = None

def ml_anomaly_score(x: dict) -> float:
    if not HST: return 0.0
    try:
        s = HST.score_one(x)
        HST.learn_one(x)
        norm = 1 - (1 / (1 + s))
        return max(0.0, min(1.0, norm))
    except Exception:
        return 0.0

def severity_and_attack(packet, ml_score: float, ip_counts: dict):
    size, src = packet["size"], packet["src_ip"]
    hits = ip_counts.get(src, 0)
    
    attack = "Normal"
    if size > 1200: attack = "Possible DDoS"
    elif hits >= 5: attack = "Suspicious Host"
    elif ml_score >= 0.75: attack = "Unknown Attack (AI Flagged)"
    elif size > 1000: attack = "Large Packet"

    if attack in ("Possible DDoS",) or ml_score >= 0.9 or size > 1400: sev = "High"
    elif attack in ("Suspicious Host",) or ml_score >= 0.75 or size > 1200: sev = "Medium"
    elif attack in ("Large Packet",) or ml_score >= 0.6 or size > 1000: sev = "Low"
    else: sev = "Normal"
    
    return sev, attack

SRC_HITS = {}

# ------------------- API Routes -------------------
@app.post("/login", response_model=Token)
def login(request: Request, form_data: OAuth2PasswordRequestForm = Depends()):
    """Handles user login, providing a JWT token upon success."""
    if form_data.username != settings.ADMIN_USER or not pwd_context.verify(form_data.password, settings.ADMIN_PASS_HASH):
        logging.warning("User login failed", extra={'event_type': 'LOGIN_FAILURE', 'username_attempt': form_data.username, 'ip_address': request.client.host})
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    
    logging.info("User login successful", extra={'event_type': 'LOGIN_SUCCESS', 'username': form_data.username, 'ip_address': request.client.host})
    token = create_access_token({"sub": settings.ADMIN_USER})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/")
def root():
    return {"message": "🚀 Secure Smart Security Dashboard Backend is running"}

@app.get("/packet_rate")
def packet_rate():
    return {"rate": current_rate(), "history": rate_history()}

@app.get("/logs", response_model=LogsResponse)
def logs(page: int = 1, limit: int = 25, type: str = "All", severity: str = "All", user: str = Depends(get_current_user), db: DBSession = Depends(get_db)):
    page = max(1, page)
    limit = max(1, min(200, limit))
    stmt = select(Block).order_by(Block.id.desc())
    rows = db.exec(stmt).all()

    def keep(r: Block):
        if severity != "All" and r.severity != severity: return False
        if type != "All" and r.attack_type != type: return False
        return True

    filtered_rows = [r for r in rows if keep(r)]
    total = len(filtered_rows)
    pages = max(1, (total + limit - 1) // limit)
    start = (page - 1) * limit
    page_rows = filtered_rows[start:start + limit]

    items = [r.dict() for r in page_rows]
    for item in items:
        item["signature_ok"] = verify_signature(bytes.fromhex(item["hash"]), item["signature_hex"])
        
    return {"items": items, "page": page, "pages": pages, "total": total}

@app.post("/reset")
def reset(user: str = Depends(get_current_user), db: DBSession = Depends(get_db)):
    db.query(Block).delete()
    db.commit()
    SRC_HITS.clear()
    _rate_times.clear()
    return {"ok": True}

@app.get("/export")
def export(format: str = Query("pdf"), user: str = Depends(get_current_user), db: DBSession = Depends(get_db)):
    if format.lower() != "pdf":
        raise HTTPException(status_code=400, detail="Only PDF export is enabled.")
    if not REPORTLAB_OK:
        raise HTTPException(status_code=500, detail="PDF export library not installed.")

    stmt = select(Block).order_by(Block.id.desc())
    rows = db.exec(stmt).all()
    
    data = [["Index","Timestamp","Src IP","Dst IP","Size","Severity","Attack","By","Conf","Host","Country","City","ISP","Hash"]]
    for r in rows[:1000]:
        data.append([
            r.index, r.timestamp, r.src_ip, r.dst_ip, r.size, r.severity, r.attack_type,
            r.detected_by, f"{int(r.ml_confidence*100)}%" if r.detected_by=="ML" else "-",
            r.hostname or "-", r.country or "-", r.city or "-", r.isp or "-", r.hash[:16]+"..."
        ])

    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=20, rightMargin=20, topMargin=20, bottomMargin=20)
    styles = getSampleStyleSheet()
    title = Paragraph("Secure Logs Export", styles["Title"])
    t = Table(data, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1f2937")), ("TEXTCOLOR", (0,0), (-1,0), colors.whitesmoke),
        ("GRID", (0,0), (-1,-1), 0.25, colors.gray), ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,0), 9), ("FONTSIZE", (0,1), (-1,-1), 8),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#0b1220"), colors.HexColor("#0f172a")]),
        ("TEXTCOLOR", (0,1), (-1,-1), colors.whitesmoke), ("ALIGN", (0,0), (-1,-1), "LEFT"),
    ]))
    doc.build([title, Spacer(1,8), t])
    pdf = buf.getvalue()
    buf.close()
    
    return Response(content=pdf, media_type="application/pdf", headers={"Content-Disposition": "attachment; filename=logs.pdf"})

@app.get("/capture")
def capture(mode: str = Query("simulate", enum=["simulate", "real"]), db: DBSession = Depends(get_db)):
    if mode == "simulate":
        packet = {
            "src_ip": f"192.168.1.{random.randint(1, 255)}", "dst_ip": f"10.0.0.{random.randint(1, 255)}",
            "size": random.randint(50, 1500), "timestamp": time.time(),
        }
    elif mode == "real" and SCAPY_OK:
        pkts = sniff(count=1, filter="ip", timeout=2)
        if not pkts: return {"error": "No packet captured"}
        p = pkts[0]
        if IP in p:
            packet = {"src_ip": p[IP].src, "dst_ip": p[IP].dst, "size": len(p), "timestamp": time.time()}
        else:
            return {"error": "No IP layer found"}
    else:
        return {"error": "Real mode not available (Scapy not installed or no privileges)"}

    SRC_HITS[packet["src_ip"]] = SRC_HITS.get(packet["src_ip"], 0) + 1

    features = {"size": float(packet["size"]), "src_tail": float(int(packet["src_ip"].split(".")[-1]))}
    ml_score = ml_anomaly_score(features)
    detected_by = "ML" if ml_score >= 0.6 else "Rule" if packet["size"] > 1200 or SRC_HITS[packet["src_ip"]] >= 5 else "None"
    severity, attack_type = severity_and_attack(packet, ml_score, SRC_HITS)

    host = hostname_of(packet["src_ip"])
    country, city, isp = geo_of(packet["src_ip"])

    flat = {**packet, "severity": severity, "attack_type": attack_type, "detected_by": detected_by, "ml_confidence": ml_score, "hostname": host, "country": country, "city": city, "isp": isp}
    
    last: Optional[Block] = db.exec(select(Block).order_by(Block.id.desc())).first()
    index = (last.index + 1) if last else 0
    ts_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    prev_hash = last.hash if last else "0"

    data_text = json.dumps(flat, sort_keys=True)
    this_hash = calculate_hash(index, ts_str, data_text, prev_hash)
    sig_hex = sign_bytes(bytes.fromhex(this_hash))
    enc = encrypt_json(packet)
    
    row = Block(
        index=index, timestamp=ts_str, previous_hash=prev_hash, hash=this_hash,
        signature_hex=sig_hex, src_ip=packet["src_ip"], dst_ip=packet["dst_ip"],
        size=packet["size"], severity=severity, attack_type=attack_type,
        detected_by=detected_by, ml_confidence=ml_score, hostname=host,
        country=country, city=city, isp=isp, enc_data=enc
    )
    db.add(row)
    db.commit()

    push_rate()

    return {"packet": flat, "block_hash": this_hash}