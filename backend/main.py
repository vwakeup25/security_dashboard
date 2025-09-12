import os, json, time, hashlib, socket, random
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, Query, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from dotenv import load_dotenv

from sqlmodel import SQLModel, Field, Session, create_engine, select
from sqlalchemy.orm import sessionmaker

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
import logging
from pythonjsonlogger import jsonlogger
from fastapi import FastAPI # Or your other imports
app = FastAPI()

# =================== ADD THIS LOGGING SETUP CODE ===================
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logHandler = logging.FileHandler("app_security_local.log")
formatter = jsonlogger.JsonFormatter('%(asctime)s %(levelname)s %(message)s')
logHandler.setFormatter(formatter)
logger.addHandler(logHandler)
# ===================================================================

# Optional libs (best-effort)
try:
    from river import anomaly
    RIVER_OK = True
except Exception:
    RIVER_OK = False

try:
    from scapy.all import sniff, IP
    SCAPY_OK = True
except Exception:
    SCAPY_OK = False

try:
    import geoip2.database
    GEO_OK = True
except Exception:
    GEO_OK = False

# ------------------- Env & setup -------------------
load_dotenv()

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", "8000"))
CORS_ORIGINS = os.getenv("CORS_ORIGINS", "*")

JWT_SECRET = os.getenv("JWT_SECRET", "dev_secret_change_me")
JWT_ALGO = os.getenv("JWT_ALGO", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = 12 * 60

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "admin123")

DB_URL = os.getenv("DATABASE_URL", "sqlite:///./secure_logs.db")
FERNET_KEY_PATH = os.getenv("FERNET_KEY_PATH", "fernet.key")
ED25519_PRIV_PATH = os.getenv("ED25519_PRIV_PATH", "ed25519_private.key")
ED25519_PUB_PATH = os.getenv("ED25519_PUB_PATH", "ed25519_public.key")
GEOLITE_DB = os.getenv("GEOLITE_DB", "GeoLite2-City.mmdb")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Database
engine = create_engine(DB_URL, connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Fernet
with open(FERNET_KEY_PATH, "rb") as f:
    FERNET = Fernet(f.read())

# Ed25519 keys
with open(ED25519_PRIV_PATH, "rb") as f:
    PRIV_KEY = serialization.load_pem_private_key(f.read(), password=None)
with open(ED25519_PUB_PATH, "rb") as f:
    PUB_KEY = serialization.load_pem_public_key(f.read())

# GeoIP reader (optional)
GEO_READER = None
if GEO_OK and os.path.exists(GEOLITE_DB):
    try:
        GEO_READER = geoip2.database.Reader(GEOLITE_DB)
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

    # Flattened quick fields (not encrypted) for indexing/filtering
    src_ip: str
    dst_ip: str
    size: int
    severity: str
    attack_type: str
    detected_by: str
    ml_confidence: float

    # Geo/meta (optional)
    hostname: Optional[str] = None
    country: Optional[str] = None
    city: Optional[str] = None
    isp: Optional[str] = None

    # Encrypted packet json
    enc_data: bytes

class LogsResponse(BaseModel):
    items: List[dict]
    page: int
    pages: int
    total: int

# Create DB
SQLModel.metadata.create_all(engine)

# ------------------- Auth -------------------
def verify_password(plain, expected):
    # simple compare for demo; swap to hashed if you want stored hash
    return plain == expected

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGO)

def get_current_user(token: str = Depends(lambda: None)):
    # Simple Bearer parser
    from fastapi import Request
    async def inner(request: Request):
        auth: str = request.headers.get("Authorization", "")
        if not auth.lower().startswith("bearer "):
            raise HTTPException(status_code=401, detail="Missing bearer token")
        token = auth.split(" ", 1)[1]
        try:
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])
            sub: str = payload.get("sub")
            if sub != ADMIN_USER:
                raise HTTPException(status_code=401, detail="Invalid user")
            return sub
        except JWTError:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
    return inner

# ------------------- App -------------------
app = FastAPI(title="Smart Security Dashboard (Secure)")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[CORS_ORIGINS] if CORS_ORIGINS != "*" else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ------------------- Helpers -------------------
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
    # Private/local ranges: skip
    if ip.startswith(("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                      "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                      "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                      "172.30.", "172.31.", "127.", "0.", "169.254.")):
        return (None, None, None)
    if GEO_READER:
        try:
            r = GEO_READER.city(ip)
            country = r.country.name or None
            city = r.city.name or None
            isp = None  # Needs GeoLite2-ASN for ISP; left None or integrate ASN DB
            return (country, city, isp)
        except Exception:
            return (None, None, None)
    return (None, None, None)

# Packet rate
RATE_WINDOW = 30
_rate_times: List[float] = []

def push_rate():
    now = time.time()
    _rate_times.append(now)
    # keep last RATE_WINDOW seconds
    cutoff = now - RATE_WINDOW
    while _rate_times and _rate_times[0] < cutoff:
        _rate_times.pop(0)

def current_rate():
    if len(_rate_times) < 2:
        return 0.0
    span = _rate_times[-1] - _rate_times[0]
    return (len(_rate_times) - 1) / span if span > 0 else 0.0

def rate_history():
    # simple downsample: 10 buckets over last window
    now = time.time()
    cutoff = now - RATE_WINDOW
    pts = [t for t in _rate_times if t >= cutoff]
    if not pts:
        return []
    buckets = 10
    width = RATE_WINDOW / buckets
    hist = []
    for i in range(buckets):
        start = cutoff + i * width
        end = start + width
        count = sum(1 for t in pts if start <= t < end)
        hist.append({"ts": int(start), "count": count})
    return hist

# ML anomaly (online)
if RIVER_OK:
    # Half-Space Trees is streaming anomaly detector
    HST = anomaly.HalfSpaceTrees(seed=42)
else:
    HST = None

def ml_anomaly_score(x: dict) -> float:
    """
    Returns 0..1 score (normalized) – higher = more anomalous.
    """
    if not HST:
        return 0.0
    try:
        # River scores are unbounded; clamp a simple logistic-ish transform
        s = HST.score_one(x)
        HST.learn_one(x)
        # naive squash for UI: score ~[0,1]
        norm = 1 - (1 / (1 + s))
        return max(0.0, min(1.0, norm))
    except Exception:
        return 0.0

def severity_and_attack(packet, ml_score: float, ip_counts: dict):
    # rule+ml fusion → severity
    size = packet["size"]
    src = packet["src_ip"]
    # repeated source?
    hits = ip_counts.get(src, 0)

    # Attack type
    attack = "Normal"
    if size > 1200:
        attack = "Possible DDoS"
    elif hits >= 5:
        attack = "Suspicious Host"
    elif ml_score >= 0.75:
        attack = "Unknown Attack (AI Flagged)"
    elif size > 1000:
        attack = "Large Packet"

    # Severity
    if attack in ("Possible DDoS",) or ml_score >= 0.9 or size > 1400:
        sev = "High"
    elif attack in ("Suspicious Host",) or ml_score >= 0.75 or size > 1200:
        sev = "Medium"
    elif attack in ("Large Packet",) or ml_score >= 0.6 or size > 1000:
        sev = "Low"
    else:
        sev = "Normal"

    return sev, attack

# simple memory counter for src frequencies
SRC_HITS = {}

# ------------------- Routes -------------------
@app.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends()):
    if form.username != ADMIN_USER or not verify_password(form.password, ADMIN_PASS):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token({"sub": ADMIN_USER})
    return {"access_token": token, "token_type": "bearer"}

@app.get("/")
def root():
    return {"message": "🚀 Secure Smart Security Dashboard Backend is running"}

@app.get("/packet_rate")
def packet_rate():
    return {"rate": current_rate(), "history": rate_history()}

@app.get("/logs", response_model=LogsResponse)
def logs(page: int = 1,
         limit: int = 25,
         type: str = "All",
         severity: str = "All",
         user: str = Depends(get_current_user())):
    page = max(1, page)
    limit = max(1, min(200, limit))
    with Session(engine) as s:
        stmt = select(Block).order_by(Block.id.desc())
        rows = s.exec(stmt).all()

        # filtering
        def keep(r: Block):
            if severity != "All" and r.severity != severity:
                return False
            if type != "All" and r.attack_type != type:
                return False
            return True

        rows = [r for r in rows if keep(r)]
        total = len(rows)
        pages = max(1, (total + limit - 1) // limit)
        start = (page - 1) * limit
        page_rows = rows[start:start + limit]

        items = []
        for r in page_rows:
            items.append({
                "index": r.index,
                "timestamp": r.timestamp,
                "src_ip": r.src_ip,
                "dst_ip": r.dst_ip,
                "size": r.size,
                "severity": r.severity,
                "attack_type": r.attack_type,
                "detected_by": r.detected_by,
                "ml_confidence": r.ml_confidence,
                "hostname": r.hostname,
                "country": r.country,
                "city": r.city,
                "isp": r.isp,
                "hash": r.hash,
                "signature_ok": verify_signature(bytes.fromhex(r.hash), r.signature_hex)
            })
        return {"items": items, "page": page, "pages": pages, "total": total}

@app.post("/reset")
def reset(user: str = Depends(get_current_user())):
    with Session(engine) as s:
        s.exec("DELETE FROM block")
        s.commit()
    SRC_HITS.clear()
    _rate_times.clear()
    return {"ok": True}

# PDF export
@app.get("/export")
def export(format: str = Query("pdf"), user: str = Depends(get_current_user())):
    if format.lower() != "pdf":
        raise HTTPException(status_code=400, detail="Only PDF export is enabled.")
    # generate simple PDF table with reportlab
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet

    with Session(engine) as s:
        stmt = select(Block).order_by(Block.id.desc())
        rows = s.exec(stmt).all()

    data = [["Index","Timestamp","Src IP","Dst IP","Size","Severity","Attack","By","Conf","Host","Country","City","ISP","Hash"]]
    for r in rows[:1000]:  # cap to 1000 rows for PDF
        data.append([
            r.index, r.timestamp, r.src_ip, r.dst_ip, r.size, r.severity, r.attack_type,
            r.detected_by, f"{int(r.ml_confidence*100)}%" if r.detected_by=="ML" else "-",
            r.hostname or "-", r.country or "-", r.city or "-", r.isp or "-", r.hash[:16]+"..."
        ])

    from io import BytesIO
    buf = BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=landscape(A4), leftMargin=20, rightMargin=20, topMargin=20, bottomMargin=20)
    styles = getSampleStyleSheet()
    title = Paragraph("Secure Logs Export", styles["Title"])
    t = Table(data, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0,0), (-1,0), colors.whitesmoke),
        ("GRID", (0,0), (-1,-1), 0.25, colors.gray),
        ("FONTNAME", (0,0), (-1,0), "Helvetica-Bold"),
        ("FONTSIZE", (0,0), (-1,0), 9),
        ("FONTSIZE", (0,1), (-1,-1), 8),
        ("ROWBACKGROUNDS", (0,1), (-1,-1), [colors.HexColor("#0b1220"), colors.HexColor("#0f172a")]),
        ("TEXTCOLOR", (0,1), (-1,-1), colors.whitesmoke),
        ("ALIGN", (0,0), (-1,-1), "LEFT"),
    ]))
    doc.build([title, Spacer(1,8), t])
    pdf = buf.getvalue()
    buf.close()
    return Response(content=pdf, media_type="application/pdf", headers={
        "Content-Disposition": "attachment; filename=logs.pdf"
    })

@app.get("/capture")
def capture(mode: str = Query("simulate", enum=["simulate", "real"])):
    """
    Public (no auth): UI polls this frequently.
    Writes encrypted, signed block into DB.
    """
    # ----------- capture packet -----------
    if mode == "simulate":
        packet = {
            "src_ip": f"192.168.1.{random.randint(1, 255)}",
            "dst_ip": f"10.0.0.{random.randint(1, 255)}",
            "size": random.randint(50, 1500),
            "timestamp": time.time(),
        }
    elif mode == "real" and SCAPY_OK:
        pkts = sniff(count=1, filter="ip", timeout=2)
        if not pkts:
            return {"error": "No packet captured"}
        p = pkts[0]
        if IP in p:
            packet = {
                "src_ip": p[IP].src,
                "dst_ip": p[IP].dst,
                "size": len(p),
                "timestamp": time.time(),
            }
        else:
            return {"error": "No IP layer found"}
    else:
        return {"error": "Real mode not available (Scapy not installed or no privileges)"}

    # ----------- enrich & score -----------
    SRC_HITS[packet["src_ip"]] = SRC_HITS.get(packet["src_ip"], 0) + 1

    features = {
        "size": float(packet["size"]),
        "src_tail": float(int(packet["src_ip"].split(".")[-1])),
    }
    ml_score = ml_anomaly_score(features)  # 0..1
    detected_by = "ML" if ml_score >= 0.6 else "Rule" if packet["size"] > 1200 or SRC_HITS[packet["src_ip"]] >= 5 else "None"
    severity, attack_type = severity_and_attack(packet, ml_score, SRC_HITS)

    host = hostname_of(packet["src_ip"])
    country, city, isp = geo_of(packet["src_ip"])

    # ----------- blockchain block -----------
    # flatten-for-hash
    flat = {
        "src_ip": packet["src_ip"],
        "dst_ip": packet["dst_ip"],
        "size": packet["size"],
        "timestamp": packet["timestamp"],
        "severity": severity,
        "attack_type": attack_type,
        "detected_by": detected_by,
        "ml_confidence": ml_score,
        "hostname": host,
        "country": country,
        "city": city,
        "isp": isp
    }

    with Session(engine) as s:
        last: Optional[Block] = s.exec(select(Block).order_by(Block.id.desc())).first()
        index = (last.index + 1) if last else 0
        ts_str = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        prev_hash = last.hash if last else "0"

        # data to sign/hash
        data_text = json.dumps(flat, sort_keys=True)
        this_hash = calculate_hash(index, ts_str, data_text, prev_hash)
        sig_hex = sign_bytes(bytes.fromhex(this_hash))

        enc = encrypt_json(packet)  # raw packet JSON encrypted

        row = Block(
            index=index,
            timestamp=ts_str,
            previous_hash=prev_hash,
            hash=this_hash,
            signature_hex=sig_hex,
            src_ip=packet["src_ip"],
            dst_ip=packet["dst_ip"],
            size=packet["size"],
            severity=severity,
            attack_type=attack_type,
            detected_by=detected_by,
            ml_confidence=ml_score,
            hostname=host,
            country=country,
            city=city,
            isp=isp,
            enc_data=enc
        )
        s.add(row)
        s.commit()

    push_rate()

    return {
        "packet": {
            **packet,
            "severity": severity,
            "attack_type": attack_type,
            "detected_by": detected_by,
            "ml_confidence": ml_score
        },
        "block_hash": this_hash
    }



















