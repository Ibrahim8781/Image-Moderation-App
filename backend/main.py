from fastapi import FastAPI, UploadFile, File, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from pymongo import MongoClient
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import os
import uuid
import boto3

load_dotenv()

# -- Config Variables -------------------------------------------------------
MONGO_URI   = os.getenv("MONGO_URI",   "mongodb://localhost:27017")
JWT_SECRET  = os.getenv("JWT_SECRET",  "shield_ai_default_jwt_secret_key_2026")
ADMIN_USER  = os.getenv("ADMIN_USER",  "admin")
ADMIN_PASS  = os.getenv("ADMIN_PASS",  "admin123")
ALGORITHM   = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 600

# -- MongoDB ----------------------------------------------------------------
_db_ok = False
try:
    _client          = MongoClient(MONGO_URI, serverSelectionTimeoutMS=4000)
    _db              = _client["image_moderation_db"]
    tokens_collection = _db["tokens"]
    usages_collection = _db["usages"]
    _db_ok = True
except Exception as _e:
    print(f"Warning: MongoDB unavailable – running without DB: {_e}")

# -- FastAPI app ------------------------------------------------------------
app = FastAPI()

# -- AWS Rekognition client ------------------------------------------------
rekognition_client = boto3.client(
    "rekognition",
    region_name=os.getenv("AWS_DEFAULT_REGION", "us-east-1")
)

# -- JWT helpers -----------------------------------------------------------
def create_access_token(data: dict) -> str:
    payload = data.copy()
    payload["exp"] = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    return jwt.encode(payload, JWT_SECRET, algorithm=ALGORITHM)

def verify_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token invalid")

security = HTTPBearer()

async def get_current_user(creds: HTTPAuthorizationCredentials = Depends(security)):
    payload = verify_token(creds.credentials)
    return {"payload": payload, "token": creds.credentials}

async def get_current_admin(user=Depends(get_current_user)):
    if not _db_ok:
        raise HTTPException(503, "Database unavailable")
    rec = tokens_collection.find_one({"token": user["token"]})
    if not rec or not rec.get("isAdmin"):
        raise HTTPException(403, "Admin access required")
    return user

class LoginData(BaseModel):
    username: str
    password: str

# ── Routes ────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return {"status": "online", "service": "ShieldAI Image Moderation API"}

# ── Auth ──────────────────────────────────────────────────────────────────

@app.post("/auth/login")
async def admin_login(data: LoginData):
    if data.username != ADMIN_USER or data.password != ADMIN_PASS:
        raise HTTPException(401, "Invalid credentials")
    token = create_access_token({"sub": data.username, "isAdmin": True})
    if _db_ok:
        try:
            tokens_collection.delete_many({"isAdmin": True})
            tokens_collection.insert_one({"token": token, "isAdmin": True, "createdAt": datetime.now(timezone.utc)})
        except Exception as e:
            print(f"DB warning: {e}")
    return {"token": token}

@app.post("/auth/tokens/guest")
async def create_guest_token():
    token = create_access_token({"id": str(uuid.uuid4()), "isAdmin": False, "role": "guest"})
    if _db_ok:
        try:
            tokens_collection.insert_one({"token": token, "isAdmin": False, "role": "guest", "createdAt": datetime.now(timezone.utc)})
        except Exception as e:
            print(f"DB warning: {e}")
    return {"token": token}

@app.post("/auth/tokens")
async def create_token(is_admin: bool = False, admin=Depends(get_current_admin)):
    role = "admin" if is_admin else "user"
    token = create_access_token({"id": str(uuid.uuid4()), "isAdmin": is_admin, "role": role})
    if _db_ok:
        try:
            tokens_collection.insert_one({"token": token, "isAdmin": is_admin, "role": role, "createdAt": datetime.now(timezone.utc)})
        except Exception as e:
            print(f"DB warning: {e}")
    return {"token": token}

@app.get("/auth/tokens")
async def list_tokens(admin=Depends(get_current_admin)):
    if not _db_ok:
        return []
    try:
        return list(tokens_collection.find({"isAdmin": False}, {"_id": 0, "token": 1, "role": 1, "createdAt": 1}))
    except Exception as e:
        print(f"DB warning: {e}")
        return []

@app.post("/auth/verify")
async def verify_auth(user=Depends(get_current_user)):
    return {"valid": True, "isAdmin": user["payload"].get("isAdmin", False)}

# ── Admin ─────────────────────────────────────────────────────────────────

@app.get("/admin/stats")
async def get_admin_stats(admin=Depends(get_current_admin)):
    if not _db_ok:
        return {"total_user_tokens": 0, "guest_tokens": 0, "named_user_tokens": 0, "total_api_calls": 0}
    try:
        return {
            "total_user_tokens": tokens_collection.count_documents({"isAdmin": False}),
            "guest_tokens":      tokens_collection.count_documents({"isAdmin": False, "role": "guest"}),
            "named_user_tokens": tokens_collection.count_documents({"isAdmin": False, "role": "user"}),
            "total_api_calls":   usages_collection.count_documents({}),
        }
    except Exception as e:
        print(f"DB warning: {e}")
        return {"total_user_tokens": 0, "guest_tokens": 0, "named_user_tokens": 0, "total_api_calls": 0}

@app.delete("/auth/tokens/purge")
async def purge_tokens(admin=Depends(get_current_admin)):
    if not _db_ok:
        return {"message": "Purged 0 old tokens"}
    try:
        res = tokens_collection.delete_many({"token": {"$ne": admin["token"]}})
        return {"message": f"Purged {res.deleted_count} old tokens"}
    except Exception as e:
        print(f"DB warning: {e}")
        return {"message": "Purged 0 old tokens"}

@app.delete("/auth/tokens/{token_str}")
async def delete_token(token_str: str, admin=Depends(get_current_admin)):
    if not _db_ok:
        raise HTTPException(503, "Database unavailable")
    try:
        res = tokens_collection.delete_one({"token": token_str})
        if res.deleted_count == 0:
            raise HTTPException(404, "Token not found")
        return {"message": "Token deleted"}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(500, str(e))

# ── Image Moderation ──────────────────────────────────────────────────────

@app.post("/moderate")
async def moderate(file: UploadFile = File(...), user=Depends(get_current_user)):
    if not file.filename:
        raise HTTPException(400, "No file uploaded")

    image = await file.read()

    # Non-blocking usage log
    if _db_ok:
        try:
            usages_collection.insert_one({
                "token": user["token"],
                "endpoint": "/moderate",
                "timestamp": datetime.now(timezone.utc)
            })
        except Exception:
            pass

    # Validate AWS credentials
    if not os.getenv("AWS_ACCESS_KEY_ID") or not os.getenv("AWS_SECRET_ACCESS_KEY"):
        raise HTTPException(500, "AWS credentials not configured. Add AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY in Vercel → Settings → Environment Variables.")

    try:
        resp   = rekognition_client.detect_moderation_labels(Image={"Bytes": image}, MinConfidence=60)
        labels = resp.get("ModerationLabels", [])
        if not labels:
            return {"filename": file.filename, "status": "safe"}
        return {
            "filename": file.filename,
            "status": "unsafe",
            "labels": [{"name": L["Name"], "confidence": L["Confidence"]} for L in labels]
        }
    except Exception as e:
        raise HTTPException(500, f"AWS Rekognition error: {str(e)}")
