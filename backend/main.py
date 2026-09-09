from fastapi import FastAPI
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import jwt
from pymongo import MongoClient
from pydantic import BaseModel
from datetime import datetime, timedelta, timezone
from dotenv import load_dotenv
import os
from fastapi.staticfiles import StaticFiles
import uuid
from fastapi import UploadFile, File, HTTPException, Depends
import boto3



load_dotenv()

# -- Config Variables -------------------------------------------------------
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017")
JWT_SECRET = os.getenv("JWT_SECRET", "shield_ai_default_jwt_secret_key_2026")
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("ADMIN_PASS", "admin123")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 600

# -- Linking with MongoDB with MONGO URI from env ---------------------------
try:
    client = MongoClient(MONGO_URI)
    db = client["image_moderation_db"]
    tokens_collection = db["tokens"]
    usages_collection = db["usages"]
except Exception as e:
    print(f"Warning: Mongo init error: {e}")

# -- making instance of an app of FastAPI Init -------------------------------
app = FastAPI()

# -- Mount Static Files for Frontend UI --------------------------------------
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")

app.mount("/ui", StaticFiles(directory=FRONTEND_DIR, html=True), name="static")

# -- Security and AWS Rekognition Client Setup -----------------------------
security = HTTPBearer()
rekognition_client = boto3.client(
    "rekognition",
    region_name=os.getenv("AWS_DEFAULT_REGION", "us-east-1")
)

def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)

# -- Token Verification by decoding it ---------------------------------------------
def verify_token(token: str) -> dict:
    try:
        return jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token Invalid")

# -- Dependency to get current user from token --------------------------------
async def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(security)
):
    token = creds.credentials
    payload = verify_token(token)
    return {"payload": payload, "token": token}


# -- Dependency to ensure admin access ---------------------------------------
async def get_current_admin(user=Depends(get_current_user)):
    token = user["token"]
    rec = tokens_collection.find_one({"token": token})
    if not rec or not rec.get("isAdmin"):
        raise HTTPException(403, "Admin access required")
    return user

class LoginData(BaseModel):
    username: str
    password: str

@app.get("/")
def root():
    return {"message": "Hello from FastAPI"}

# -- Authetnication Endpoints ---------------------------------------------------

@app.post("/auth/login")
async def admin_login(data: LoginData):
    if data.username != ADMIN_USER or data.password != ADMIN_PASS:
        raise HTTPException(status_code=401, detail="Invalid Credentials")
    
    # Issue a fresh admin JWT
    token = create_access_token({"sub": data.username, "isAdmin": True})
    try:
        if 'tokens_collection' in globals():
            tokens_collection.delete_many({"isAdmin": True})
            tokens_collection.insert_one({
                "token": token, 
                "isAdmin": True, 
                "createdAt": datetime.now(timezone.utc)
            })
    except Exception as e:
        print(f"DB warning on admin login: {e}")
    return {"token": token}

@app.post("/auth/tokens/guest")
async def create_guest_token():
    """Public endpoint: Allows website visitors to instantly get a session token without admin intervention."""
    payload = {"id": str(uuid.uuid4()), "isAdmin": False, "role": "guest"}
    token = create_access_token(payload)
    try:
        if 'tokens_collection' in globals():
            tokens_collection.insert_one({
                "token": token,
                "isAdmin": False,
                "role": "guest",
                "createdAt": datetime.now(timezone.utc)
            })
    except Exception as e:
        print(f"DB warning on guest token creation: {e}")
    return {"token": token}

@app.post("/auth/tokens")
async def create_token(is_admin: bool = False, admin=Depends(get_current_admin)):
    role = "admin" if is_admin else "user"
    payload = {"id": str(uuid.uuid4()), "isAdmin": is_admin, "role": role}
    token = create_access_token(payload)
    try:
        if 'tokens_collection' in globals():
            tokens_collection.insert_one({
                "token": token,
                "isAdmin": is_admin,
                "role": role,
                "createdAt": datetime.now(timezone.utc)
            })
    except Exception as e:
        print(f"DB warning on token creation: {e}")
    return {"token": token}

@app.get("/auth/tokens")
async def list_tokens(admin=Depends(get_current_admin)):
    try:
        if 'tokens_collection' in globals():
            return list(tokens_collection.find({"isAdmin": False}, {"_id": 0, "token": 1, "role": 1, "createdAt": 1}))
    except Exception as e:
        print(f"DB warning on list tokens: {e}")
    return []

@app.get("/admin/stats")
async def get_admin_stats(admin=Depends(get_current_admin)):
    try:
        if 'tokens_collection' in globals() and 'usages_collection' in globals():
            total_user_tokens = tokens_collection.count_documents({"isAdmin": False})
            total_api_calls  = usages_collection.count_documents({})
            guest_tokens = tokens_collection.count_documents({"isAdmin": False, "role": "guest"})
            named_tokens = tokens_collection.count_documents({"isAdmin": False, "role": "user"})
            return {
                "total_user_tokens": total_user_tokens,
                "guest_tokens": guest_tokens,
                "named_user_tokens": named_tokens,
                "total_api_calls": total_api_calls,
            }
    except Exception as e:
        print(f"DB warning on stats: {e}")
    return {"total_user_tokens": 0, "guest_tokens": 0, "named_user_tokens": 0, "total_api_calls": 0}

@app.delete("/auth/tokens/purge")
async def purge_tokens(admin=Depends(get_current_admin)):
    current_admin_token = admin["token"]
    try:
        if 'tokens_collection' in globals():
            res = tokens_collection.delete_many({"token": {"$ne": current_admin_token}})
            return {"message": f"Purged {res.deleted_count} old tokens"}
    except Exception as e:
        print(f"DB warning on purge: {e}")
    return {"message": "Purged 0 old tokens"}

@app.delete("/auth/tokens/{token_str}")
async def delete_token(token_str: str, admin=Depends(get_current_admin)):
    try:
        if 'tokens_collection' in globals():
            res = tokens_collection.delete_one({"token": token_str})
            if res.deleted_count == 0:
                raise HTTPException(status_code=404, detail="Token not found")
            return {"message": "Token deleted"}
    except HTTPException:
        raise
    except Exception as e:
        print(f"DB warning on delete token: {e}")
    return {"message": "Token deleted"}

@app.post("/auth/verify")
async def verify_auth(user=Depends(get_current_user)):
    return {
        "valid": True,
        "isAdmin": user["payload"].get("isAdmin", False)
    }

# -- Image Moderation Endpoint ------------------------------------------------
@app.post("/moderate")
async def moderate(
    file: UploadFile = File(...),
    user=Depends(get_current_user)
):
    if not file.filename:
        raise HTTPException(status_code=400, detail="No file uploaded")
    
    image = await file.read()

    # Log usage safely without blocking on DB errors
    try:
        if 'usages_collection' in globals():
            usages_collection.insert_one({
                "token": user["token"],
                "endpoint": "/moderate",
                "timestamp": datetime.now(timezone.utc)
            })
    except Exception as db_err:
        print(f"Non-fatal usage log error: {db_err}")

    # Check AWS configuration
    aws_key = os.getenv("AWS_ACCESS_KEY_ID")
    aws_secret = os.getenv("AWS_SECRET_ACCESS_KEY")
    if not aws_key or not aws_secret:
        raise HTTPException(
            status_code=500,
            detail="AWS credentials not configured on Vercel. Please add AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY to Environment Variables on Vercel dashboard."
        )

    try:
        resp = rekognition_client.detect_moderation_labels(
            Image={"Bytes": image}, MinConfidence=60
        )
        labels = resp.get("ModerationLabels", [])
        if not labels:
            return {"filename": file.filename, "status": "safe"}
        return {
            "filename": file.filename,
            "status": "unsafe",
            "labels": [
                {"name": L["Name"], "confidence": L["Confidence"]}
                for L in labels
            ]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AWS Rekognition Error: {str(e)}")
