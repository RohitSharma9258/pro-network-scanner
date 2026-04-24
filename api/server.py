import time
import asyncio
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Set, Any

from fastapi import FastAPI, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
import jwt

from core.config import Config
from core.database import VanguardDatabase
from core.exceptions import AuthError

app = FastAPI(
    title="Vanguard Titan Security Hardened API", 
    version="12.6",
    description="Maximum Security Recon API with Persistent Revocation and HTTPS Enforcement"
)

# Global instances initialized lazily to avoid loop errors at import time
_db = None
_shared_state_lock = None

def get_db():
    global _db
    if _db is None:
        _db = VanguardDatabase()
    return _db

def get_lock():
    global _shared_state_lock
    if _shared_state_lock is None:
        _shared_state_lock = asyncio.Lock()
    return _shared_state_lock

pwd_context = CryptContext(
    schemes=["bcrypt"], 
    deprecated="auto",
    bcrypt__rounds=Config.BCRYPT_ROUNDS
)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Security State (Volatile) ---
rate_limit_data: Dict[str, List[float]] = {}
login_attempts: Dict[str, List[float]] = {}
shared_state: Dict[str, Any] = {"results": {}}

# --- Security Helpers ---

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    return jwt.encode(to_encode, Config.JWT_SECRET_KEY, algorithm=Config.ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme)):
    db = get_db()
    if db.is_token_revoked(token):
        raise HTTPException(status_code=401, detail="Token revoked")
        
    try:
        payload = jwt.decode(token, Config.JWT_SECRET_KEY, algorithms=[Config.ALGORITHM])
        username: str = payload.get("sub")
        if username != Config.API_USER:
            raise AuthError("Invalid user context")
        return username
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token signature")

# --- Middleware ---

@app.middleware("http")
async def security_middleware(request: Request, call_next):
    if Config.ENV == "production":
        forwarded_proto = request.headers.get("X-Forwarded-Proto", "http")
        if forwarded_proto != "https" and request.url.scheme != "https":
            return HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, 
                detail="HTTPS Connection Required"
            )

    client_ip = request.client.host
    current_time = time.time()
    
    rate_limit_data.setdefault(client_ip, [])
    rate_limit_data[client_ip] = [t for t in rate_limit_data[client_ip] if current_time - t < 60]
    
    if len(rate_limit_data[client_ip]) > 100:
        raise HTTPException(status_code=429, detail="API rate limit exceeded")
    
    rate_limit_data[client_ip].append(current_time)
    
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["X-Frame-Options"] = "DENY"
    return response

# --- Endpoints ---

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

@app.post("/token", response_model=TokenResponse)
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    if form_data.username != Config.API_USER or not verify_password(form_data.password, get_password_hash(Config.API_PASSWORD_RAW)):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    access = create_token({"sub": form_data.username, "type": "access"}, timedelta(minutes=Config.ACCESS_TOKEN_EXPIRE_MINUTES))
    refresh = create_token({"sub": form_data.username, "type": "refresh"}, timedelta(days=Config.REFRESH_TOKEN_EXPIRE_DAYS))
    
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer"}

@app.post("/logout")
async def logout(token: str = Depends(oauth2_scheme)):
    get_db().revoke_token(token)
    return {"detail": "Logged out and token revoked"}

@app.get("/api/v1/scan/current")
async def get_current(user: str = Depends(get_current_user)):
    lock = get_lock()
    async with lock:
        return shared_state["results"]

@app.get("/api/v1/health")
async def health():
    return {
        "status": "operational", 
        "version": "12.6-Hardened",
        "https_enforced": Config.ENV == "production"
    }
