import datetime
import uuid
import httpx
import jwt
from fastapi import APIRouter, HTTPException, Depends, Query, Request, Response
from fastapi.responses import RedirectResponse, JSONResponse
import json
import re
from pydantic import BaseModel, EmailStr, field_validator
from typing import Optional, List
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from icecream import ic

# Cryptography imports for RSA key generation
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

from core.configs.settings_config import SETTINGS
from infras.db.mongo import get_collection
from dotenv import load_dotenv
load_dotenv()
from hyperlocal_platform.infras.redis.main import redis_client

router = APIRouter(prefix="/auth", tags=["Authentication"])
ph = PasswordHasher()

# JWT Config
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Pydantic Schemas
class GenerateKeySchema(BaseModel):
    version: str

class CallbackSchema(BaseModel):
    token_id: str
    service: str
    version: Optional[str] = "1"

class RefreshSchema(BaseModel):
    refresh_token: str
    version: Optional[str] = "1"

class RevokeSchema(BaseModel):
    token: str

class UserCreateManualSchema(BaseModel):
    user_id: Optional[str] = None
    email: EmailStr
    mobilenumber: str
    password: str
    two_factor: bool = False

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v):
        if isinstance(v, str):
            return v.strip().lower()
        return v

class LoginRequestSchema(BaseModel):
    email: Optional[str] = None
    mobilenumber: Optional[str] = None
    password: str
    service: Optional[str] = "HYPERLOCAL"
    version: Optional[str] = "1"
    entity_name: Optional[str] = None
    entity_type: Optional[str] = None

class UserResponseSchema(BaseModel):
    user_id: str
    email: Optional[str] = None
    mobilenumber: Optional[str] = None
    two_factor: bool

class ForgotPasswordSchema(BaseModel):
    email: Optional[str] = None
    mobilenumber: Optional[str] = None

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v):
        if isinstance(v, str) and v.strip():
            return v.strip().lower()
        return v

class ResetPasswordSchema(BaseModel):
    reset_token: Optional[str] = None
    email: Optional[str] = None
    mobilenumber: Optional[str] = None
    user_id: Optional[str] = None
    new_password: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v):
        if isinstance(v, str) and v.strip():
            return v.strip().lower()
        return v

class ChangePasswordSchema(BaseModel):
    email: Optional[str] = None
    mobilenumber: Optional[str] = None
    user_id: Optional[str] = None
    old_password: str
    new_password: str

    @field_validator("email")
    @classmethod
    def normalize_email(cls, v):
        if isinstance(v, str) and v.strip():
            return v.strip().lower()
        return v



# DAUTH_BASE_URL="https://api.dauth.debuggerstechnologies.com"
DAUTH_BASE_URL="http://127.0.0.1:9000"

# Helpers
def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    return private_pem, public_pem

async def get_keys_for_version(version: str):
    keys_coll = get_collection("keys")
    key_doc = await keys_coll.find_one({"version": version})
    if not key_doc:
        raise HTTPException(status_code=404, detail=f"RSA keys version '{version}' not found.")
    return key_doc["private_key"], key_doc["public_key"]


# Auth Endpoints

@router.post("/keys/generate")
async def generate_keys(data: GenerateKeySchema):
    keys_coll = get_collection("keys")
    existing = await keys_coll.find_one({"version": data.version})
    if existing:
        raise HTTPException(status_code=400, detail=f"Key version '{data.version}' already exists.")
    
    private_pem, public_pem = generate_rsa_keypair()
    await keys_coll.insert_one({
        "version": data.version,
        "private_key": private_pem,
        "public_key": public_pem,
        "created_at": datetime.datetime.utcnow()
    })
    return {"message": f"Successfully generated key pair version '{data.version}'."}

@router.get("/keys/{version}")
async def get_public_key(version: str):
    _, public_key = await get_keys_for_version(version)
    return {"version": version, "public_key": public_key}

@router.get("/login-url")
async def get_login_url(
    response: Response,
    service: str = Query(...),
    version: Optional[str] = Query("1"),
    entity_name: Optional[str] = Query(None),
    entity_type: Optional[str] = Query(None),
    redirect_url: Optional[str] = Query(None)
):
    # Connects to Debugger Auth
    constructed_url = f"{DAUTH_BASE_URL}/auth"
    payload = {
        "apikey": SETTINGS.DEB_APIKEY,
        "additional_infos": {
            "entity_name": entity_name,
            "entity_type": entity_type,
            "redirect_url": redirect_url,
            "service": service,
            "version": version
        }
    }
    async with httpx.AsyncClient(timeout=30) as client:
        response_data = await client.post(
            constructed_url,
            json=payload
        )

        ic(response_data.text)
    
    if response_data.status_code != 200:
        raise HTTPException(
            status_code=response_data.status_code,
            detail="Failed to fetch login URLs from Debugger Auth"
        )
    
    res = response_data.json()
    # Set the cookie with service and version info
    state_val = json.dumps({
        "service": service,
        "version": version,
        "entity_name": entity_name,
        "entity_type": entity_type,
        "redirect_url": redirect_url
    })
    response.set_cookie(key="oauth_state", value=state_val, max_age=900, samesite="lax")
    return res

@router.post("/callback/verify")
async def callback_verify(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    ic("callback/verify request received:", body)
    
    flow_type = body.get("flow_type", "signin")
    auth_provider = body.get("auth_provider", "password")
    raw_email = body.get("email")
    email = raw_email.strip().lower() if isinstance(raw_email, str) and raw_email.strip() else None
    mobilenumber = body.get("mobile_number") or body.get("mobilenumber") or body.get("phone")
    if isinstance(mobilenumber, str):
        mobilenumber = mobilenumber.strip()
    password = body.get("password")
    
    users_coll = get_collection("users")
    query_or = []
    if email:
        query_or.append({"email": email})
        query_or.append({"email": {"$regex": f"^{re.escape(email)}$", "$options": "i"}})
    if mobilenumber:
        query_or.append({"mobilenumber": mobilenumber})
        
    user_doc = await users_coll.find_one({"$or": query_or}) if query_or else None
    
    # 1. Signin Verification
    if flow_type == "signin":
        if not user_doc:
            return JSONResponse(
                status_code=401,
                content={
                    "message": "Account not found with this email or mobile number.",
                    "status_code": 401,
                    "success": False
                }
            )
            
        if auth_provider == "password" and password:
            stored_pwd = user_doc.get("password")
            has_custom_pwd = user_doc.get("has_custom_password", False)
            
            if stored_pwd and has_custom_pwd:
                try:
                    ph.verify(stored_pwd, password)
                except Exception:
                    return JSONResponse(
                        status_code=401,
                        content={
                            "message": "Incorrect password. Please check your credentials.",
                            "status_code": 401,
                            "success": False
                        }
                    )
                    
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "message": "Verification successful.",
                "user_id": user_doc.get("user_id"),
                "email": user_doc.get("email"),
                "mobilenumber": user_doc.get("mobilenumber")
            }
        )
        
    # 2. Signup Verification
    elif flow_type == "signup":
        if user_doc:
            return JSONResponse(
                status_code=409,
                content={
                    "message": "An account with this email or mobile number already exists.",
                    "status_code": 409,
                    "success": False
                }
            )
        return JSONResponse(
            status_code=200,
            content={
                "success": True,
                "message": "Verification successful. New user allowed to register."
            }
        )
        
    # 3. Default fallback
    return JSONResponse(
        status_code=200,
        content={
            "success": True,
            "message": "Verification successful."
        }
    )

        
@router.get("/callback")
async def callback(
    request: Request,
    token_id: Optional[str] = Query(None),
    error: Optional[str] = Query(None),
    status_code: Optional[int] = Query(None),
    service: Optional[str] = Query(None),
    version: Optional[str] = Query(None)
):
    # If error parameter is present from DAuth failure redirect
    if error:
        cookie_state = request.cookies.get("oauth_state")
        redirect_url_param = None
        if cookie_state:
            try:
                state_data = json.loads(cookie_state)
                redirect_url_param = state_data.get("redirect_url")
            except Exception:
                pass
        base_redirect_url = redirect_url_param or f"{SETTINGS.FRONTEND_URL}/auth/callback"
        from urllib.parse import quote
        sep = "&" if "?" in base_redirect_url else "?"
        status_part = f"&status_code={status_code}" if status_code else ""
        return RedirectResponse(url=f"{base_redirect_url}{sep}error={quote(str(error))}{status_part}")

    if not token_id:
        raise HTTPException(status_code=400, detail="Missing token_id in callback")

    # 1. Check if token_id is a login_id stored in Redis
    redis_key = f"login_id:{token_id}"
    stored_payload_json = await redis_client.get(redis_key)
    if stored_payload_json:
        # This is a frontend exchange request!
        payload = json.loads(stored_payload_json)
        await redis_client.delete(redis_key)
        
        user_id = payload["user_id"]
        email = payload.get("email")
        mobilenumber = payload.get("mobilenumber")
        service = payload.get("service", "HYPERLOCAL")
        version = payload.get("version", "1")
        entity_name = payload.get("entity_name")
        entity_type = payload.get("entity_type")
        
        # Generate versioned tokens
        private_key_pem, _ = await get_keys_for_version(version)
        
        now = datetime.datetime.now(datetime.timezone.utc)
        access_jti = str(uuid.uuid4())
        access_exp = now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_payload = {
            "sub": user_id,
            "user_id": user_id,
            "service_name": service,
            "type": "access",
            "version": version,
            "exp": int(access_exp.timestamp()),
            "jti": access_jti,
            "email": email,
            "mobilenumber": mobilenumber
        }
        if entity_name:
            access_payload["entity_name"] = entity_name
        if entity_type:
            access_payload["entity_type"] = entity_type
        
        refresh_jti = str(uuid.uuid4())
        refresh_exp = now + datetime.timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        refresh_payload = {
            "sub": user_id,
            "user_id": user_id,
            "service_name": service,
            "type": "refresh",
            "version": version,
            "exp": int(refresh_exp.timestamp()),
            "jti": refresh_jti,
            "email": email,
            "mobilenumber": mobilenumber
        }
        if entity_name:
            refresh_payload["entity_name"] = entity_name
        if entity_type:
            refresh_payload["entity_type"] = entity_type
        
        access_token = jwt.encode(access_payload, private_key_pem, algorithm="RS256")
        refresh_token = jwt.encode(refresh_payload, private_key_pem, algorithm="RS256")
        
        return {
            "access_token": access_token,
            "refresh_token": refresh_token,
            "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
        }

    # 2. Otherwise, treat it as the OAuth callback from Debugger Auth
    cookie_state = request.cookies.get("oauth_state")
    entity_name = None
    entity_type = None
    redirect_url_param = None
    if cookie_state:
        try:
            state_data = json.loads(cookie_state)
            if not service:
                service = state_data.get("service")
            if not version:
                version = state_data.get("version")
            entity_name = state_data.get("entity_name")
            entity_type = state_data.get("entity_type")
            redirect_url_param = state_data.get("redirect_url")
        except Exception:
            pass
            
    if not service:
        service = "HYPERLOCAL"
    if not version:
        version = "1"
        
    # Connects to Debugger Auth to get loggedin user
    constructed_url = f"{DAUTH_BASE_URL}/auth/authenticated-user"
    async with httpx.AsyncClient(timeout=30) as client:
        response = await client.post(
            constructed_url,
            json={
                "token_id": token_id,
                "client_id": SETTINGS.DEB_APIKEY,
                "client_secret": SETTINGS.DEB_SECRETS
            }
        )
    
    if response.status_code != 200:
        raise HTTPException(
            status_code=response.status_code,
            detail="Failed to fetch authenticated user from Debugger Auth"
        )
    
    deb_data = response.json()
    ic(deb_data["token"])
    deb_user_info = jwt.decode(
        deb_data["token"],
        options={"verify_signature": False}
    )
    ic(deb_user_info)
    
    additional_infos = deb_user_info.get("additional_infos") or {}
    if "entity_name" in additional_infos:
        entity_name = additional_infos.get("entity_name")
    if "entity_type" in additional_infos:
        entity_type = additional_infos.get("entity_type")
    if "redirect_url" in additional_infos:
        redirect_url_param = additional_infos.get("redirect_url")
    if additional_infos.get("service"):
        service = additional_infos.get("service")
    if additional_infos.get("version"):
        version = additional_infos.get("version")
    
    # Store user if not exists
    raw_email = deb_user_info.get("email")
    email = raw_email.strip().lower() if isinstance(raw_email, str) and raw_email.strip() else None
    mobilenumber = deb_user_info.get("mobilenumber") or deb_user_info.get("mobile_number")
    if isinstance(mobilenumber, str):
        mobilenumber = mobilenumber.strip()
    
    users_coll = get_collection("users")
    user_query = {}
    if email:
        user_query["$or"] = [
            {"email": email},
            {"email": {"$regex": f"^{re.escape(email)}$", "$options": "i"}}
        ]
    elif mobilenumber:
        user_query["mobilenumber"] = mobilenumber
        
    user_doc = None
    if user_query:
        user_doc = await users_coll.find_one(user_query)
        
    if not user_doc:
        user_id = deb_user_info.get("user_id") or deb_user_info.get("id") or str(uuid.uuid4())
        
        # Determine password based on auth_provider
        auth_provider = deb_user_info.get("auth_provider") or deb_user_info.get("provider") or deb_user_info.get("login_type")
        incoming_password = deb_user_info.get("password")
        
        if (auth_provider == "password" or incoming_password) and incoming_password:
            password_val = incoming_password
            has_custom_password = True
        else:
            password_val = str(uuid.uuid4())
            has_custom_password = False
            
        hashed_password = ph.hash(password_val)
        
        user_doc = {
            "user_id": user_id,
            "password": hashed_password,
            "has_custom_password": has_custom_password,
            "two_factor": False,
            "created_at": datetime.datetime.utcnow(),
            "updated_at": datetime.datetime.utcnow()
        }
        if email:
            user_doc["email"] = email
        if mobilenumber:
            user_doc["mobilenumber"] = mobilenumber
            
        await users_coll.insert_one(user_doc)
    else:
        user_id = user_doc["user_id"]
        email = user_doc.get("email") or email
        mobilenumber = user_doc.get("mobilenumber") or mobilenumber
        
        auth_provider = deb_user_info.get("auth_provider") or deb_user_info.get("provider") or deb_user_info.get("login_type")
        incoming_password = deb_user_info.get("password")
        new_password_field = deb_user_info.get("new_password")
        
        is_reset_event = bool(
            auth_provider in ("forgot-password", "forgot_password", "reset_password", "password_reset")
            or deb_user_info.get("flow_type") == "password_reset"
            or deb_user_info.get("is_reset")
            or deb_user_info.get("is_password_reset")
            or deb_user_info.get("action") in ("reset_password", "forgot_password", "change_password", "reset", "update_password")
            or deb_user_info.get("event") in ("reset_password", "forgot_password", "change_password", "reset")
            or new_password_field
        )
        effective_new_pwd = new_password_field or incoming_password

        # If it's a reset / forgot password event, directly update with new password
        if is_reset_event and effective_new_pwd:
            new_hash = ph.hash(effective_new_pwd)
            await users_coll.update_one(
                {"_id": user_doc["_id"]},
                {"$set": {
                    "password": new_hash,
                    "has_custom_password": True,
                    "updated_at": datetime.datetime.utcnow()
                }}
            )
        # If user logged in via password, verify with stored password
        elif auth_provider == "password" or incoming_password:
            if incoming_password:
                stored_pwd_hash = user_doc.get("password")
                has_custom_pwd = user_doc.get("has_custom_password", False)
                if stored_pwd_hash and has_custom_pwd:
                    try:
                        ph.verify(stored_pwd_hash, incoming_password)
                    except VerifyMismatchError:
                        raise HTTPException(
                            status_code=401,
                            detail="Invalid password. Please check your credentials."
                        )
                    except Exception as e:
                        raise HTTPException(
                            status_code=401,
                            detail=f"Password verification failed: {str(e)}"
                        )
                    
                    if ph.check_needs_rehash(stored_pwd_hash):
                        new_hash = ph.hash(incoming_password)
                        await users_coll.update_one(
                            {"_id": user_doc["_id"]},
                            {"$set": {"password": new_hash, "updated_at": datetime.datetime.utcnow()}}
                        )
                else:
                    # User was previously created via OTP / OAuth; store their password now
                    new_hash = ph.hash(incoming_password)
                    await users_coll.update_one(
                        {"_id": user_doc["_id"]},
                        {"$set": {
                            "password": new_hash,
                            "has_custom_password": True,
                            "updated_at": datetime.datetime.utcnow()
                        }}
                    )

    # Generate a temporary login_id and store user payload in Redis
    login_id = str(uuid.uuid4())
    new_redis_key = f"login_id:{login_id}"
    
    user_context = {
        "user_id": user_id,
        "email": email,
        "mobilenumber": mobilenumber,
        "service": service,
        "version": version,
        "entity_name": entity_name,
        "entity_type": entity_type
    }
    
    await redis_client.set(new_redis_key, json.dumps(user_context), ex=120)
    
    def append_query_param(url: str, key: str, value: str) -> str:
        from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode
        parsed = urlparse(url)
        params = parse_qsl(parsed.query)
        params.append((key, value))
        new_query = urlencode(params)
        return urlunparse(parsed._replace(query=new_query))

    base_redirect_url = None
    if redirect_url_param:
        base_redirect_url = redirect_url_param
    else:
        srv_upper = service.upper() if service else ""
        ent_lower = entity_type.lower() if entity_type else ""
        if srv_upper == "HYPERLOCAL" and ent_lower == "website":
            base_redirect_url = SETTINGS.HYPERLOCAL_WEBSITE_URL
        elif ent_lower == "app":
            base_redirect_url = SETTINGS.APP_DEEP_LINK
        else:
            base_redirect_url = f"{SETTINGS.FRONTEND_URL}/auth/callback"

    redirect_url = append_query_param(base_redirect_url, "token_id", login_id)
    return RedirectResponse(url=redirect_url)

@router.post("/refresh")
async def refresh_token(data: RefreshSchema):
    version = data.version
    if not version:
        try:
            unv = jwt.decode(data.refresh_token, options={"verify_signature": False})
            version = unv.get("version", "1")
        except Exception:
            version = "1"

    # Verify signature using public key matching version
    _, public_key_pem = await get_keys_for_version(version)
    
    try:
        payload = jwt.decode(data.refresh_token, public_key_pem, algorithms=["RS256"])
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid refresh token: {str(e)}")
        
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=400, detail="Token type must be refresh")
        
    # Check if revoked
    revoked_coll = get_collection("revoked_tokens")
    is_revoked = await revoked_coll.find_one({"jti": payload.get("jti")})
    if is_revoked:
        raise HTTPException(status_code=401, detail="Refresh token has been revoked")
        
    # Issue new access token & fresh refresh token
    private_key_pem, _ = await get_keys_for_version(version)
    
    user_id = payload.get("user_id") or payload["sub"]
    email = payload.get("email")
    mobilenumber = payload.get("mobilenumber")
    service = payload.get("service_name")
    entity_name = payload.get("entity_name")
    entity_type = payload.get("entity_type")
    
    now = datetime.datetime.now(datetime.timezone.utc)
    access_jti = str(uuid.uuid4())
    access_exp = now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_payload = {
        "sub": user_id,
        "user_id": user_id,
        "service_name": service,
        "type": "access",
        "version": version,
        "exp": int(access_exp.timestamp()),
        "jti": access_jti,
        "email": email,
        "mobilenumber": mobilenumber
    }
    if entity_name:
        access_payload["entity_name"] = entity_name
    if entity_type:
        access_payload["entity_type"] = entity_type
    
    new_access_token = jwt.encode(access_payload, private_key_pem, algorithm="RS256")

    refresh_jti = str(uuid.uuid4())
    refresh_exp = now + datetime.timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_payload = {
        "sub": user_id,
        "user_id": user_id,
        "service_name": service,
        "type": "refresh",
        "version": version,
        "exp": int(refresh_exp.timestamp()),
        "jti": refresh_jti,
        "email": email,
        "mobilenumber": mobilenumber
    }
    if entity_name:
        refresh_payload["entity_name"] = entity_name
    if entity_type:
        refresh_payload["entity_type"] = entity_type

    new_refresh_token = jwt.encode(refresh_payload, private_key_pem, algorithm="RS256")
    
    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60
    }

@router.post("/revoke")
async def revoke_token(data: RevokeSchema):
    # Decode token without verification to get version and jti
    try:
        unverified_payload = jwt.decode(data.token, options={"verify_signature": False})
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=400, detail="Invalid token format")
        
    version = unverified_payload.get("version")
    if not version:
        raise HTTPException(status_code=400, detail="Token version metadata missing")
        
    # Verify token fully
    _, public_key_pem = await get_keys_for_version(version)
    try:
        payload = jwt.decode(data.token, public_key_pem, algorithms=["RS256"])
    except jwt.PyJWTError as e:
        raise HTTPException(status_code=401, detail="Invalid token signature or expired")
        
    jti = payload.get("jti")
    if not jti:
        raise HTTPException(status_code=400, detail="Token identifier (jti) missing")
        
    revoked_coll = get_collection("revoked_tokens")
    await revoked_coll.update_one(
        {"jti": jti},
        {"$set": {"jti": jti, "revoked_at": datetime.datetime.utcnow()}},
        upsert=True
    )
    return {"message": "Token revoked successfully"}


# Manual User Creation & CRUD Endpoints

@router.post("/users", response_model=UserResponseSchema)
async def create_user_manual(data: UserCreateManualSchema):
    users_coll = get_collection("users")
    normalized_email = data.email.strip().lower() if data.email else None
    
    # Check if exists (case-insensitive email matching)
    query_or = []
    if normalized_email:
        query_or.append({"email": normalized_email})
        query_or.append({"email": {"$regex": f"^{re.escape(normalized_email)}$", "$options": "i"}})
    if data.mobilenumber:
        query_or.append({"mobilenumber": data.mobilenumber.strip()})
        
    existing = await users_coll.find_one({"$or": query_or}) if query_or else None
    if existing:
        raise HTTPException(status_code=400, detail="User with this email or mobile number already exists.")
        
    user_id = data.user_id if data.user_id else str(uuid.uuid4())
    hashed_password = ph.hash(data.password)
    
    user_doc = {
        "user_id": user_id,
        "email": normalized_email,
        "mobilenumber": data.mobilenumber.strip() if data.mobilenumber else None,
        "password": hashed_password,
        "has_custom_password": True,
        "two_factor": data.two_factor,
        "created_at": datetime.datetime.utcnow(),
        "updated_at": datetime.datetime.utcnow()
    }
    await users_coll.insert_one(user_doc)
    return user_doc

@router.post("/login")
async def login_with_password(data: LoginRequestSchema):
    if not data.email and not data.mobilenumber:
        raise HTTPException(status_code=400, detail="Email or mobile number is required")
    
    users_coll = get_collection("users")
    query_or = []
    if data.email:
        clean_email = data.email.strip().lower()
        query_or.append({"email": clean_email})
        query_or.append({"email": {"$regex": f"^{re.escape(clean_email)}$", "$options": "i"}})
    if data.mobilenumber:
        query_or.append({"mobilenumber": data.mobilenumber.strip()})
        
    user_doc = await users_coll.find_one({"$or": query_or}) if query_or else None
    if not user_doc:
        raise HTTPException(status_code=401, detail="Invalid email/mobile or password.")
        
    stored_pwd = user_doc.get("password")
    if not stored_pwd:
        raise HTTPException(status_code=401, detail="No password set for this account. Please login via OTP or OAuth.")
        
    try:
        ph.verify(stored_pwd, data.password)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid email/mobile or password.")
        
    if ph.check_needs_rehash(stored_pwd):
        new_hash = ph.hash(data.password)
        await users_coll.update_one(
            {"_id": user_doc["_id"]},
            {"$set": {"password": new_hash, "updated_at": datetime.datetime.utcnow()}}
        )
        
    version = data.version or "1"
    private_key_pem, _ = await get_keys_for_version(version)
    
    user_id = user_doc["user_id"]
    email = user_doc.get("email")
    mobilenumber = user_doc.get("mobilenumber")
    
    now = datetime.datetime.now(datetime.timezone.utc)
    access_jti = str(uuid.uuid4())
    access_exp = now + datetime.timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_payload = {
        "sub": user_id,
        "user_id": user_id,
        "service_name": data.service or "HYPERLOCAL",
        "type": "access",
        "version": version,
        "exp": int(access_exp.timestamp()),
        "jti": access_jti,
        "email": email,
        "mobilenumber": mobilenumber
    }
    if data.entity_name:
        access_payload["entity_name"] = data.entity_name
    if data.entity_type:
        access_payload["entity_type"] = data.entity_type
        
    refresh_jti = str(uuid.uuid4())
    refresh_exp = now + datetime.timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_payload = {
        "sub": user_id,
        "user_id": user_id,
        "service_name": data.service or "HYPERLOCAL",
        "type": "refresh",
        "version": version,
        "exp": int(refresh_exp.timestamp()),
        "jti": refresh_jti,
        "email": email,
        "mobilenumber": mobilenumber
    }
    if data.entity_name:
        refresh_payload["entity_name"] = data.entity_name
    if data.entity_type:
        refresh_payload["entity_type"] = data.entity_type
        
    access_token = jwt.encode(access_payload, private_key_pem, algorithm="RS256")
    refresh_token = jwt.encode(refresh_payload, private_key_pem, algorithm="RS256")
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        "user": {
            "user_id": user_id,
            "email": email,
            "mobilenumber": mobilenumber
        }
    }

@router.get("/users", response_model=List[UserResponseSchema])
async def get_all_users():
    users_coll = get_collection("users")
    cursor = users_coll.find({})
    users = []
    async for doc in cursor:
        users.append(doc)
    return users

@router.get("/users/by-id/{user_id}", response_model=UserResponseSchema)
async def get_user_by_id(user_id: str):
    users_coll = get_collection("users")
    user = await users_coll.find_one({"user_id": user_id})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.get("/users/by-email/{email}", response_model=UserResponseSchema)
async def get_user_by_email(email: str):
    users_coll = get_collection("users")
    clean_email = email.strip().lower()
    user = await users_coll.find_one({
        "$or": [
            {"email": clean_email},
            {"email": {"$regex": f"^{re.escape(clean_email)}$", "$options": "i"}}
        ]
    })
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.get("/users/by-mobile/{mobilenumber}", response_model=UserResponseSchema)
async def get_user_by_mobile(mobilenumber: str):
    users_coll = get_collection("users")
    user = await users_coll.find_one({"mobilenumber": mobilenumber})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user

@router.delete("/users/{user_id}")
async def delete_user(user_id: str):
    users_coll = get_collection("users")
    res = await users_coll.delete_one({"user_id": user_id})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="User not found")
    return {"message": "User deleted successfully"}


# Password Reset & Management Endpoints

@router.post("/forgot-password")
async def forgot_password(data: ForgotPasswordSchema):
    if not data.email and not data.mobilenumber:
        raise HTTPException(status_code=400, detail="Email or mobile number is required.")
    
    users_coll = get_collection("users")
    query_or = []
    if data.email:
        clean_email = data.email.strip().lower()
        query_or.append({"email": clean_email})
        query_or.append({"email": {"$regex": f"^{re.escape(clean_email)}$", "$options": "i"}})
    if data.mobilenumber:
        query_or.append({"mobilenumber": data.mobilenumber.strip()})
        
    user_doc = await users_coll.find_one({"$or": query_or}) if query_or else None
    if not user_doc:
        raise HTTPException(status_code=404, detail="User with this email/mobile number not found.")
        
    reset_token = str(uuid.uuid4())
    redis_key = f"pwd_reset:{reset_token}"
    token_payload = {
        "user_id": user_doc["user_id"],
        "email": user_doc.get("email"),
        "mobilenumber": user_doc.get("mobilenumber")
    }
    # Store token in Redis for 15 minutes (900 seconds)
    await redis_client.set(redis_key, json.dumps(token_payload), ex=900)
    
    return {
        "message": "Password reset token generated successfully.",
        "reset_token": reset_token,
        "user_id": user_doc["user_id"],
        "email": user_doc.get("email"),
        "mobilenumber": user_doc.get("mobilenumber"),
        "expires_in_seconds": 900
    }

@router.post("/reset-password")
async def reset_password(data: ResetPasswordSchema):
    if not data.new_password:
        raise HTTPException(status_code=400, detail="New password is required.")
    
    users_coll = get_collection("users")
    user_id = data.user_id
    
    if data.reset_token:
        redis_key = f"pwd_reset:{data.reset_token}"
        stored_payload_json = await redis_client.get(redis_key)
        if not stored_payload_json:
            raise HTTPException(status_code=400, detail="Invalid or expired reset token.")
        
        token_data = json.loads(stored_payload_json)
        user_id = token_data.get("user_id") or user_id
        await redis_client.delete(redis_key)
        
    query_or = []
    if user_id:
        query_or.append({"user_id": user_id})
    if data.email:
        clean_email = data.email.strip().lower()
        query_or.append({"email": clean_email})
        query_or.append({"email": {"$regex": f"^{re.escape(clean_email)}$", "$options": "i"}})
    if data.mobilenumber:
        query_or.append({"mobilenumber": data.mobilenumber.strip()})
        
    if not query_or:
        raise HTTPException(status_code=400, detail="Reset token, user_id, email, or mobile number is required.")
        
    user_doc = await users_coll.find_one({"$or": query_or})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found.")
        
    new_hash = ph.hash(data.new_password)
    await users_coll.update_one(
        {"_id": user_doc["_id"]},
        {"$set": {
            "password": new_hash,
            "has_custom_password": True,
            "updated_at": datetime.datetime.utcnow()
        }}
    )
    
    return {"message": "Password has been successfully updated. You can now login with your new password."}

@router.post("/change-password")
async def change_password(data: ChangePasswordSchema):
    if not data.old_password or not data.new_password:
        raise HTTPException(status_code=400, detail="Both old and new passwords are required.")
        
    users_coll = get_collection("users")
    query_or = []
    if data.user_id:
        query_or.append({"user_id": data.user_id})
    if data.email:
        clean_email = data.email.strip().lower()
        query_or.append({"email": clean_email})
        query_or.append({"email": {"$regex": f"^{re.escape(clean_email)}$", "$options": "i"}})
    if data.mobilenumber:
        query_or.append({"mobilenumber": data.mobilenumber.strip()})
        
    if not query_or:
        raise HTTPException(status_code=400, detail="User identifier (user_id, email, or mobile number) is required.")
        
    user_doc = await users_coll.find_one({"$or": query_or})
    if not user_doc:
        raise HTTPException(status_code=404, detail="User not found.")
        
    stored_pwd = user_doc.get("password")
    has_custom_pwd = user_doc.get("has_custom_password", False)
    
    if stored_pwd and has_custom_pwd:
        try:
            ph.verify(stored_pwd, data.old_password)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid current password.")
            
    new_hash = ph.hash(data.new_password)
    await users_coll.update_one(
        {"_id": user_doc["_id"]},
        {"$set": {
            "password": new_hash,
            "has_custom_password": True,
            "updated_at": datetime.datetime.utcnow()
        }}
    )
    
    return {"message": "Password changed successfully."}

