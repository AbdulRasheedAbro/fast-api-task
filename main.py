"""Auth Login & Protect - FastAPI + Supabase Auth."""
import os
from contextlib import asynccontextmanager
from typing import Optional

from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from supabase import Client, create_client

load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_KEY")
PORT = int(os.getenv("PORT", "8000"))

if not SUPABASE_URL or not SUPABASE_KEY:
    raise RuntimeError("SUPABASE_URL and SUPABASE_KEY must be set in .env")


def new_client() -> Client:
    """Fresh client per request so one user's session never leaks into another's."""
    return create_client(SUPABASE_URL, SUPABASE_KEY)


@asynccontextmanager
async def lifespan(app: FastAPI):
    new_client()  # fails loudly on a malformed URL/key
    print("Server running and connected to Supabase")
    yield


app = FastAPI(
    title="Auth Login & Protect API",
    description="Sign up, log in, and access protected routes using Supabase Auth JWTs.",
    version="1.0.0",
    lifespan=lifespan,
)

# auto_error=False -> we return our own 401 (FastAPI's default would be 403)
bearer_scheme = HTTPBearer(auto_error=False, description="Paste the access_token from /auth/login")


# ---------- Models ----------
class Credentials(BaseModel):
    # Optional so that a missing field yields our 400, not FastAPI's default 422
    email: Optional[str] = Field(default=None, examples=["test@example.com"])
    password: Optional[str] = Field(default=None, examples=["password123"])


class MessageResponse(BaseModel):
    message: str


class ErrorResponse(BaseModel):
    error: str


# ---------- Error handling ----------
@app.exception_handler(RequestValidationError)
async def bad_request_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(status_code=400, content={"error": "Invalid or malformed request body"})


# ---------- Auth dependency (middleware guard) ----------
def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer_scheme),
):
    """Verify the Bearer token with Supabase. Returns (user, token)."""
    if credentials is None or not credentials.credentials.strip():
        raise AuthError("Access token required")
    token = credentials.credentials.strip()
    try:
        res = new_client().auth.get_user(token)
        user = res.user if res else None
    except Exception:
        user = None
    if user is None:
        raise AuthError("Invalid or expired token")
    return user, token


class AuthError(Exception):
    def __init__(self, message: str):
        self.message = message


@app.exception_handler(AuthError)
async def auth_error_handler(request: Request, exc: AuthError):
    return JSONResponse(
        status_code=401,
        content={"error": exc.message},
        headers={"WWW-Authenticate": "Bearer"},
    )


def user_summary(user) -> dict:
    return {"id": str(user.id), "email": user.email, "created_at": str(user.created_at)}


# ---------- Public ----------
@app.get("/public/info", response_model=MessageResponse, tags=["Public"])
def public_info():
    return {"message": "Welcome stranger! This info is public."}


# ---------- Auth ----------
@app.post("/auth/signup", status_code=201, tags=["Auth"],
          responses={400: {"model": ErrorResponse}})
def signup(body: Credentials):
    if not body.email or not body.password:
        return JSONResponse(status_code=400, content={"error": "Email and password are required"})
    try:
        res = new_client().auth.sign_up({"email": body.email, "password": body.password})
    except Exception as e:
        return JSONResponse(status_code=400, content={"error": str(getattr(e, "message", e))})
    return JSONResponse(status_code=201, content=jsonable_encoder(res.user))


@app.post("/auth/login", tags=["Auth"],
          responses={400: {"model": ErrorResponse}, 401: {"model": ErrorResponse}})
def login(body: Credentials):
    if not body.email or not body.password:
        return JSONResponse(status_code=400, content={"error": "Email and password are required"})
    try:
        res = new_client().auth.sign_in_with_password(
            {"email": body.email, "password": body.password}
        )
    except Exception:
        return JSONResponse(status_code=401, content={"error": "Invalid login credentials"})
    if not res or not res.session:
        return JSONResponse(status_code=401, content={"error": "Invalid login credentials"})
    s = res.session
    return {
        "access_token": s.access_token,
        "refresh_token": s.refresh_token,
        "token_type": "bearer",
        "expires_in": s.expires_in,
    }


@app.post("/auth/logout", status_code=204, tags=["Auth"],
          responses={401: {"model": ErrorResponse}})
def logout(auth=Depends(get_current_user)):
    _, token = auth
    try:
        # Revokes the session tied to this JWT (uses the user's token, not a service key)
        new_client().auth.admin.sign_out(token)
    except Exception:
        raise AuthError("Invalid or expired token")
    return Response(status_code=204)


# ---------- Protected ----------
@app.get("/protected/profile", tags=["Protected"], responses={401: {"model": ErrorResponse}})
def profile(auth=Depends(get_current_user)):
    user, _ = auth
    return user_summary(user)


@app.get("/protected/dashboard", tags=["Protected"], responses={401: {"model": ErrorResponse}})
def dashboard(auth=Depends(get_current_user)):
    user, _ = auth
    return {"message": f"Welcome to your dashboard, {user.email}!"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=PORT, reload=True)