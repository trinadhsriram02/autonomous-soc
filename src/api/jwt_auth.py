import os
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Optional
from jose import JWTError, jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

# ─────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-super-secret-key-change-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 8  # 8 hours

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# ─────────────────────────────────────────
# Role permissions
# ─────────────────────────────────────────
ROLE_PERMISSIONS = {
    "admin": [
        "analyze", "view", "feedback",
        "manage_users", "view_all", "change_settings"
    ],
    "analyst": [
        "analyze", "view", "feedback"
    ],
    "readonly": [
        "view"
    ]
}


# ─────────────────────────────────────────
# Password hashing
# Compatible with Python 3.13
# ─────────────────────────────────────────
def hash_password(password: str) -> str:
    """Hash password using SHA256 with salt."""
    salt = os.urandom(32).hex()
    hashed = hashlib.sha256((password + salt).encode()).hexdigest()
    return f"{salt}:{hashed}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify password against stored hash."""
    try:
        salt, stored_hash = hashed_password.split(":")
        check_hash = hashlib.sha256(
            (plain_password + salt).encode()
        ).hexdigest()
        return hmac.compare_digest(check_hash, stored_hash)
    except Exception:
        return False


# ─────────────────────────────────────────
# JWT token functions
# ─────────────────────────────────────────
def create_access_token(data: dict,
                        expires_delta: Optional[timedelta] = None) -> str:
    """Create a JWT token with user data and expiry."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (
        expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    """Decode and verify a JWT token."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None


# ─────────────────────────────────────────
# Permission helpers
# ─────────────────────────────────────────
def has_permission(role: str, permission: str) -> bool:
    """Check if a role has a specific permission."""
    return permission in ROLE_PERMISSIONS.get(role, [])


async def get_current_user(
    token: str = Depends(oauth2_scheme)
) -> dict:
    """
    Validates JWT token on every protected request.
    Add this to any endpoint that needs authentication.
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )

    payload = decode_token(token)
    if not payload:
        raise credentials_exception

    username = payload.get("sub")
    role = payload.get("role")

    if not username or not role:
        raise credentials_exception

    return {
        "username": username,
        "role": role,
        "id": payload.get("id")
    }


def require_permission(permission: str):
    """
    Permission checker dependency.
    Locks endpoints to specific roles.
    Usage: Depends(require_permission('manage_users'))
    """
    async def check_permission(
        current_user: dict = Depends(get_current_user)
    ):
        if not has_permission(current_user["role"], permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Your role '{current_user['role']}' cannot perform '{permission}'"
            )
        return current_user
    return check_permission