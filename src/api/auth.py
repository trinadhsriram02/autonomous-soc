import os
from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

VALID_API_KEYS = {
    os.getenv("SOC_API_KEY", "soc-dev-key-12345"): "admin",
}


def verify_api_key(api_key: str = Security(API_KEY_HEADER)) -> str:
    """
    Validates API key on every protected endpoint.
    Add X-API-Key header to all requests.
    """
    if not api_key:
        raise HTTPException(
            status_code=401,
            detail="API key missing. Add X-API-Key header."
        )

    if api_key not in VALID_API_KEYS:
        raise HTTPException(
            status_code=403,
            detail="Invalid API key."
        )

    return VALID_API_KEYS[api_key]