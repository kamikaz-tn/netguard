"""
netguard/backend/routers/password.py
──────────────────────────────────────
Password breach check via HaveIBeenPwned k-anonymity API.

How it works (privacy-preserving):
  1. Client hashes password with SHA-1 in the browser
  2. Sends only the first 5 chars of the hash to US
  3. We forward that prefix to HIBP
  4. HIBP returns all matching hash suffixes + breach counts
  5. Client checks locally if their full hash is in the list

The real password NEVER leaves the user's machine.
"""

import httpx
from fastapi import APIRouter, HTTPException
from models.schemas import PasswordCheckRequest, PasswordCheckResponse

router = APIRouter(prefix="/api/password", tags=["Password Security"])

HIBP_URL = "https://api.pwnedpasswords.com/range/"
HEADERS = {
    "User-Agent": "NetGuard-Security-App/1.0",
    "Add-Padding": "true",   # HIBP padding makes traffic analysis harder
}


@router.post("/check", response_model=PasswordCheckResponse)
async def check_password_breach(body: PasswordCheckRequest):
    """
    Proxy the HIBP k-anonymity request.
    Receives SHA-1 prefix (5 chars), returns matching suffixes.
    The client then does the final comparison locally.
    """
    prefix = body.hash_prefix.upper()

    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(
                HIBP_URL + prefix,
                headers=HEADERS,
            )
            response.raise_for_status()
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="HIBP API timed out")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=502, detail=f"HIBP API error: {e.response.status_code}")
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Could not reach HIBP: {str(e)}")

    # Parse response — each line is "SUFFIX:COUNT"
    lines = response.text.strip().splitlines()
    results = {}
    for line in lines:
        parts = line.split(":")
        if len(parts) == 2:
            suffix, count = parts
            results[suffix.upper()] = int(count)

    # Return all suffix:count pairs so client can check locally
    # (We never know which specific hash the client cares about)
    return PasswordCheckResponse(
        pwned=False,   # client determines this locally
        count=0,
        message="\n".join(f"{s}:{c}" for s, c in results.items()),
    )


@router.get("/tips", tags=["Password Security"])
async def password_tips():
    """Return password security best practices."""
    return {
        "tips": [
            "Use a unique password for every account — reuse is the #1 breach risk",
            "Use a password manager (Bitwarden, 1Password, KeePass) to generate and store strong passwords",
            "Enable two-factor authentication (2FA) everywhere possible",
            "A strong password is long (16+ chars) not just complex — passphrases work great",
            "Never use personal info in passwords: birthday, name, city, pet name",
            "Change passwords immediately if a service you use announces a breach",
        ],
        "recommended_managers": [
            {"name": "Bitwarden", "url": "https://bitwarden.com", "note": "Free and open source"},
            {"name": "KeePassXC", "url": "https://keepassxc.org", "note": "Offline, fully local"},
            {"name": "1Password", "url": "https://1password.com", "note": "Best UX, paid"},
        ]
    }
