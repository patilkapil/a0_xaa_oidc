"""
Minimal dummy API server protected by Auth0.

Validates the Bearer token (Auth0 access token) on every request using
Auth0's JWKS endpoint, then returns static data.

Install deps:
    pip install flask python-jose[cryptography] requests
"""

import os
import json
import requests
from functools import wraps
from flask import Flask, request, jsonify, abort
from jose import jwt, JWTError
from dotenv import load_dotenv

load_dotenv()

AUTH0_DOMAIN = os.environ["AUTH0_DOMAIN"]          # e.g. your-tenant.auth0.com
AUTH0_API_AUDIENCE = os.environ["AUTH0_API_AUDIENCE"]  # e.g. https://your-api-identifier/

app = Flask(__name__)

# ── Token validation ──────────────────────────────────────────────────────────

def _get_jwks():
    url = f"https://{AUTH0_DOMAIN}/.well-known/jwks.json"
    return requests.get(url, timeout=5).json()

def require_auth(f):
    """Decorator: validates Auth0 JWT access token on every request."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            abort(401, "Missing Bearer token")

        token = auth_header.split(" ", 1)[1]
        jwks = _get_jwks()

        try:
            # Decode & validate signature, audience, issuer, expiry
            payload = jwt.decode(
                token,
                jwks,
                algorithms=["RS256"],
                audience=AUTH0_API_AUDIENCE,
                issuer=f"https://{AUTH0_DOMAIN}/",
            )
        except JWTError as e:
            abort(401, f"Invalid token: {e}")

        # Attach claims to the request context
        request.token_claims = payload
        return f(*args, **kwargs)
    return decorated

# ── API routes ────────────────────────────────────────────────────────────────

@app.get("/data")
@require_auth
def get_data():
    """Returns static dummy data. Token claims show which user the agent acted for."""
    claims = request.token_claims
    return jsonify({
        "message": "Cross-App Access successful!",
        "acting_subject": claims.get("sub"),
        "data": [
            {"id": 1, "name": "Widget Alpha", "value": 42},
            {"id": 2, "name": "Widget Beta",  "value": 99},
        ],
    })

if __name__ == "__main__":
    app.run(port=8080, debug=True)
