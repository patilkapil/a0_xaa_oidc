"""
Minimal XAA UI — single Flask file.

Run:
    python ui.py
    open http://localhost:5000

Flow when you click "Run XAA Flow":
    1. Browser → Okta login (Authorization Code + PKCE)
    2. Okta → /callback  (auth code)
    3. Server exchanges code → Okta id_token
    4. Server exchanges id_token at Okta → ID-JAG
    5. Server exchanges ID-JAG at Auth0 → Auth0 access token
    6. Page reloads showing all three tokens + API response
"""

import os
import base64
import hashlib
import secrets
import requests
from urllib.parse import urlencode
from flask import Flask, redirect, render_template, request, session, url_for
from dotenv import load_dotenv
from agent import get_id_jag_from_okta, get_auth0_access_token, call_api

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────

OKTA_DOMAIN         = os.environ["OKTA_DOMAIN"]
OKTA_CLIENT_ID      = os.environ["OKTA_CLIENT_ID"]
OKTA_CLIENT_SECRET  = os.environ["OKTA_CLIENT_SECRET"]

AUTH0_DOMAIN        = os.environ["AUTH0_DOMAIN"]
AUTH0_CLIENT_ID     = os.environ["AUTH0_CLIENT_ID"]
AUTH0_CLIENT_SECRET = os.environ["AUTH0_CLIENT_SECRET"]
AUTH0_API_AUDIENCE  = os.environ["AUTH0_API_AUDIENCE"]
AUTH0_API_SCOPE     = os.environ.get("AUTH0_API_SCOPE", "openid")
AUTH0_CONNECTION    = os.environ["AUTH0_CONNECTION"]

# Issuer URL of the Okta Resource App's Authorization Server (not the Auth0 URL).
# Okta Admin → Security → API → Authorization Servers → resource app AS → Issuer
OKTA_RESOURCE_AS_ISSUER = os.environ["OKTA_RESOURCE_AS_ISSUER"]

API_BASE_URL        = os.environ.get("API_BASE_URL", "http://localhost:8080")

CALLBACK_URI           = "http://localhost:5000/callback"         # must be registered in Okta app
PROVISION_CALLBACK_URI = "http://localhost:5000/provision/callback" # must be registered in Auth0 app

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)   # session encryption key (ephemeral)

# ── PKCE ──────────────────────────────────────────────────────────────────────

def _pkce_pair():
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).rstrip(b"=").decode()
    return verifier, challenge

# ── Token exchange helpers ────────────────────────────────────────────────────

def _exchange_code_for_id_token(code: str, verifier: str) -> str:
    print("\n[Step 1] Exchanging auth code for Okta tokens...")
    url = f"https://{OKTA_DOMAIN}/oauth2/v1/token"   # Org AS — id_token issuer must match Step 2
    print(f"         POST {url}")
    resp = requests.post(
        url,
        data={
            "grant_type":    "authorization_code",
            "client_id":     OKTA_CLIENT_ID,
            "client_secret": OKTA_CLIENT_SECRET,
            "redirect_uri":  CALLBACK_URI,
            "code":          code,
            "code_verifier": verifier,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )
    print(f"         Status: {resp.status_code}")
    if not resp.ok:
        print(f"         Error body: {resp.text}")
    resp.raise_for_status()
    tokens = resp.json()
    print(f"         Keys returned: {list(tokens.keys())}")
    print(f"         id_token present: {'id_token' in tokens}")
    return tokens

# ── Routes ────────────────────────────────────────────────────────────────────

@app.get("/")
def index():
    tokens      = session.get("tokens", {})
    api_data    = session.get("api_data")
    error       = session.pop("error", None)
    provisioned = session.get("provisioned", False)
    return render_template("index.html", tokens=tokens, api_data=api_data, error=error, provisioned=provisioned)

@app.get("/start")
def start():
    """Kick off Okta Authorization Code + PKCE login."""
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(16)
    session["pkce_verifier"] = verifier
    session["oauth_state"]   = state

    params = {
        "response_type":         "code",
        "client_id":             OKTA_CLIENT_ID,
        "redirect_uri":          CALLBACK_URI,
        "scope":                 "openid profile email",
        "state":                 state,
        "code_challenge":        challenge,
        "code_challenge_method": "S256",
    }
    return redirect(f"https://{OKTA_DOMAIN}/oauth2/v1/authorize?{urlencode(params)}")

@app.get("/callback")
def callback():
    """Okta redirects here with ?code=... after user login."""
    # Validate state
    if request.args.get("state") != session.get("oauth_state"):
        session["error"] = "State mismatch — possible CSRF."
        return redirect(url_for("index"))

    code     = request.args.get("code")
    verifier = session.pop("pkce_verifier", None)
    print(f"\n{'='*60}")
    print(f"Callback received. Starting XAA flow...")
    print(f"{'='*60}")

    try:
        # Step 1 — exchange code for Okta tokens
        okta_tokens = _exchange_code_for_id_token(code, verifier)
        id_token    = okta_tokens["id_token"]

        # Hand off to the agent (requesting entity).
        # In production, your agent receives the id_token from whatever triggered
        # it and runs Steps 2–4 autonomously — no further user interaction needed.

        # Step 2 — agent exchanges id_token at Okta for ID-JAG
        id_jag = get_id_jag_from_okta(id_token)

        # Step 3 — agent exchanges ID-JAG at Auth0 for access token
        auth0_access_token = get_auth0_access_token(id_jag)

        # Step 4 — agent calls the protected API
        api_data = call_api(auth0_access_token)
        print(f"\n{'='*60}")
        print("XAA flow complete!")
        print(f"{'='*60}\n")

        session["tokens"] = {
            "okta_id_token":       id_token,
            "id_jag":              id_jag,
            "auth0_access_token":  auth0_access_token,
        }
        session["api_data"] = api_data

    except Exception as e:
        print(f"\n[ERROR] Flow failed: {e}")
        session["error"] = str(e)

    return redirect(url_for("index"))

@app.get("/provision")
def provision():
    """
    Step 0 — Log in via Auth0 Universal Login using the Okta Enterprise
    connection. This creates the user's profile in Auth0 (one-time only).
    After this, the XAA flow can act on their behalf indefinitely.
    """
    verifier, challenge = _pkce_pair()
    state = secrets.token_urlsafe(16)
    session["provision_verifier"] = verifier
    session["provision_state"]    = state

    params = {
        "response_type":         "code",
        "client_id":             AUTH0_CLIENT_ID,
        "redirect_uri":          PROVISION_CALLBACK_URI,
        "scope":                 "openid profile email",
        "state":                 state,
        "connection":            AUTH0_CONNECTION,   # force Okta Enterprise connection
        "code_challenge":        challenge,
        "code_challenge_method": "S256",
    }
    return redirect(f"https://{AUTH0_DOMAIN}/authorize?{urlencode(params)}")

@app.get("/provision/callback")
def provision_callback():
    """Auth0 redirects here after the user logs in via Okta Enterprise connection."""
    if request.args.get("state") != session.get("provision_state"):
        session["error"] = "State mismatch during provisioning."
        return redirect(url_for("index"))

    code     = request.args.get("code")
    verifier = session.pop("provision_verifier", None)

    try:
        print("\n[Provision] Exchanging code for Auth0 tokens...")
        resp = requests.post(
            f"https://{AUTH0_DOMAIN}/oauth/token",
            data={
                "grant_type":    "authorization_code",
                "client_id":     AUTH0_CLIENT_ID,
                "client_secret": AUTH0_CLIENT_SECRET,
                "redirect_uri":  PROVISION_CALLBACK_URI,
                "code":          code,
                "code_verifier": verifier,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10,
        )
        resp.raise_for_status()
        print(f"[Provision] User profile created in Auth0. Keys: {list(resp.json().keys())}")
        session["provisioned"] = True
    except Exception as e:
        print(f"[Provision] Failed: {e}")
        session["error"] = f"Provisioning failed: {e}"

    return redirect(url_for("index"))

@app.get("/reset")
def reset():
    session.clear()
    return redirect(url_for("index"))

if __name__ == "__main__":
    print("XAA UI running  → http://localhost:5000")
    app.run(port=5000, debug=True)
