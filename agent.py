"""
XAA Agent — Cross-App Access Flow (OIDC Requesting App)
Aligned with: https://auth0.com/docs/ai-agents-mcp/cross-app-access/end-to-end-testing#oidc-requesting-app

──────────────────────────────────────────────────────────────────────────────
This file has two roles:

  AS A MODULE  — get_id_jag_from_okta(), get_auth0_access_token(), call_api()
                 are the requesting entity's core. Import these into your agent
                 (LangChain tool, CrewAI agent, custom script, etc.) to act on
                 a user's behalf without requiring them to log in again.

  AS A SCRIPT  — python agent.py runs a full end-to-end demo with a browser
                 login (Step 1) to simulate how a user's identity reaches the
                 agent in practice.

──────────────────────────────────────────────────────────────────────────────
FLOW:

  Step 1: Open browser → user logs in to Okta (Authorization Code + PKCE)
          Local server catches the redirect → exchange code → Okta id_token
          (demo scaffolding only — not part of the agent's job in production)

  Step 2: Exchange Okta id_token at Okta → ID-JAG
          (Identity Assertion Authorization Grant, targeted at Auth0)

  Step 3: Exchange ID-JAG at Auth0 → Auth0 access token
          (grant_type=jwt-bearer, assertion=ID-JAG)

  Step 4: Call protected API with Auth0 access token
──────────────────────────────────────────────────────────────────────────────

Install deps:
    pip install requests python-dotenv
"""

import os
import sys
import json
import base64
import hashlib
import secrets
import threading
import webbrowser
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlencode, urlparse, parse_qs
from dotenv import load_dotenv

load_dotenv()

# ── Config ────────────────────────────────────────────────────────────────────

OKTA_DOMAIN         = os.environ["OKTA_DOMAIN"]           # e.g. your-org.okta.com
OKTA_CLIENT_ID      = os.environ["OKTA_CLIENT_ID"]        # Agent's Client ID in Okta
OKTA_CLIENT_SECRET  = os.environ["OKTA_CLIENT_SECRET"]    # Agent's Client Secret in Okta

AUTH0_DOMAIN        = os.environ["AUTH0_DOMAIN"]          # e.g. your-tenant.auth0.com
AUTH0_CLIENT_ID     = os.environ["AUTH0_CLIENT_ID"]       # Requesting App Client ID in Auth0
AUTH0_CLIENT_SECRET = os.environ["AUTH0_CLIENT_SECRET"]   # Requesting App Client Secret in Auth0
AUTH0_API_AUDIENCE  = os.environ["AUTH0_API_AUDIENCE"]    # Auth0 API Identifier e.g. https://my-api/
AUTH0_API_SCOPE     = os.environ.get("AUTH0_API_SCOPE", "openid")
AUTH0_CONNECTION    = os.environ["AUTH0_CONNECTION"]

API_BASE_URL        = os.environ.get("API_BASE_URL", "http://localhost:8080")

# Local callback server — must match the redirect URI registered in your Okta app
CALLBACK_PORT       = 8765
CALLBACK_URI        = f"http://localhost:{CALLBACK_PORT}/callback"


# ── PKCE helpers ──────────────────────────────────────────────────────────────

def generate_pkce_pair() -> tuple[str, str]:
    """Returns (code_verifier, code_challenge)."""
    code_verifier = secrets.token_urlsafe(64)
    digest = hashlib.sha256(code_verifier.encode()).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode()
    return code_verifier, code_challenge


# ── Local callback server ─────────────────────────────────────────────────────

class _CallbackHandler(BaseHTTPRequestHandler):
    """Catches the single redirect from Okta and extracts the auth code."""

    auth_code: str | None = None
    error: str | None = None

    def do_GET(self):
        params = parse_qs(urlparse(self.path).query)
        if "error" in params:
            _CallbackHandler.error = params["error"][0]
        else:
            _CallbackHandler.auth_code = params.get("code", [None])[0]

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"<h2>Login successful. You can close this tab.</h2>")
        # Signal the server to shut down after this request
        threading.Thread(target=self.server.shutdown).start()

    def log_message(self, *args):
        pass  # suppress access logs


# ── Step 1: Authorization Code + PKCE → Okta id_token ───────────────────────

def get_okta_id_token() -> str:
    """
    1a. Build the Okta /authorize URL with PKCE and open it in the browser.
    1b. Spin up a local HTTP server to catch the redirect callback.
    1c. Exchange the auth code for tokens and return the id_token.

    The redirect URI http://localhost:{CALLBACK_PORT}/callback must be
    registered in your Okta application's "Sign-in redirect URIs".
    """
    code_verifier, code_challenge = generate_pkce_pair()
    state = secrets.token_urlsafe(16)

    # Build Okta /authorize URL
    params = {
        "response_type":         "code",
        "client_id":             OKTA_CLIENT_ID,
        "redirect_uri":          CALLBACK_URI,
        "scope":                 "openid profile email",
        "state":                 state,
        "code_challenge":        code_challenge,
        "code_challenge_method": "S256",
    }
    authorize_url = f"https://{OKTA_DOMAIN}/oauth2/v1/authorize?{urlencode(params)}"

    print("[Step 1] Opening browser for Okta login…")
    print(f"         URL: {authorize_url}\n")
    webbrowser.open(authorize_url)

    # Start local callback server
    server = HTTPServer(("localhost", CALLBACK_PORT), _CallbackHandler)
    print(f"         Waiting for callback on {CALLBACK_URI} …")
    server.serve_forever()  # blocks until _CallbackHandler shuts it down

    if _CallbackHandler.error:
        raise RuntimeError(f"Okta login error: {_CallbackHandler.error}")

    auth_code = _CallbackHandler.auth_code
    if not auth_code:
        raise RuntimeError("No auth code received from Okta callback.")

    print("         Auth code received. Exchanging for tokens…")

    # Exchange auth code for tokens
    resp = requests.post(
        f"https://{OKTA_DOMAIN}/oauth2/v1/token",
        data={
            "grant_type":    "authorization_code",
            "client_id":     OKTA_CLIENT_ID,
            "client_secret": OKTA_CLIENT_SECRET,
            "redirect_uri":  CALLBACK_URI,
            "code":          auth_code,
            "code_verifier": code_verifier,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )
    resp.raise_for_status()
    tokens = resp.json()

    id_token = tokens.get("id_token")
    if not id_token:
        raise ValueError("No id_token in Okta token response. Ensure 'openid' scope is requested.")

    print(f"[Step 1] Okta id_token acquired.")
    print(f"         id_token (first 40 chars): {id_token[:40]}…")
    return id_token


# ── Requesting Entity Core ───────────────────────────────────────────────────
# At first glance this file may not look like an "agent" — it opens a browser,
# waits for a login, and prints results to the terminal. That's the demo shell.
#
# The actual agent pattern is the three functions below: get_id_jag_from_okta(),
# get_auth0_access_token(), and call_api(). These are stateless HTTP calls with
# no browser, no UI, and no Flask dependency. In a real deployment, your agent
# already has the user's id_token (from a prior session, an orchestration layer,
# or a trigger event) and calls these three functions autonomously to obtain
# delegated access to a protected API on the user's behalf.
#
# To embed this pattern in your agent:
#
#   from agent import get_id_jag_from_okta, get_auth0_access_token, call_api
#
#   id_jag             = get_id_jag_from_okta(user_id_token)
#   auth0_access_token = get_auth0_access_token(id_jag)
#   result             = call_api(auth0_access_token)
#
# That's it. Drop these three calls into any agentic framework — LangChain,
# CrewAI, an MCP server handler, or a custom script — and your agent can act
# on a user's behalf without requiring them to log in again.

# ── Step 2: Exchange Okta id_token → ID-JAG (at Okta) ───────────────────────

def get_id_jag_from_okta(okta_id_token: str) -> str:
    """
    Token exchange at Okta requesting an ID-JAG.
    The audience is the Auth0 tenant issuer URL — this scopes the ID-JAG
    so that only Auth0 can accept it.

    Okta returns the ID-JAG in the `access_token` field of the response.
    """
    auth0_issuer = f"https://{AUTH0_DOMAIN}"

    resp = requests.post(
        f"https://{OKTA_DOMAIN}/oauth2/v1/token",   # Org AS — required for id-jag
        data={
            "grant_type":           "urn:ietf:params:oauth:grant-type:token-exchange",
            "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag",
            "subject_token_type":   "urn:ietf:params:oauth:token-type:id_token",
            "subject_token":        okta_id_token,
            "client_id":            OKTA_CLIENT_ID,
            "client_secret":        OKTA_CLIENT_SECRET,
            "audience":             auth0_issuer,    # Auth0 tenant issuer URL
            "scope":                AUTH0_API_SCOPE,
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )

    if not resp.ok:
        print(f"\n[Step 2] FAILED — Okta ID-JAG exchange ({resp.status_code})")
        print(resp.text)
        resp.raise_for_status()

    id_jag = resp.json().get("access_token")
    if not id_jag:
        raise ValueError("No ID-JAG returned by Okta in access_token field.")

    print(f"\n[Step 2] ID-JAG acquired from Okta.")
    print(f"         ID-JAG (first 40 chars): {id_jag[:40]}…")
    return id_jag


# ── Step 3: Exchange ID-JAG → Auth0 access token (at Auth0) ──────────────────

def get_auth0_access_token(id_jag: str) -> str:
    """
    Auth0 accepts the ID-JAG via grant_type=jwt-bearer.
    Auth0 validates the ID-JAG signature against Okta's JWKS, confirms the
    audience matches the Auth0 tenant, then issues an access token scoped
    to your Auth0 API.
    """
    resp = requests.post(
        f"https://{AUTH0_DOMAIN}/oauth/token",
        data={
            "grant_type":    "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "client_id":     AUTH0_CLIENT_ID,
            "client_secret": AUTH0_CLIENT_SECRET,
            "assertion":     id_jag,             # The ID-JAG from Okta
            "resource":      AUTH0_API_AUDIENCE, # Auth0 API Identifier
            "connection":    AUTH0_CONNECTION,   # Okta Enterprise connection in Auth0
        },
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        timeout=10,
    )

    if not resp.ok:
        print(f"\n[Step 3] FAILED — Auth0 token exchange ({resp.status_code})")
        print(resp.text)
        resp.raise_for_status()

    access_token = resp.json().get("access_token")
    if not access_token:
        raise ValueError("No access_token returned by Auth0.")

    print(f"\n[Step 3] Auth0 access token acquired.")
    print(f"         access_token (first 40 chars): {access_token[:40]}…")
    return access_token


# ── Step 4: Call the protected API ───────────────────────────────────────────

def call_api(auth0_access_token: str) -> dict:
    url = f"{API_BASE_URL}/data"
    resp = requests.get(
        url,
        headers={"Authorization": f"Bearer {auth0_access_token}"},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    print("=== XAA Agent: Cross-App Access Flow ===\n")

    # Step 1: User logs in via browser → Okta id_token
    okta_id_token = get_okta_id_token()

    # Step 2: Exchange id_token at Okta → ID-JAG targeted at Auth0
    id_jag = get_id_jag_from_okta(okta_id_token)

    # Step 3: Exchange ID-JAG at Auth0 → Auth0 access token
    auth0_access_token = get_auth0_access_token(id_jag)

    # Step 4: Call the API
    print("\n[Step 4] Calling protected API…")
    result = call_api(auth0_access_token)

    print("\n[API] Response:")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    try:
        main()
    except requests.HTTPError as e:
        print(f"\nHTTP error: {e}", file=sys.stderr)
        sys.exit(1)
