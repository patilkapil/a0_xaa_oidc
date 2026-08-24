# XAA — Cross-App Access: Okta → Auth0

A minimal working implementation of **Cross-App Access (XAA)** where **Okta** acts as the Identity Provider and **Auth0** acts as the Resource Server protecting an API.

Built and tested against:
- Auth0 docs: https://auth0.com/docs/ai-agents-mcp/cross-app-access/end-to-end-testing
- Auth0 blog: https://auth0.com/blog/setting-up-testing-cross-app-access-auth0/

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                        USER'S BROWSER                               │
│                    http://localhost:5000                             │
└──────────────────────────┬──────────────────────────────────────────┘
                           │
                    ┌──────▼──────┐
                    │   ui.py     │  Flask web UI (browser flow + session)
                    │  :5000      │
                    └──────┬──────┘
                           │
          ┌────────────────┼──────────────────────────────────┐
          │                │                                   │
   Step 0 │         Step 1 │                        Steps 2–4 │
   (Auth0 │  (Okta login,  │                    (delegated to │
 provision)│   ui.py only) │                      agent.py)   │
          ▼                ▼                                   ▼
  ┌───────────────┐ ┌─────────────┐               ┌───────────────────┐
  │    Auth0      │ │    Okta     │               │     agent.py      │
  │ Universal     │ │  Org AS     │               │  Requesting Entity│
  │ Login         │ │ /oauth2/v1  │               │  (importable core)│
  │ (provision)   │ │ /authorize  │               └────────┬──────────┘
  └───────────────┘ └─────────────┘                        │
                                                 Step 2     │  id_token → ID-JAG
                                                            ▼
                                                   ┌───────────────┐
                                                   │     Okta      │
                                                   │   Org AS      │
                                                   │  /oauth2/v1   │
                                                   │  /token       │
                                                   └───────┬───────┘
                                                           │ ID-JAG
                                                 Step 3    ▼
                                                   ┌───────────────┐
                                                   │    Auth0      │
                                                   │  /oauth/token │
                                                   │ (jwt-bearer)  │
                                                   └───────┬───────┘
                                                           │ Auth0 access token
                                                 Step 4    ▼
                                                   ┌───────────────┐
                                                   │  api_server   │
                                                   │    :8080      │
                                                   │  /data        │
                                                   └───────────────┘
```

---

## How It Works

### Step 0 — Provision User in Auth0 (one-time per user)
The user logs in via **Auth0 Universal Login** using the `KP-XAA` Enterprise OIDC connection, which federates to Okta. This creates the user's profile in Auth0's user store. Auth0 does not support JIT provisioning via ID-JAG, so this step is required once per user before XAA can work.

### Step 1 — Okta Login → ID Token *(demo scaffolding)*
The UI kicks off an **Authorization Code + PKCE** flow against the **Okta Org Authorization Server** (`/oauth2/v1/authorize`). The user authenticates with Okta and the server exchanges the auth code for an `id_token`.

> **Note:** This step is handled by `ui.py`, not `agent.py`. It exists in this demo to simulate how the user's identity reaches the agent. In a real deployment, the agent receives the `id_token` (or a trigger carrying the user's identity) from your platform — the browser login is not part of the agent's job.

> **Important:** Must use the Okta **Org AS** (`/oauth2/v1`), not the Default Custom AS (`/oauth2/default/v1`). Only the Org AS supports XAA features.

### Step 2 — ID Token → ID-JAG (at Okta) *(agent takes over from here)*
The server performs a **Token Exchange** (RFC 8693) at the Okta Org AS, presenting the `id_token` and requesting an **ID-JAG** (Identity Assertion Authorization Grant):

```
grant_type           = urn:ietf:params:oauth:grant-type:token-exchange
requested_token_type = urn:ietf:params:oauth:token-type:id-jag
subject_token_type   = urn:ietf:params:oauth:token-type:id_token
subject_token        = <okta id_token>
audience             = https://smalser5.eu.auth0.com        ← Auth0 tenant issuer (who can CONSUME this ID-JAG, not the API resource)
scope                = xaa:read
```

Okta validates the id_token, confirms the audience matches a registered XAA Resource App, and returns the ID-JAG in the `access_token` field.

### Step 3 — ID-JAG → Auth0 Access Token (at Auth0)
The server presents the ID-JAG to Auth0 using the **JWT Bearer** grant:

```
grant_type    = urn:ietf:params:oauth:grant-type:jwt-bearer
client_id     = <Auth0 requesting app client ID>    ← identifies WHICH APP is asking
client_secret = <Auth0 requesting app secret>       ← proves the app is legitimate
assertion     = <ID-JAG>                            ← signed JWT carrying the USER's delegated identity
resource      = https://api.my-xaa-mcp-server.com/ ← the API audience being requested
connection    = KP-XAA                              ← which Enterprise connection to look up the user against
```

`client_id` + `client_secret` authenticate the **requesting app** (who is asking).
`assertion` carries the **user's delegated identity** (on whose behalf).
Both are required — one without the other will fail.

Auth0 validates the ID-JAG signature against Okta's JWKS, confirms the audience matches
the Auth0 tenant, looks up the user via the `KP-XAA` connection, and issues an
**Auth0 access token** scoped to `https://api.my-xaa-mcp-server.com/`.

### Step 4 — Call the API
The Auth0 access token is used as a Bearer token to call the protected API (`api_server.py`), which validates it against Auth0's JWKS endpoint and returns data.

---

## Code Design: Agent as the Requesting Entity

A key goal of this POC is to make it obvious **which code represents the agent** and which is just demo scaffolding.

### The separation

| File | Role | What it owns |
|---|---|---|
| `ui.py` | Demo scaffolding | Browser login (Step 1), PKCE, Flask session, provisioning flow |
| `agent.py` | Requesting entity | Steps 2–4: ID-JAG exchange, Auth0 token exchange, API call |
| `api_server.py` | Protected resource | JWT validation, API response |

### Why this matters

In a real deployment, your agent does not open a browser. It receives the user's identity from whatever triggered it (an orchestration layer, a session store, a prior login event) and then autonomously runs Steps 2–4 to obtain delegated access. No user interaction is needed after initial provisioning.

This POC simulates that by having `ui.py` handle the browser login and hand the `id_token` to `agent.py` at the `/callback` route:

```python
# ui.py — /callback route
okta_tokens = _exchange_code_for_id_token(code, verifier)  # ui.py gets id_token from Okta
id_token    = okta_tokens["id_token"]

# Hand off to the agent (requesting entity).
# In production, your agent receives the id_token from whatever triggered it
# and runs Steps 2–4 autonomously — no further user interaction needed.
id_jag             = get_id_jag_from_okta(id_token)    # agent.py
auth0_access_token = get_auth0_access_token(id_jag)    # agent.py
api_data           = call_api(auth0_access_token)       # agent.py
```

### Embedding this in your real agent

`agent.py` is designed to be imported, not just run. To add XAA to any agentic framework:

```python
from agent import get_id_jag_from_okta, get_auth0_access_token, call_api

# Inside your agent's tool/action handler:
id_jag             = get_id_jag_from_okta(user_id_token)
auth0_access_token = get_auth0_access_token(id_jag)
result             = call_api(auth0_access_token)
```

The three functions are stateless HTTP calls — no Flask, no session, no browser dependency. Drop them into a LangChain tool, a CrewAI agent action, an MCP server handler, or any other framework.

---

## Token Flow Summary

```
Okta id_token
    │
    │  Token Exchange at Okta Org AS
    │  audience = https://smalser5.eu.auth0.com
    │  scope    = xaa:read
    ▼
ID-JAG  (JWT issued by Okta, intended for Auth0)
    │
    │  JWT Bearer grant at Auth0
    │  resource   = https://api.my-xaa-mcp-server.com/
    │  connection = KP-XAA
    ▼
Auth0 Access Token
    │
    │  Bearer token
    ▼
Protected API  →  { data }
```

---

## Project Structure

```
a0_xaa_oidc/
├── agent.py         # Requesting entity core: Steps 2–4 (importable module + CLI demo)
├── ui.py            # Flask web UI: browser/PKCE flow, calls agent.py for Steps 2–4
├── api_server.py    # Protected API: validates Auth0 Bearer tokens via JWKS
├── templates/
│   └── index.html   # Jinja2 template for the web UI
├── .env             # Your real credentials (never commit — in .gitignore)
├── .env.example     # Template with all required variables and comments
└── requirements.txt # Python dependencies
```

> **Why two files for the flow?** `agent.py` owns the XAA logic (Steps 2–4). `ui.py` owns the browser interaction (Step 1 + session management). This separation makes it easy to see exactly which part of the code represents the agent — and to lift that code into any real agentic framework.

---

## Setup

### 1. Install dependencies

```bash
pip install -r requirements.txt
```

### 2. Configure environment variables

```bash
cp .env.example .env
```

Edit `.env` with your real values:

| Variable | Where to find it |
|---|---|
| `OKTA_DOMAIN` | Okta Admin → top-right org URL (hostname only) |
| `OKTA_CLIENT_ID` | Okta Admin → Applications → agent app → General → Client ID |
| `OKTA_CLIENT_SECRET` | Okta Admin → Applications → agent app → General → Client Secrets |
| `AUTH0_DOMAIN` | Auth0 Dashboard → Settings → General → Domain |
| `AUTH0_API_AUDIENCE` | Auth0 Dashboard → Applications → APIs → your API → Identifier |
| `AUTH0_CLIENT_ID` | Auth0 Dashboard → Applications → Requesting App → Settings → Client ID |
| `AUTH0_CLIENT_SECRET` | Auth0 Dashboard → Applications → Requesting App → Settings → Client Secret |
| `AUTH0_CONNECTION` | Auth0 Dashboard → Authentication → Enterprise → your Okta connection → Name |
| `AUTH0_API_SCOPE` | Scope registered on Okta Resource App (e.g. `xaa:read`) |

### 3. Register redirect URIs

**In Okta** (Admin → Applications → agent app → General → Sign-in redirect URIs):
```
http://localhost:5000/callback
```

**In Auth0** (Dashboard → Applications → Requesting App → Settings → Allowed Callback URLs):
```
http://localhost:5000/provision/callback
```

### 4. Okta configuration checklist

- [ ] AI Agent app created in Okta with `ai_agent` profile
- [ ] Resource App created as **OIDC** app in Okta (not SAML)
- [ ] Resource App has **Cross-App Access (XAA) enabled** with Issuer URL = `https://<your-auth0-domain>`
- [ ] Resource App assigned to the AI Agent via **Resource connections** with scope `xaa:read`
- [ ] Both apps use the **Okta Org AS** (`/oauth2/v1`), not the Default Custom AS

### 5. Auth0 configuration checklist

- [ ] Enterprise OIDC connection (`KP-XAA`) configured pointing to Okta
- [ ] API created with identifier matching `AUTH0_API_AUDIENCE`
- [ ] Requesting App (M2M or Regular Web App) authorised to call the API
- [ ] Requesting App has `http://localhost:5000/provision/callback` in Allowed Callback URLs

---

## Running

### Terminal 1 — Start the API server
```bash
cd "/path/to/XAA_A0_OIDC/a0_xaa_oidc"
python api_server.py
# Runs on http://localhost:8080
```

### Terminal 2 — Start the UI
```bash
cd "/path/to/XAA_A0_OIDC/a0_xaa_oidc"
python ui.py
# Runs on http://localhost:5000
# ui.py imports agent.py automatically — no separate process needed
```

### In the browser

1. Open `http://localhost:5000`
2. Click **Step 0: Login via Auth0 (Okta)** — logs you in via Auth0's Okta Enterprise connection to provision your user profile *(one-time per user)*
3. Click **Run XAA Flow** — performs the full XAA token exchange and calls the API
4. The page displays all three tokens and the API response

---

## API Endpoints Used

### Okta Org Authorization Server

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `https://{OKTA_DOMAIN}/oauth2/v1/authorize` | Step 1a — initiate user login (PKCE) |
| `POST` | `https://{OKTA_DOMAIN}/oauth2/v1/token` | Step 1b — exchange auth code → id_token |
| `POST` | `https://{OKTA_DOMAIN}/oauth2/v1/token` | Step 2 — exchange id_token → ID-JAG (`token-exchange` grant) |

### Auth0

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `https://{AUTH0_DOMAIN}/authorize` | Step 0 — provision user via Universal Login |
| `POST` | `https://{AUTH0_DOMAIN}/oauth/token` | Step 0 callback — exchange auth code |
| `POST` | `https://{AUTH0_DOMAIN}/oauth/token` | Step 3 — exchange ID-JAG → access token (`jwt-bearer` grant) |
| `GET` | `https://{AUTH0_DOMAIN}/.well-known/jwks.json` | API server — fetch public keys to validate JWT |

### Protected API (local)

| Method | Endpoint | Purpose |
|---|---|---|
| `GET` | `http://localhost:8080/data` | Step 4 — fetch protected resource with Auth0 access token |

---

## Key Lessons Learned

1. **Okta Org AS, not Default AS** — The ID-JAG token type (`urn:ietf:params:oauth:token-type:id-jag`) is only supported by the Okta Org Authorization Server at `/oauth2/v1`. The Default Custom AS at `/oauth2/default/v1` returns `invalid_requested_token_type`.

2. **Audience = Auth0 tenant issuer, no trailing slash** — The `audience` in the ID-JAG request must exactly match the Issuer URL configured on the Okta Resource App (e.g. `https://smalser5.eu.auth0.com` without a trailing slash).

3. **Scope = xaa:read, not openid** — The scope for the ID-JAG exchange is the resource-specific scope registered on the Okta Resource App, not `openid`.

4. **Auth0 requires pre-provisioned users** — Auth0 does not support JIT user creation via ID-JAG. Users must authenticate via the Auth0 Enterprise connection at least once to create their profile before XAA can act on their behalf.

5. **Resource App must be OIDC, not SAML** — The Okta Resource App representing Auth0 must be created as an OIDC application for the jwt-bearer token exchange to work at Auth0.
