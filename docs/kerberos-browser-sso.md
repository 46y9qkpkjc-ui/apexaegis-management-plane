# Browser Kerberos SSO (SPNEGO) — deploy & config runbook

Silent, password-free sign-in to the admin console for a **domain-joined browser**
— the point being April inside her `AD.APEXAEGIS.APP` WorkSpace, where typing or
pasting a password into a nested remote session is painful. On a domain-joined
machine the browser obtains a Kerberos service ticket and signs in with no prompt.

## Flow

```
Browser (domain-joined WorkSpace)                 MP (api.apexaegis.app)
  │  GET /api/v1/auth/negotiate?redirect_uri=<web-ui>/login
  │ ───────────────────────────────────────────────▶
  │  401 + WWW-Authenticate: Negotiate               │  (no Authorization yet)
  │ ◀───────────────────────────────────────────────
  │  (browser silently gets a ticket for HTTP/api.apexaegis.app from the DC)
  │  GET …/negotiate  Authorization: Negotiate <SPNEGO>
  │ ───────────────────────────────────────────────▶
  │                                                  │  validate ticket OFFLINE
  │                                                  │  against the keytab →
  │                                                  │  principal user@REALM →
  │                                                  │  resolve users row →
  │  302 <web-ui>/login?code=<one-time>&method=kerberos  mint 2-min code
  │ ◀───────────────────────────────────────────────
  │  POST /api/v1/auth/negotiate/exchange { code }   │
  │ ───────────────────────────────────────────────▶  redeem code → issue
  │  { access_token, refresh_token, user }           │  access+refresh tokens
  │ ◀───────────────────────────────────────────────
```

Full-page navigation (not fetch) is used for the challenge, so cross-origin CORS
never applies to the Negotiate handshake. Only the final `exchange` is a normal
cross-origin POST (code in the body, no cookies) — already allowed by the MP CORS
middleware for the console origins.

Endpoints (see `internal/api/handlers/negotiate_handler.go`):
- `GET  /api/v1/auth/negotiate` — challenge + validate + redirect-with-code.
- `POST /api/v1/auth/negotiate/exchange` — swap the one-time code for tokens.

The validator is the **same offline keytab validator** as the agent Kerberos path
(`internal/security/kerberos.go`), so configuring the keytab unblocks both. If the
keytab is not configured, `/negotiate` returns `503` and the console falls back to
OIDC / credentials.

## Prerequisites (infra / Windows side — NOT code)

1. **SPN + keytab (AD).** Register the console SPN to the MP service account and
   export a keytab:
   ```
   setspn -S HTTP/api.apexaegis.app svc-apex-mp
   ktpass -princ HTTP/api.apexaegis.app@AD.APEXAEGIS.APP -mapuser svc-apex-mp \
          -crypto AES256-SHA1 -ptype KRB5_NT_PRINCIPAL -pass <pw> -out apex-mp.keytab
   base64 -w0 apex-mp.keytab   # store the result in SSM SecureString
   ```
   Note: `HTTP/api.apexaegis.app` — the browser requests a ticket for the host it
   navigates to (the MP), not the web-UI host.

2. **MP env (from SSM).** Keytab/SPN/realm gate the agent and browser paths;
   the UPN suffix is browser-SSO only:
   - `MP_KRB5_KEYTAB_B64` — base64 keytab (SecureString).
   - `MP_KRB5_SPN` — `HTTP/api.apexaegis.app@AD.APEXAEGIS.APP`.
   - `MP_KRB5_REALM` — `AD.APEXAEGIS.APP` (enforced; a ticket from another realm is rejected).
   - `MP_KRB5_UPN_SUFFIX` — `apexaegis.app`. The ticket principal is
     `sAMAccountName@REALM` (`…@AD.APEXAEGIS.APP`), but seeded `users.email` uses the
     routable UPN (`…@apexaegis.app`); this lets the handler fall back to
     `sAMAccountName@<suffix>` when the exact principal doesn't match. Omit only if
     the UPN suffix equals the realm.

3. **Browser Integrated Auth (WorkSpace GPO / policy).** `api.apexaegis.app` must
   be trusted for Windows Integrated Auth so the browser sends the ticket:
   - Edge/IE zones: add `api.apexaegis.app` to **Local Intranet** (or Trusted Sites)
     with *Automatic logon with current user name and password*.
   - Chrome/Edge policy: `AuthServerAllowlist = "api.apexaegis.app"`
     (and `AuthNegotiateDelegateAllowlist` if delegation is needed).
   Push via GPO to the WorkSpace image.

4. **Seed the demo users so the principal resolves** (migration 046). The handler
   maps the Kerberos principal to a `users` row via `ResolveUserByEmail` — trying
   the exact principal (`sAMAccountName@REALM`) then `sAMAccountName@<UPN suffix>`.
   With `MP_KRB5_UPN_SUFFIX=apexaegis.app`, seed **`users.email` = the UPN**:
   - April Woon → `april.woon.starhub@apexaegis.app`, `operator_scope='StarHub'`.
   - Evelyn Ng  → `evelyn.ng.aspire@apexaegis.app`, no `operator_scope`.
   No password is stored — these users are AD-authenticated only.

## Failure modes (surfaced to the login page as `?sso_error`)

- `kerberos_validation_failed` — ticket didn't validate (clock skew, wrong keytab,
  SPN mismatch, non-domain machine). Falls back to credentials.
- `principal_not_provisioned` — valid ticket, but no `users` row matches the
  principal email. Fix the seed (step 4).
- Browser shows a native username/password box instead of silent SSO → the site
  isn't in the Integrated-Auth allowlist (step 3).

## Test coverage (what's verified without a domain)

- One-time code round-trip + forgery/typ rejection: `internal/db/kerberos_code_test.go`.
- Open-redirect guard on `redirect_uri`: `internal/api/handlers/negotiate_test.go`.
- Offline SPNEGO validation itself: `internal/security/kerberos_test.go` (existing).

End-to-end silent sign-in can only be exercised on a domain-joined browser with the
keytab deployed — i.e. from the WorkSpace once steps 1–4 are done.
