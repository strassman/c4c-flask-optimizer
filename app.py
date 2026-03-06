import os, math, uuid, hashlib, requests, urllib.parse, base64, json
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from flask_session import Session
from supabase import create_client
from geopy.geocoders import Nominatim

# ── Token encryption ───────────────────────────────────────────────────────────
# Fernet symmetric encryption for OAuth tokens at rest.
# INTEGRATION_KEY must be a 32-url-safe-base64 bytes key set in Railway env vars.
# Generate with: python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
try:
    from cryptography.fernet import Fernet
    _raw_key = os.environ.get("INTEGRATION_KEY", "")
    _fernet  = Fernet(_raw_key.encode()) if _raw_key else None
except Exception:
    _fernet = None

def encrypt_token(token: str) -> str:
    """Encrypt an OAuth token for storage. Falls back to base64 if key not set."""
    if not token: return ""
    if _fernet:
        return _fernet.encrypt(token.encode()).decode()
    # Fallback: obfuscate only — set INTEGRATION_KEY in production!
    return base64.b64encode(token.encode()).decode()

def decrypt_token(stored: str) -> str:
    """Decrypt a stored OAuth token."""
    if not stored: return ""
    if _fernet:
        try:
            return _fernet.decrypt(stored.encode()).decode()
        except Exception:
            return ""
    try:
        return base64.b64decode(stored.encode()).decode()
    except Exception:
        return ""

# ── Integration provider registry ─────────────────────────────────────────────
# Each entry describes one OAuth provider. Credentials come from env vars.
# Scopes and URLs will be filled in when you obtain API access from each vendor.
INTEGRATIONS = {
    "ngpvan": {
        "name":          "NGP VAN",
        "logo":          "🗳️",
        "description":   "Voter file, contact history, survey responses, volunteer data",
        "color":         "#1a5fa8",
        "auth_url":      os.environ.get("VAN_AUTH_URL",    "https://auth.ngpvan.com/oauth2/authorize"),
        "token_url":     os.environ.get("VAN_TOKEN_URL",   "https://auth.ngpvan.com/oauth2/token"),
        "client_id":     os.environ.get("VAN_CLIENT_ID",   ""),
        "client_secret": os.environ.get("VAN_CLIENT_SECRET",""),
        "scope":         "contacts voterFile surveys",
        "docs":          "https://developers.ngpvan.com/van-api",
        "status":        "coming_soon",   # change to "enabled" once you have API access
    },
    "nationbuilder": {
        "name":          "NationBuilder",
        "logo":          "🏛️",
        "description":   "People database, membership, donations, events, tags",
        "color":         "#e8562a",
        "auth_url":      "https://{slug}.nationbuilder.com/oauth/authorize",
        "token_url":     "https://{slug}.nationbuilder.com/oauth/token",
        "client_id":     os.environ.get("NB_CLIENT_ID",    ""),
        "client_secret": os.environ.get("NB_CLIENT_SECRET",""),
        "scope":         "people donations",
        "docs":          "https://nationbuilder.com/api_documentation",
        "status":        "coming_soon",
    },
    "actblue": {
        "name":          "ActBlue",
        "logo":          "💙",
        "description":   "Donation records, donor contact info, fundraising data",
        "color":         "#2655a0",
        "auth_url":      "",   # ActBlue uses API key auth, not OAuth — handled separately
        "token_url":     "",
        "client_id":     os.environ.get("ACTBLUE_CLIENT_ID",""),
        "client_secret": os.environ.get("ACTBLUE_CLIENT_SECRET",""),
        "scope":         "",
        "docs":          "https://secure.actblue.com/docs/api",
        "status":        "coming_soon",
    },
    "catalist": {
        "name":          "Catalist",
        "logo":          "📊",
        "description":   "National voter file, modeling scores, demographic data",
        "color":         "#2d6a4f",
        "auth_url":      "",
        "token_url":     "",
        "client_id":     os.environ.get("CATALIST_CLIENT_ID",""),
        "client_secret": os.environ.get("CATALIST_CLIENT_SECRET",""),
        "scope":         "",
        "docs":          "https://catalist.us",
        "status":        "coming_soon",
    },
}

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-change-me")

# Server-side filesystem sessions — no 4KB cookie limit
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = "/tmp/flask_sessions"
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_USE_SIGNER"] = True
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
Session(app)

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY")

if not SUPABASE_URL or not SUPABASE_KEY:
    print("WARNING: SUPABASE_URL or SUPABASE_KEY not set!", flush=True)
else:
    print(f"Supabase OK: {SUPABASE_URL[:40]}", flush=True)

COLORS     = ["red","blue","green","orange","purple","darkred","cadetblue","darkgreen"]
HEX_COLORS = ["#e74c3c","#3498db","#2ecc71","#f39c12","#9b59b6","#c0392b","#5f9ea0","#27ae60"]

# ── DB ─────────────────────────────────────────────────────────────────────────
def db():
    return create_client(SUPABASE_URL, SUPABASE_KEY)

def hp(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def load_all(cid):
    keys = ["vols","addrs","run_ids","done","history","runs"]
    ids  = [f"{cid}_{k}" for k in keys]
    try:
        rows = db().table("campaign_data").select("id,data").in_("id", ids).execute().data
        lk   = {r["id"]: r["data"] for r in rows}
        return {k: lk.get(f"{cid}_{k}", []) for k in keys}
    except:
        return {k: [] for k in keys}

def save_data(cid, key, val):
    try:
        db().table("campaign_data").upsert({"id": f"{cid}_{key}", "data": val}).execute()
    except:
        pass

# ── Auth helpers ───────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "cid" not in session:
            return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated

def get_cache_bust(cid):
    """Get the latest cache bust timestamp from DB."""
    try:
        rows = db().table("campaign_data").select("data").eq("id", f"{cid}_cache_bust").execute().data
        return rows[0]["data"].get("t","") if rows else ""
    except:
        return ""

def get_data():
    """Get campaign data from session cache, reloading if vols have made updates."""
    cid = session["cid"]
    # Always check if a volunteer has busted the cache since last load
    current_bust = get_cache_bust(cid)
    cache_stale  = (session.get("loaded_for") != cid or
                    session.get("cache_bust_ts","") != current_bust)
    if cache_stale:
        d = load_all(cid)
        session["vols"]          = d["vols"]    or []
        session["addrs"]         = d["addrs"]   or []
        session["run_ids"]       = d["run_ids"] or []
        session["done"]          = d["done"]    or []
        session["history"]       = d["history"] or []
        session["runs"]          = d["runs"]    or []
        session["loaded_for"]    = cid
        session["cache_bust_ts"] = current_bust
    return {
        "vols":    session.get("vols", []),
        "addrs":   session.get("addrs", []),
        "run_ids": session.get("run_ids", []),
        "done":    {c["key"]:c for c in session.get("done", [])},
        "history": session.get("history", []),
        "runs":    session.get("runs", []),
        "cname":   session.get("cname", "Campaign"),
        "cid":     cid,
    }

def save_session(key, val):
    session[key] = val
    session.modified = True
    save_data(session["cid"], key, val)

# ── Geocoding ──────────────────────────────────────────────────────────────────
_geocache = {}

def geocode(addr):
    if addr in _geocache:
        return _geocache[addr]
    try:
        r = requests.get(
            "https://geocoding.geo.census.gov/geocoder/locations/onelineaddress",
            params={"address": addr, "benchmark": "2020", "format": "json"}, timeout=5)
        m = r.json().get("result", {}).get("addressMatches", [])
        if m:
            c = m[0]["coordinates"]
            result = (c["y"], c["x"])
            _geocache[addr] = result
            return result
    except: pass
    try:
        loc = Nominatim(user_agent="campaign_opt").geocode(addr, timeout=5)
        if loc:
            result = (loc.latitude, loc.longitude)
            _geocache[addr] = result
            return result
    except: pass
    return None, None

# ── Routing ────────────────────────────────────────────────────────────────────
def hav(a, b):
    R = 6371
    la1,lo1,la2,lo2 = map(math.radians,[a[0],a[1],b[0],b[1]])
    return R*2*math.asin(math.sqrt(
        math.sin((la2-la1)/2)**2 + math.cos(la1)*math.cos(la2)*math.sin((lo2-lo1)/2)**2))

def osrm_matrix(pts):
    try:
        coords = ";".join(f"{b},{a}" for a,b in pts)
        r = requests.get(
            f"https://router.project-osrm.org/table/v1/driving/{coords}?annotations=distance",
            timeout=20)
        d = r.json()
        if d.get("code") == "Ok":
            return [[x/1000 for x in row] for row in d["distances"]]
    except: pass
    return [[hav(pts[i],pts[j]) for j in range(len(pts))] for i in range(len(pts))]

def osrm_route(wps):
    try:
        coords = ";".join(f"{b},{a}" for a,b in wps)
        r = requests.get(
            f"https://router.project-osrm.org/route/v1/driving/{coords}?overview=full&geometries=geojson",
            timeout=20)
        d = r.json()
        if d.get("code") == "Ok":
            return [[p[1],p[0]] for p in d["routes"][0]["geometry"]["coordinates"]]
    except: pass
    return [[a,b] for a,b in wps]

def solve_tsp(fm, hi, stops):
    if not stops: return [], 0.0
    n = len(stops)
    sub = [[fm[stops[i]][stops[j]] for j in range(n)] for i in range(n)]
    def nn(s):
        vis=[False]*n; r=[s]; vis[s]=True
        for _ in range(n-1):
            last=r[-1]; bj,bd=-1,1e18
            for j in range(n):
                if not vis[j] and sub[last][j]<bd: bd=sub[last][j]; bj=j
            r.append(bj); vis[bj]=True
        return r
    def two_opt(r):
        imp=True
        while imp:
            imp=False
            for i in range(1,n-1):
                for j in range(i+1,n):
                    if sub[r[i-1]][r[i]]+sub[r[j]][r[(j+1)%n]]>sub[r[i-1]][r[j]]+sub[r[i]][r[(j+1)%n]]+1e-10:
                        r[i:j+1]=r[i:j+1][::-1]; imp=True
        return r
    br,bc = None,1e18
    for s in range(n):
        ro = two_opt(nn(s)); fr = [stops[x] for x in ro]
        cost = fm[hi][fr[0]]+sum(fm[fr[k]][fr[k+1]] for k in range(len(fr)-1))+fm[fr[-1]][hi]
        if cost < bc: bc=cost; br=fr
    return br, round(bc*0.621371, 2)

def gmaps_url(o, d):
    return f"https://www.google.com/maps/dir/{urllib.parse.quote(o)}/{urllib.parse.quote(d)}"

def gen_email(r, cname):
    v=r["volunteer"]; s=r["stops"]; mi=r.get("distance_miles","—")
    mi_str = f" (~{mi} mi)" if mi != "—" else ""
    lines=[f"Hi {v['name']},",f"\nThank you for volunteering for {cname}!",
           f"\nYou have {len(s)} stop{'s' if len(s)!=1 else ''}{mi_str}:\n"]
    for i,stop in enumerate(s):
        prev=v["address"] if i==0 else s[i-1]["address"]
        lines+=[f"  Stop {i+1}: {stop['address']}",f"  Directions: {gmaps_url(prev,stop['address'])}\n"]
    lines+=[f"Return home: {v['address']}",f"\nThank you!\n{cname} Team"]
    return "\n".join(lines)

# CSV column detection
FMAP = {
    "addr":  ["address","street_address","addr","street","address1","mailing_address"],
    "first": ["first_name","firstname","fname","first"],
    "last":  ["last_name","lastname","lname","last"],
    "email": ["email","email_address"],
    "phone": ["phone","phone_number","mobile","cell"],
    "city":  ["city","town"],
    "state": ["state","state_code"],
    "zip":   ["zip","zipcode","zip_code","postal_code"],
}
def detect_col(cols, key):
    cl = {c.lower().strip().replace(" ","_"): c for c in cols}
    for k in FMAP.get(key, []):
        if k in cl: return cl[k]
    return None

# ══════════════════════════════════════════════════════════════════════════════
# INTEGRATION DB HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def get_integrations(cid: str) -> dict:
    """Load all integration records for a campaign. Returns dict keyed by provider."""
    try:
        rows = db().table("campaign_integrations")                    .select("*").eq("campaign_id", cid).execute().data
        return {r["provider"]: r for r in rows}
    except Exception:
        return {}

def save_integration(cid: str, provider: str, data: dict):
    """Upsert an integration record. Tokens must already be encrypted."""
    try:
        db().table("campaign_integrations").upsert({
            "campaign_id": cid,
            "provider":    provider,
            **data,
        }, on_conflict="campaign_id,provider").execute()
    except Exception as e:
        print(f"save_integration error: {e}", flush=True)

def delete_integration(cid: str, provider: str):
    """Remove an integration (disconnect)."""
    try:
        db().table("campaign_integrations")             .delete().eq("campaign_id", cid).eq("provider", provider).execute()
    except Exception as e:
        print(f"delete_integration error: {e}", flush=True)

def integration_connected(cid: str, provider: str) -> bool:
    """Quick check — is this provider connected for this campaign?"""
    intgs = get_integrations(cid)
    rec   = intgs.get(provider)
    return bool(rec and rec.get("status") == "connected" and rec.get("access_token_enc"))

# ── Read-only data fetchers ────────────────────────────────────────────────────
# These functions pull data from external APIs and MAP it to our internal
# constituent schema. They never write back to the external system.
# Implement the body once you have API credentials.

def fetch_van_contacts(cid: str, limit: int = 500) -> list:
    """
    Pull contacts from NGP VAN API (read-only).
    Maps VAN fields → our constituent schema.
    Returns list of dicts ready to merge into d["addrs"].
    """
    intgs = get_integrations(cid)
    rec   = intgs.get("ngpvan")
    if not rec or rec.get("status") != "connected":
        return []
    token = decrypt_token(rec.get("access_token_enc", ""))
    if not token:
        return []
    # ── TODO: implement when VAN API access obtained ───────────────────────
    # docs: https://developers.ngpvan.com/van-api#people-get-people
    # base = "https://api.securevan.com/v4"
    # headers = {"Authorization": f"Basic {token}", "Content-Type": "application/json"}
    # resp = requests.get(f"{base}/people/search", headers=headers,
    #                     params={"$top": limit}, timeout=15)
    # raw = resp.json().get("items", [])
    # return [_map_van_contact(c) for c in raw]
    return []

def _map_van_contact(raw: dict) -> dict:
    """Map a single VAN contact record to our schema. READ ONLY — never write back."""
    addr_parts = raw.get("primaryAddress", {})
    address    = ", ".join(filter(None, [
        addr_parts.get("addressLine1",""),
        addr_parts.get("city",""),
        addr_parts.get("stateOrProvince",""),
        addr_parts.get("zipOrPostalCode",""),
    ]))
    return {
        "id":            str(uuid.uuid4()),
        "address":       address,
        "first_name":    raw.get("firstName",""),
        "last_name":     raw.get("lastName",""),
        "contact":       f"{raw.get('firstName','')} {raw.get('lastName','')}".strip(),
        "phone":         (raw.get("phones") or [{}])[0].get("phoneNumber",""),
        "email":         (raw.get("emails") or [{}])[0].get("email",""),
        "voter_id":      str(raw.get("vanId","")),
        "party":         raw.get("party",""),
        "precinct":      raw.get("precinct",{}).get("name","") if raw.get("precinct") else "",
        "support_score": str(raw.get("supportScore","")) if raw.get("supportScore") else "",
        "status":        "pending",
        "source":        "ngpvan",       # marks record as read-only import
        "source_id":     str(raw.get("vanId","")),
    }

def fetch_nb_people(cid: str, limit: int = 500) -> list:
    """
    Pull people from NationBuilder API (read-only).
    Maps NB fields → our constituent schema.
    """
    intgs = get_integrations(cid)
    rec   = intgs.get("nationbuilder")
    if not rec or rec.get("status") != "connected":
        return []
    token = decrypt_token(rec.get("access_token_enc", ""))
    slug  = rec.get("nb_slug","")
    if not token or not slug:
        return []
    # ── TODO: implement when NB API access obtained ────────────────────────
    # docs: https://nationbuilder.com/people_api
    # base = f"https://{slug}.nationbuilder.com/api/v1"
    # headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
    # resp = requests.get(f"{base}/people", headers=headers,
    #                     params={"limit": limit}, timeout=15)
    # raw = resp.json().get("results", [])
    # return [_map_nb_person(p) for p in raw]
    return []

def _map_nb_person(raw: dict) -> dict:
    """Map a NationBuilder person to our schema. READ ONLY."""
    addr = ", ".join(filter(None,[
        raw.get("primary_address",{}).get("address1",""),
        raw.get("primary_address",{}).get("city",""),
        raw.get("primary_address",{}).get("state",""),
        raw.get("primary_address",{}).get("zip",""),
    ]))
    return {
        "id":             str(uuid.uuid4()),
        "address":        addr,
        "first_name":     raw.get("first_name",""),
        "last_name":      raw.get("last_name",""),
        "contact":        f"{raw.get('first_name','')} {raw.get('last_name','')}".strip(),
        "phone":          raw.get("phone",""),
        "email":          raw.get("email",""),
        "party":          raw.get("party",""),
        "precinct":       raw.get("precinct",""),
        "support_score":  str(raw.get("support_level","")) if raw.get("support_level") else "",
        "donor":          bool(raw.get("is_donor")),
        "volunteer_interest": bool(raw.get("is_volunteer")),
        "tags":           [t.get("name","") for t in raw.get("tags",[])],
        "status":         "pending",
        "source":         "nationbuilder",
        "source_id":      str(raw.get("id","")),
    }

# ══════════════════════════════════════════════════════════════════════════════
# AUTH ROUTES
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/", methods=["GET","POST"])
def login_page():
    if "cid" in session:
        return redirect(url_for("volunteers"))
    error = None
    if request.method == "POST":
        action = request.form.get("action")
        email  = request.form.get("email","").lower().strip()
        pw     = request.form.get("password","")
        if action == "login":
            try:
                res = db().table("campaign_accounts").select("*").eq("email",email).execute()
                if not res.data:
                    error = "No account found with that email."
                elif res.data[0]["password_hash"] != hp(pw):
                    error = "Wrong password."
                else:
                    a = res.data[0]
                    session.clear()
                    session["cid"]   = a["id"]
                    session["cname"] = a["campaign_name"]
                    return redirect(url_for("volunteers"))
            except Exception as e:
                error = str(e)
        elif action == "signup":
            cname  = request.form.get("cname","").strip()
            pw2    = request.form.get("password2","")
            if not cname or not email or not pw:
                error = "All fields required."
            elif pw != pw2:
                error = "Passwords don't match."
            elif len(pw) < 6:
                error = "Password must be 6+ characters."
            else:
                try:
                    ex = db().table("campaign_accounts").select("id").eq("email",email).execute()
                    if ex.data:
                        error = "Email already registered."
                    else:
                        nid = str(uuid.uuid4())
                        db().table("campaign_accounts").insert({
                            "id":nid,"campaign_name":cname,
                            "email":email,"password_hash":hp(pw)
                        }).execute()
                        session.clear()
                        session["cid"]   = nid
                        session["cname"] = cname
                        return redirect(url_for("volunteers"))
                except Exception as e:
                    error = str(e)
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))

# ══════════════════════════════════════════════════════════════════════════════
# INTEGRATIONS PAGE
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/integrations", methods=["GET","POST"])
@login_required
def integrations_page():
    cid   = session["cid"]
    intgs = get_integrations(cid)
    msg   = None

    if request.method == "POST":
        action   = request.form.get("action")
        provider = request.form.get("provider","")

        if action == "disconnect":
            delete_integration(cid, provider)
            msg = f"Disconnected {INTEGRATIONS.get(provider,{}).get('name', provider)}."

        elif action == "manual_api_key":
            # For providers that use API keys instead of OAuth (ActBlue, Catalist)
            api_key = request.form.get("api_key","").strip()
            if api_key:
                save_integration(cid, provider, {
                    "status":           "connected",
                    "access_token_enc": encrypt_token(api_key),
                    "auth_type":        "api_key",
                    "connected_at":     datetime.now().isoformat(),
                    "last_sync":        None,
                    "nb_slug":          request.form.get("nb_slug","").strip(),
                })
                msg = f"Connected {INTEGRATIONS.get(provider,{}).get('name', provider)}."
            else:
                msg = "API key required."

        elif action == "sync":
            # Trigger a read-only data pull and merge into campaign data
            provider_name = INTEGRATIONS.get(provider,{}).get("name", provider)
            if provider == "ngpvan":
                contacts = fetch_van_contacts(cid)
            elif provider == "nationbuilder":
                contacts = fetch_nb_people(cid)
            else:
                contacts = []

            if contacts:
                d = get_data()
                existing_source_ids = {a.get("source_id") for a in d["addrs"] if a.get("source_id")}
                new_records = [c for c in contacts if c.get("source_id") not in existing_source_ids]
                d["addrs"].extend(new_records)
                save_session("addrs", d["addrs"])
                # Update last_sync timestamp
                if provider in intgs:
                    rec = intgs[provider]
                    rec["last_sync"] = datetime.now().isoformat()
                    save_integration(cid, provider, rec)
                msg = f"Synced {len(new_records)} new records from {provider_name}."
            else:
                msg = f"No new records from {provider_name} (API not yet configured)."

        return redirect(url_for("integrations_page"))

    return render_template("integrations.html",
                           integrations=INTEGRATIONS,
                           connected=intgs,
                           msg=msg)

# ── OAuth flow ─────────────────────────────────────────────────────────────────
@app.route("/integrations/connect/<provider>")
@login_required
def oauth_connect(provider):
    """
    Step 1: Redirect the campaign to the provider's OAuth authorization page.
    State param prevents CSRF — we store cid in it (signed by session).
    """
    cfg = INTEGRATIONS.get(provider)
    if not cfg or cfg.get("status") == "coming_soon":
        return redirect(url_for("integrations_page"))
    if not cfg.get("client_id"):
        return redirect(url_for("integrations_page"))

    # For NationBuilder we need the campaign's NB slug first
    if provider == "nationbuilder":
        nb_slug = request.args.get("slug","").strip()
        if not nb_slug:
            return redirect(url_for("integrations_page"))
        session["nb_slug"] = nb_slug
        auth_url = cfg["auth_url"].replace("{slug}", nb_slug)
        token_url = cfg["token_url"].replace("{slug}", nb_slug)
    else:
        auth_url = cfg["auth_url"]

    state        = hashlib.sha256(f"{session['cid']}{app.secret_key}".encode()).hexdigest()
    session["oauth_state"]    = state
    session["oauth_provider"] = provider

    callback = url_for("oauth_callback", provider=provider, _external=True)
    params = {
        "response_type": "code",
        "client_id":     cfg["client_id"],
        "redirect_uri":  callback,
        "scope":         cfg.get("scope",""),
        "state":         state,
    }
    return redirect(auth_url + "?" + urllib.parse.urlencode(params))


@app.route("/integrations/callback/<provider>")
@login_required
def oauth_callback(provider):
    """
    Step 2: Provider redirects back here with an authorization code.
    We exchange it for an access token and store it encrypted.
    """
    cfg   = INTEGRATIONS.get(provider, {})
    error = request.args.get("error")
    code  = request.args.get("code")
    state = request.args.get("state")
    cid   = session["cid"]

    # Validate state to prevent CSRF
    expected = hashlib.sha256(f"{cid}{app.secret_key}".encode()).hexdigest()
    if state != expected or session.get("oauth_state") != state:
        return redirect(url_for("integrations_page"))
    if error or not code:
        return redirect(url_for("integrations_page"))

    # Exchange code for token
    nb_slug   = session.pop("nb_slug", "")
    token_url = cfg.get("token_url","")
    if provider == "nationbuilder" and nb_slug:
        token_url = token_url.replace("{slug}", nb_slug)

    callback = url_for("oauth_callback", provider=provider, _external=True)
    try:
        resp = requests.post(token_url, data={
            "grant_type":    "authorization_code",
            "code":          code,
            "redirect_uri":  callback,
            "client_id":     cfg["client_id"],
            "client_secret": cfg["client_secret"],
        }, timeout=15)
        token_data = resp.json()
    except Exception as e:
        print(f"OAuth token exchange error ({provider}): {e}", flush=True)
        return redirect(url_for("integrations_page"))

    access_token  = token_data.get("access_token","")
    refresh_token = token_data.get("refresh_token","")
    expires_in    = token_data.get("expires_in", 3600)

    if not access_token:
        return redirect(url_for("integrations_page"))

    save_integration(cid, provider, {
        "status":            "connected",
        "access_token_enc":  encrypt_token(access_token),
        "refresh_token_enc": encrypt_token(refresh_token),
        "token_expiry":      (datetime.now() + timedelta(seconds=expires_in)).isoformat(),
        "auth_type":         "oauth2",
        "connected_at":      datetime.now().isoformat(),
        "last_sync":         None,
        "nb_slug":           nb_slug,
        "scopes":            cfg.get("scope",""),
    })

    session.pop("oauth_state", None)
    session.pop("oauth_provider", None)
    return redirect(url_for("integrations_page"))

# ══════════════════════════════════════════════════════════════════════════════
# VOLUNTEERS
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/volunteers", methods=["GET","POST"])
@login_required
def volunteers():
    d = get_data()
    msg = None
    if request.method == "POST":
        action = request.form.get("action")
        cid = d["cid"]
        if action == "add":
            name = request.form.get("name","").strip()
            street = request.form.get("street","").strip()
            city   = request.form.get("city","").strip()
            state  = request.form.get("state","").strip()
            zipcode= request.form.get("zip","").strip()
            if name and street and city and state and zipcode:
                addr = f"{street}, {city}, {state} {zipcode}"
                skills_raw = request.form.get("skills","").strip()
                avail_raw  = request.form.get("availability","").strip()
                d["vols"].append({"name":name,
                    "first_name":    request.form.get("vfirst","").strip(),
                    "last_name":     request.form.get("vlast","").strip(),
                    "email":         request.form.get("email","").strip(),
                    "phone":         request.form.get("phone","").strip(),
                    "address":       addr,
                    "has_vehicle":   request.form.get("has_vehicle") == "1",
                    "skills":        [s.strip() for s in skills_raw.split(",") if s.strip()],
                    "availability":  avail_raw,
                    "shirt_size":    request.form.get("shirt_size","").strip(),
                    "emergency_contact": request.form.get("emergency_contact","").strip(),
                    "emergency_phone":   request.form.get("emergency_phone","").strip(),
                    "note":          request.form.get("vnote","").strip(),
                    "runs_completed": 0,
                    "joined_date":   datetime.now().strftime("%b %d, %Y"),
                })
                save_session("vols", d["vols"])
                msg = f"✅ {name} added!"
            else:
                msg = "❌ Name, street, city, state, ZIP required."
        elif action == "delete":
            name = request.form.get("name")
            d["vols"] = [v for v in d["vols"] if v["name"] != name]
            save_session("vols", d["vols"])
            msg = "Volunteer removed."
        elif action == "update_vol":
            vid = request.form.get("vol_id_key")
            for v in d["vols"]:
                if v.get("id","") == vid or v["name"] == vid:
                    for field in ["name","email","phone","first_name","last_name",
                                  "shirt_size","availability","emergency_contact",
                                  "emergency_phone","note"]:
                        val = request.form.get(field,"").strip()
                        if val: v[field] = val
                    skills_raw = request.form.get("skills","").strip()
                    v["skills"] = [s.strip() for s in skills_raw.split(",") if s.strip()]
                    v["has_vehicle"] = request.form.get("has_vehicle") == "1"
                    break
            save_session("vols", d["vols"])
        elif action == "clear":
            save_session("vols", [])
            d["vols"] = []
            msg = "All volunteers cleared."
        elif action == "import_csv":
            import csv, io
            f = request.files.get("csv_file")
            if f:
                content = f.read().decode("utf-8-sig")
                reader  = csv.DictReader(io.StringIO(content))
                cols    = reader.fieldnames or []
                existing = {v["name"].lower() for v in d["vols"]}
                added = 0
                for row in reader:
                    fn = row.get(detect_col(cols,"first"),"").strip() if detect_col(cols,"first") else ""
                    ln = row.get(detect_col(cols,"last"),"").strip()  if detect_col(cols,"last")  else ""
                    name = (fn+" "+ln).strip()
                    if not name or name.lower() in existing: continue
                    ac=detect_col(cols,"addr"); cc=detect_col(cols,"city")
                    sc=detect_col(cols,"state"); zc=detect_col(cols,"zip")
                    addr = row.get(ac,"").strip() if ac else ""
                    parts=[p for p in [row.get(cc,"").strip() if cc else "",
                                       row.get(sc,"").strip() if sc else "",
                                       row.get(zc,"").strip() if zc else ""] if p]
                    if parts: addr += ", "+", ".join(parts)
                    ec=detect_col(cols,"email"); pc=detect_col(cols,"phone")
                    d["vols"].append({"name":name,
                        "email":row.get(ec,"").strip() if ec else "",
                        "phone":row.get(pc,"").strip() if pc else "",
                        "address":addr})
                    existing.add(name.lower()); added+=1
                save_session("vols", d["vols"])
                msg = f"Imported {added} volunteers."
    return render_template("volunteers.html", d=d, msg=msg)

# ══════════════════════════════════════════════════════════════════════════════
# CONSTITUENTS
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/constituents", methods=["GET","POST"])
@login_required
def constituents():
    d = get_data()
    msg = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            street  = request.form.get("street","").strip()
            city    = request.form.get("city","").strip()
            state   = request.form.get("state","").strip()
            zipcode = request.form.get("zip","").strip()
            if street and city and state and zipcode:
                addr = f"{street}, {city}, {state} {zipcode}"
                tags_raw = request.form.get("tags","").strip()
                entry = {"id":str(uuid.uuid4()),"address":addr,
                    # Basic contact
                    "contact":       request.form.get("contact","").strip(),
                    "first_name":    request.form.get("first_name","").strip(),
                    "last_name":     request.form.get("last_name","").strip(),
                    "phone":         request.form.get("phone","").strip(),
                    "email":         request.form.get("email","").strip(),
                    "note":          request.form.get("note","").strip(),
                    # Voter profile
                    "voter_id":      request.form.get("voter_id","").strip(),
                    "party":         request.form.get("party","").strip(),
                    "precinct":      request.form.get("precinct","").strip(),
                    "ward":          request.form.get("ward","").strip(),
                    "district":      request.form.get("district","").strip(),
                    "support_score": request.form.get("support_score","").strip(),
                    "relationship":  request.form.get("relationship","supporter"),
                    "language":      request.form.get("language","").strip(),
                    "best_contact_time": request.form.get("best_contact_time","").strip(),
                    # Vote history
                    "voted_2024g":   request.form.get("voted_2024g") == "1",
                    "voted_2024p":   request.form.get("voted_2024p") == "1",
                    "voted_2022g":   request.form.get("voted_2022g") == "1",
                    "voted_2022p":   request.form.get("voted_2022p") == "1",
                    "voted_2020g":   request.form.get("voted_2020g") == "1",
                    # Engagement
                    "sign_requested":    request.form.get("sign_requested") == "1",
                    "volunteer_interest":request.form.get("volunteer_interest") == "1",
                    "donor":             request.form.get("donor") == "1",
                    "donation_amount":   request.form.get("donation_amount","").strip(),
                    "tags":              [t.strip() for t in tags_raw.split(",") if t.strip()],
                    # Canvass tracking
                    "canvass_result":    request.form.get("canvass_result","").strip(),
                    "canvass_date":      request.form.get("canvass_date","").strip(),
                    "canvassed_by":      request.form.get("canvassed_by","").strip(),
                    "status":            "pending"}
                lat,lng = geocode(addr)
                if lat: entry["lat"]=lat; entry["lng"]=lng
                d["addrs"].append(entry)
                save_session("addrs", d["addrs"])
                msg = "✅ Address added!"
            else:
                msg = "❌ Street, city, state, ZIP required."
        elif action == "delete":
            addr = request.form.get("address")
            d["addrs"]   = [a for a in d["addrs"]   if a["address"]!=addr]
            d["run_ids"] = [r for r in d["run_ids"] if r not in {a["id"] for a in d["addrs"]}]
            save_session("addrs",   d["addrs"])
            save_session("run_ids", d["run_ids"])
        elif action == "clear_all":
            save_session("addrs",   [])
            save_session("run_ids", [])
            d["addrs"] = []; d["run_ids"] = []
        elif action == "clear_pending":
            pids = {a["id"] for a in d["addrs"] if a.get("status")!="delivered"}
            d["addrs"]   = [a for a in d["addrs"]   if a["id"] not in pids]
            d["run_ids"] = [r for r in d["run_ids"] if r not in pids]
            save_session("addrs",   d["addrs"])
            save_session("run_ids", d["run_ids"])
        elif action == "clear_delivered":
            d["addrs"] = [a for a in d["addrs"] if a.get("status")!="delivered"]
            save_session("addrs", d["addrs"])
        elif action == "mark_delivered":
            addr = request.form.get("address")
            for a in d["addrs"]:
                if a["address"]==addr:
                    a["status"]="delivered"
                    a["delivered_date"]=datetime.now().strftime("%b %d, %Y")
            save_session("addrs", d["addrs"])
        elif action == "undo_delivery":
            addr = request.form.get("address")
            for a in d["addrs"]:
                if a["address"]==addr: a["status"]="pending"
            save_session("addrs", d["addrs"])
        elif action == "update_voter":
            vid = request.form.get("voter_id_key")
            for a in d["addrs"]:
                if a["id"] == vid:
                    for field in ["contact","first_name","last_name","phone","email","note",
                                  "voter_id","party","precinct","ward","district","support_score",
                                  "relationship","language","best_contact_time",
                                  "canvass_result","canvass_date","canvassed_by","donation_amount"]:
                        val = request.form.get(field,"").strip()
                        if val or field in ["support_score","relationship"]: a[field] = val
                    tags_raw = request.form.get("tags","").strip()
                    a["tags"] = [t.strip() for t in tags_raw.split(",") if t.strip()]
                    for flag in ["sign_requested","volunteer_interest","donor",
                                 "voted_2024g","voted_2024p","voted_2022g","voted_2022p","voted_2020g"]:
                        a[flag] = request.form.get(flag) == "1"
                    break
            save_session("addrs", d["addrs"])
        elif action == "import_csv":
            import csv, io
            f = request.files.get("csv_file")
            if f:
                content = f.read().decode("utf-8-sig")
                reader  = csv.DictReader(io.StringIO(content))
                cols    = reader.fieldnames or []
                existing = {a["address"].lower() for a in d["addrs"]}
                added = 0
                for row in reader:
                    ac=detect_col(cols,"addr"); cc=detect_col(cols,"city")
                    sc=detect_col(cols,"state"); zc=detect_col(cols,"zip")
                    addr = row.get(ac,"").strip() if ac else ""
                    if not addr: continue
                    parts=[p for p in [row.get(cc,"").strip() if cc else "",
                                       row.get(sc,"").strip() if sc else "",
                                       row.get(zc,"").strip() if zc else ""] if p]
                    if parts: addr+=", "+", ".join(parts)
                    if addr.lower() in existing: continue
                    fn=detect_col(cols,"first"); ln=detect_col(cols,"last")
                    f_=row.get(fn,"").strip() if fn else ""
                    l_=row.get(ln,"").strip() if ln else ""
                    ec=detect_col(cols,"email"); pc=detect_col(cols,"phone")
                    entry={"id":str(uuid.uuid4()),"address":addr,
                        "contact":(f_+" "+l_).strip(),
                        "phone":row.get(pc,"").strip() if pc else "",
                        "email":row.get(ec,"").strip() if ec else "",
                        "note":"","status":"pending"}
                    lat,lng=geocode(addr)
                    if lat: entry["lat"]=lat; entry["lng"]=lng
                    d["addrs"].append(entry); existing.add(addr.lower()); added+=1
                save_session("addrs", d["addrs"])
                msg = f"Imported {added} addresses."
        return redirect(url_for("constituents"))
    return render_template("constituents.html", d=d, msg=msg)

# ══════════════════════════════════════════════════════════════════════════════
# DELIVERY RUN
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/delivery-run", methods=["GET","POST"])
@login_required
def delivery_run():
    d = get_data()
    msg = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "save_run":
            avail   = request.form.getlist("avail")
            run_ids = request.form.getlist("run_ids")
            session["avail"]   = avail
            session["run_ids"] = run_ids
            save_data(d["cid"], "run_ids", run_ids)
            msg = "Run saved!"
        elif action == "clear_run":
            session["avail"]   = []
            session["run_ids"] = []
            save_data(d["cid"], "run_ids", [])
        elif action == "add_address":
            street  = request.form.get("street","").strip()
            city    = request.form.get("city","").strip()
            state   = request.form.get("state","").strip()
            zipcode = request.form.get("zip","").strip()
            if street and city and state and zipcode:
                addr = f"{street}, {city}, {state} {zipcode}"
                entry = {"id":str(uuid.uuid4()),"address":addr,
                    "contact":request.form.get("contact","").strip(),
                    "phone":request.form.get("phone","").strip(),
                    "note":request.form.get("note","").strip(),
                    "status":"pending"}
                lat,lng=geocode(addr)
                if lat: entry["lat"]=lat; entry["lng"]=lng
                d["addrs"].append(entry)
                d["run_ids"].append(entry["id"])
                save_session("addrs",   d["addrs"])
                save_session("run_ids", d["run_ids"])
                msg = "Address added to run!"
        elif action in ("optimize","proximity"):
            avail   = request.form.getlist("avail")
            run_ids = request.form.getlist("run_ids")
            session["avail"]   = avail
            session["run_ids"] = run_ids
            avols  = [v for v in d["vols"] if v.get("name") and v["name"] in avail]
            raddrs = [a for a in d["addrs"] if a["id"] in set(run_ids) and a.get("address")]
            if not avols:  return render_template("delivery_run.html", d=d, msg="❌ Select at least one volunteer.")
            if not raddrs: return render_template("delivery_run.html", d=d, msg="❌ Add at least one address.")
            # Geocode volunteers
            vr=[]
            for v in avols:
                lat,lng=geocode(v["address"])
                if not lat: return render_template("delivery_run.html", d=d, msg=f"❌ Could not geocode: {v['address']}")
                vr.append({**v,"lat":lat,"lng":lng})
            # Geocode addresses
            dr=[]; addr_updated=False
            for a in raddrs:
                lat,lng=a.get("lat"),a.get("lng")
                if not lat:
                    lat,lng=geocode(a["address"])
                    if lat:
                        for x in d["addrs"]:
                            if x["id"]==a["id"]: x["lat"]=lat; x["lng"]=lng; addr_updated=True
                if lat: dr.append({**a,"lat":lat,"lng":lng})
            if addr_updated: save_session("addrs", d["addrs"])
            if not dr: return render_template("delivery_run.html", d=d, msg="❌ No addresses could be geocoded.")

            ts  = datetime.now().strftime("%b %d, %Y at %I:%M %p")
            run_id = str(uuid.uuid4())
            if action == "optimize":
                pts = [(v["lat"],v["lng"]) for v in vr]+[(x["lat"],x["lng"]) for x in dr]
                nv  = len(vr)
                fm  = osrm_matrix(pts)
                clusters = {i:[] for i in range(nv)}
                for di in range(len(dr)):
                    bv = min(range(nv), key=lambda vi: fm[vi][nv+di])
                    clusters[bv].append(nv+di)
                routes=[]
                for vi,vol in enumerate(vr):
                    if not clusters[vi]: continue
                    order,dist=solve_tsp(fm,vi,clusters[vi])
                    stops=[dr[idx-nv] for idx in order]
                    wps=[(vol["lat"],vol["lng"])]+[(s["lat"],s["lng"]) for s in stops]+[(vol["lat"],vol["lng"])]
                    routes.append({"volunteer":vol,"stops":stops,
                        "distance_miles":dist,"road_geometry":osrm_route(wps),
                        "color":COLORS[vi%len(COLORS)],"hex":HEX_COLORS[vi%len(HEX_COLORS)]})
                run_type = "optimized"
            else:  # proximity
                clusters={i:[] for i in range(len(vr))}
                for x in dr:
                    best=min(range(len(vr)),key=lambda vi:hav((vr[vi]["lat"],vr[vi]["lng"]),(x["lat"],x["lng"])))
                    clusters[best].append(x)
                routes=[]
                for vi,vol in enumerate(vr):
                    if not clusters[vi]: continue
                    routes.append({"volunteer":vol,"stops":clusters[vi],
                        "distance_miles":"—","road_geometry":None,
                        "color":COLORS[vi%len(COLORS)],"hex":HEX_COLORS[vi%len(HEX_COLORS)]})
                run_type = "proximity"

            total_stops = sum(len(r["stops"]) for r in routes)
            vol_names   = [r["volunteer"]["name"] for r in routes]
            auto_name   = f"{ts[:6]} · {len(routes)} vol{'s' if len(routes)!=1 else ''} · {total_stops} stops"
            new_run = attach_vol_tokens({
                "id":          run_id,
                "cid":         d["cid"],
                "name":        auto_name,
                "timestamp":   ts,
                "type":        run_type,
                "status":      "active",
                "routes":      routes,
                "done_keys":   [],
                "total_stops": total_stops,
                "vol_names":   vol_names,
            })
            runs = d.get("runs", [])
            runs.insert(0, new_run)
            save_session("runs", runs)
            save_token_index(new_run)
            # Also keep history for backwards compat
            rec = {"timestamp": ts + (" (proximity)" if run_type=="proximity" else ""), "routes": routes}
            d["history"] = [rec] + (d["history"] or [])
            save_session("history", d["history"])
            session["active_run_id"] = run_id
            return redirect(url_for("map_page"))
        return redirect(url_for("delivery_run"))

    avail = session.get("avail", [])
    # Pass address coords for proximity sorting in JS
    addr_coords = [{"id": a["id"], "lat": a.get("lat"), "lng": a.get("lng")}
                   for a in d["addrs"] if a.get("lat")]
    # Pass vol coords for sorting too
    for v in d["vols"]:
        if not v.get("lat"):
            lat, lng = geocode(v["address"])
            if lat: v["lat"] = lat; v["lng"] = lng
    return render_template("delivery_run.html", d=d, msg=msg, avail=avail, addr_coords=addr_coords)

# ══════════════════════════════════════════════════════════════════════════════
# MAP
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/map")
@login_required
def map_page():
    d = get_data()
    runs = d.get("runs", [])
    active_run_id = session.get("active_run_id")

    # Find active run to display
    active_run = None
    if active_run_id:
        active_run = next((r for r in runs if r["id"] == active_run_id), None)
    if not active_run and runs:
        active_run = next((r for r in runs if r.get("status") == "active"), None)

    # Compute completion for each run
    for run in runs:
        done_set = set(run.get("done_keys", []))
        total = run.get("total_stops", 0)
        done_count = sum(
            1 for r in run.get("routes", [])
            for i, s in enumerate(r.get("stops", []))
            if r["volunteer"]["name"] + "_" + str(i) in done_set
        )
        run["done_count"] = done_count
        run["pct"] = round(done_count / total * 100) if total else 0
        if total > 0 and done_count >= total:
            run["status"] = "complete"

    return render_template("map.html", d=d,
                           runs=runs,
                           active_run=active_run,
                           HEX_COLORS=HEX_COLORS, COLORS=COLORS)

@app.route("/map/select/<run_id>")
@login_required
def map_select_run(run_id):
    session["active_run_id"] = run_id
    return redirect(url_for("map_page"))

@app.route("/map/reset")
@login_required
def map_reset():
    session.pop("active_run_id", None)
    return redirect(url_for("map_page"))

# ══════════════════════════════════════════════════════════════════════════════
# ROUTES / RUNS
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/routes", methods=["GET","POST"])
@login_required
def routes_page():
    d    = get_data()
    runs = d.get("runs", [])
    if request.method == "POST":
        action = request.form.get("action")
        run_id = request.form.get("run_id")

        if action == "delete_run":
            runs = [r for r in runs if r["id"] != run_id]
            save_session("runs", runs)
            if session.get("active_run_id") == run_id:
                session.pop("active_run_id", None)

        elif action in ("mark_done", "unmark_done"):
            key  = request.form.get("key")
            addr = request.form.get("address")
            for run in runs:
                if run["id"] == run_id:
                    done_keys = set(run.get("done_keys", []))
                    if action == "mark_done":
                        done_keys.add(key)
                        # Also mark in constituent list
                        for a in d["addrs"]:
                            if a["address"] == addr:
                                a["status"] = "delivered"
                                a["delivered_date"] = datetime.now().strftime("%b %d, %Y")
                        save_session("addrs", d["addrs"])
                    else:
                        done_keys.discard(key)
                        for a in d["addrs"]:
                            if a["address"] == addr: a["status"] = "pending"
                        save_session("addrs", d["addrs"])
                    run["done_keys"] = list(done_keys)
                    # Recheck completion
                    total = run.get("total_stops", 0)
                    if total > 0 and len(done_keys) >= total:
                        run["status"] = "complete"
                    else:
                        run["status"] = "active"
                    break
            save_session("runs", runs)

        elif action == "rename_run":
            new_name = request.form.get("new_name","").strip()
            for run in runs:
                if run["id"] == run_id and new_name:
                    run["name"] = new_name
                    break
            save_session("runs", runs)

        elif action == "close_run":
            for run in runs:
                if run["id"] == run_id:
                    run["status"] = "complete"
                    break
            save_session("runs", runs)

        elif action == "reopen_run":
            for run in runs:
                if run["id"] == run_id:
                    run["status"] = "active"
                    break
            save_session("runs", runs)

        return redirect(url_for("routes_page") + (f"?run_id={run_id}" if run_id else ""))

    # Compute completion stats
    for run in runs:
        done_set = set(run.get("done_keys", []))
        total    = run.get("total_stops", 0)
        done_ct  = sum(
            1 for r in run.get("routes",[])
            for i, s in enumerate(r.get("stops",[]))
            if r["volunteer"]["name"]+"_"+str(i) in done_set
        )
        run["done_count"] = done_ct
        run["pct"]        = round(done_ct/total*100) if total else 0

    selected_run_id = request.args.get("run_id") or (runs[0]["id"] if runs else None)
    selected_run    = next((r for r in runs if r["id"] == selected_run_id), runs[0] if runs else None)

    return render_template("routes.html", d=d, runs=runs,
                           selected_run=selected_run,
                           gmaps_url=gmaps_url)

# ══════════════════════════════════════════════════════════════════════════════
# ROUTE SEARCH
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/routes/search")
@login_required
def routes_search():
    d     = get_data()
    q     = request.args.get("q","").lower().strip()
    done  = {c["key"]:c for c in session.get("done",[])}
    results = []
    if q:
        for rec in d["history"]:
            for r in rec.get("routes",[]):
                vol = r.get("volunteer",{})
                matched_stops = []
                for i,s in enumerate(r.get("stops",[])):
                    if (q in s.get("address","").lower() or
                        q in s.get("contact","").lower() or
                        q in s.get("phone","").lower() or
                        q in vol.get("name","").lower() or
                        q in rec.get("timestamp","").lower()):
                        matched_stops.append({"stop":s,"index":i,
                            "key":vol.get("name","")+"_"+str(i),
                            "done": (vol.get("name","")+"_"+str(i)) in done})
                if matched_stops or q in vol.get("name","").lower():
                    if not matched_stops:
                        matched_stops = [{"stop":s,"index":i,
                            "key":vol.get("name","")+"_"+str(i),
                            "done":(vol.get("name","")+"_"+str(i)) in done}
                            for i,s in enumerate(r.get("stops",[]))]
                    results.append({"timestamp":rec.get("timestamp",""),
                        "volunteer":vol,"stops":matched_stops,"hex":r.get("hex","#4a9eff")})
    return render_template("routes_search.html", d=d, q=q, results=results, gmaps_url=gmaps_url)

# ══════════════════════════════════════════════════════════════════════════════
# EMAILS & TEXTS
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/emails")
@login_required
def emails_page():
    d      = get_data()
    routes = session.get("routes", [])
    emails = []
    for r in routes:
        v    = r["volunteer"]
        body = gen_email(r, d["cname"])
        subj = f"{d['cname']} - Your Yard Sign Delivery Route"
        ve   = v.get("email","")
        vp   = v.get("phone","").translate(str.maketrans("","","- ()"))
        stops_txt="\n".join([f"  {i+1}. {s['address'].split(',')[0]}" for i,s in enumerate(r["stops"])])
        txt=(f"Hi {v['name']}! {d['cname']} here. "
             f"{len(r['stops'])} stop{'s' if len(r['stops'])!=1 else ''} today:\n{stops_txt}\nFull route by email!")
        emails.append({"volunteer":v,"body":body,"subj":subj,
            "mailto":f"mailto:{ve}?"+urllib.parse.urlencode({"subject":subj,"body":body}) if ve else "",
            "sms":f"sms:{vp}&body={urllib.parse.quote(txt)}" if vp else "",
            "txt":txt})
    # Bulk
    all_em = ",".join([r["volunteer"].get("email","") for r in routes if r["volunteer"].get("email")])
    all_ph = ",".join([r["volunteer"].get("phone","").translate(str.maketrans("","","- ()"))
                       for r in routes if r["volunteer"].get("phone")])
    all_bodies = "\n\n---\n\n".join([e["body"] for e in emails])
    bulk_subj = f"{d['cname']} - Your Yard Sign Delivery Route"
    bulk_mailto = f"mailto:{all_em}?"+urllib.parse.urlencode({"subject":bulk_subj,"body":all_bodies}) if all_em else ""
    bulk_lines="\n".join([f"{r['volunteer']['name']}: "+
        ", ".join([s["address"].split(",")[0] for s in r["stops"][:3]])+
        ("…" if len(r["stops"])>3 else "") for r in routes])
    bulk_txt=f"{d['cname']} delivery run:\n{bulk_lines}\nFull details by email. Thank you!"
    bulk_sms=f"sms:{all_ph}&body={urllib.parse.quote(bulk_txt)}" if all_ph else ""
    return render_template("emails.html", d=d, emails=emails,
                           bulk_mailto=bulk_mailto, bulk_sms=bulk_sms,
                           all_em_count=len([r for r in routes if r["volunteer"].get("email")]),
                           all_ph_count=len([r for r in routes if r["volunteer"].get("phone")]))

import csv, io
from flask import Response

@app.route("/constituents/export")
@login_required
def export_csv():
    d = get_data()
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=["status","address","contact","phone","email","note","delivered_date"])
    writer.writeheader()
    for a in d["addrs"]:
        writer.writerow({"status":"placed" if a.get("status")=="delivered" else "pending","address":a.get("address",""),"contact":a.get("contact",""),"phone":a.get("phone",""),"email":a.get("email",""),"note":a.get("note",""),"delivered_date":a.get("delivered_date","")})
    return Response(output.getvalue(), mimetype="text/csv", headers={"Content-Disposition":"attachment;filename=constituents.csv"})


# ══════════════════════════════════════════════════════════════════════════════
# VOLUNTEER DELIVERY PORTAL (public — token auth only)
# ══════════════════════════════════════════════════════════════════════════════

SUPABASE_BUCKET = "sign-photos"

def get_run_by_token(run_id: str, vol_token: str):
    """
    Look up a run by vol token. Uses fast index first, falls back to full scan.
    Returns (cid, run, vol_name) or (None, None, None).
    """
    # Fast path: token index
    try:
        idx_rows = db().table("campaign_data").select("data") \
                       .eq("id", f"token_index_{run_id}").execute().data
        if idx_rows and idx_rows[0]["data"]:
            entry = idx_rows[0]["data"].get(vol_token)
            if entry:
                cid = entry["cid"]
                run_rows = db().table("campaign_data").select("data") \
                               .eq("id", f"{cid}_runs").execute().data
                runs = run_rows[0]["data"] if run_rows else []
                run  = next((r for r in runs if r["id"] == run_id), None)
                if run:
                    return cid, run, entry["vol_name"]
    except Exception as e:
        print(f"get_run_by_token fast path error: {e}", flush=True)

    # Slow fallback: scan all campaign run lists (works for old runs)
    try:
        rows = db().table("campaign_data").select("id,data") \
                   .like("id", "%_runs").execute().data
        for row in rows:
            if not row["id"].endswith("_runs"):
                continue
            cid = row["id"][:-5]
            for run in (row["data"] or []):
                if run.get("id") != run_id:
                    continue
                for vt in run.get("vol_tokens", []):
                    if vt.get("token") == vol_token:
                        return cid, run, vt.get("vol_name")
    except Exception as e:
        print(f"get_run_by_token slow path error: {e}", flush=True)

    return None, None, None

def upload_photo(cid: str, run_id: str, stop_key: str, file_bytes: bytes, mime: str) -> str:
    """Upload a sign photo to Supabase Storage. Returns public URL or ''."""
    try:
        path = f"{cid}/{run_id}/{stop_key}_{uuid.uuid4().hex[:8]}.jpg"
        db().storage.from_(SUPABASE_BUCKET).upload(
            path, file_bytes,
            {"content-type": mime, "cache-control": "3600", "upsert": "true"}
        )
        url = db().storage.from_(SUPABASE_BUCKET).get_public_url(path)
        return url
    except Exception as e:
        print(f"upload_photo error: {e}", flush=True)
        return ""

def save_photo_record(cid: str, run_id: str, stop_key: str, vol_name: str,
                      photo_url: str, lat=None, lng=None):
    """Save photo metadata to campaign_data sign_photos list."""
    try:
        key    = f"{cid}_sign_photos"
        rows   = db().table("campaign_data").select("data").eq("id", key).execute().data
        photos = rows[0]["data"] if rows else []
        photos.append({
            "id":        str(uuid.uuid4()),
            "run_id":    run_id,
            "stop_key":  stop_key,
            "vol_name":  vol_name,
            "photo_url": photo_url,
            "lat":       lat,
            "lng":       lng,
            "taken_at":  datetime.now().isoformat(),
        })
        db().table("campaign_data").upsert({"id": key, "data": photos}).execute()
    except Exception as e:
        print(f"save_photo_record error: {e}", flush=True)

def get_photos(cid: str) -> list:
    try:
        rows = db().table("campaign_data").select("data")                    .eq("id", f"{cid}_sign_photos").execute().data
        return rows[0]["data"] if rows else []
    except:
        return []

@app.route("/deliver/<run_id>/<vol_token>", methods=["GET","POST"])
def vol_deliver(run_id, vol_token):
    """Public volunteer delivery portal — no login required."""
    cid, run, vol_name = get_run_by_token(run_id, vol_token)
    if not run:
        return render_template("deliver_invalid.html"), 404

    # Check expiry — 72 hours
    try:
        created = datetime.fromisoformat(run.get("timestamp_iso", run["timestamp"]))
        if (datetime.now() - created).total_seconds() > 72 * 3600:
            return render_template("deliver_expired.html", run=run), 410
    except:
        pass

    # Find this volunteer's route
    vol_route = next((r for r in run.get("routes",[])
                      if r["volunteer"]["name"] == vol_name), None)
    if not vol_route:
        return render_template("deliver_invalid.html"), 404

    done_set = set(run.get("done_keys", []))
    photos   = get_photos(cid)
    photo_map = {p["stop_key"]: p for p in photos if p.get("run_id") == run_id}

    if request.method == "POST":
        action   = request.form.get("action")
        stop_key = request.form.get("stop_key")

        if action == "mark_done" and stop_key:
            # Load run from DB, update done_keys, save back
            try:
                rows = db().table("campaign_data").select("data")                            .eq("id", f"{cid}_runs").execute().data
                runs = rows[0]["data"] if rows else []
                for r in runs:
                    if r["id"] == run_id:
                        dk = set(r.get("done_keys", []))
                        dk.add(stop_key)
                        r["done_keys"] = list(dk)
                        # Update status
                        total = r.get("total_stops", 1)
                        if len(dk) >= total:
                            r["status"] = "complete"
                        # Also mark constituent as delivered
                        addr_rows = db().table("campaign_data").select("data")                                         .eq("id", f"{cid}_addrs").execute().data
                        addrs = addr_rows[0]["data"] if addr_rows else []
                        stop_idx = int(stop_key.split("_")[-1])
                        stop_addr = vol_route["stops"][stop_idx]["address"] if stop_idx < len(vol_route["stops"]) else ""
                        for a in addrs:
                            if a.get("address") == stop_addr:
                                a["status"] = "delivered"
                                a["delivered_date"] = datetime.now().strftime("%b %d, %Y")
                                a["delivered_by"] = vol_name
                        db().table("campaign_data").upsert({"id": f"{cid}_runs",  "data": runs}).execute()
                        db().table("campaign_data").upsert({"id": f"{cid}_addrs", "data": addrs}).execute()
                        # Bust session cache so campaign dashboard sees update immediately
                        db().table("campaign_data").upsert({"id": f"{cid}_cache_bust", "data": {"t": datetime.now().isoformat()}}).execute()
                        break
            except Exception as e:
                print(f"vol mark_done error: {e}", flush=True)

        elif action == "upload_photo" and stop_key:
            photo_file = request.files.get("photo")
            lat = request.form.get("lat")
            lng = request.form.get("lng")
            if photo_file and photo_file.filename:
                file_bytes = photo_file.read()
                url = upload_photo(cid, run_id, stop_key, file_bytes, photo_file.mimetype)
                if url:
                    save_photo_record(cid, run_id, stop_key, vol_name, url,
                                      float(lat) if lat else None,
                                      float(lng) if lng else None)
                    # Also auto-mark the stop done and mark constituent delivered
                    try:
                        rows = db().table("campaign_data").select("data")                                    .eq("id", f"{cid}_runs").execute().data
                        runs = rows[0]["data"] if rows else []
                        for r in runs:
                            if r["id"] == run_id:
                                dk = set(r.get("done_keys", []))
                                dk.add(stop_key)
                                r["done_keys"] = list(dk)
                                if len(dk) >= r.get("total_stops", 1):
                                    r["status"] = "complete"
                                # Mark constituent delivered — use rsplit to handle spaces in vol name
                                addr_rows = db().table("campaign_data").select("data")                                                .eq("id", f"{cid}_addrs").execute().data
                                addrs = addr_rows[0]["data"] if addr_rows else []
                                parts = stop_key.rsplit("_", 1)
                                stop_idx = int(parts[-1]) if len(parts) == 2 and parts[-1].isdigit() else -1
                                if stop_idx >= 0 and stop_idx < len(vol_route["stops"]):
                                    stop_addr = vol_route["stops"][stop_idx]["address"]
                                    for a in addrs:
                                        if a.get("address") == stop_addr:
                                            a["status"] = "delivered"
                                            a["delivered_date"] = datetime.now().strftime("%b %d, %Y")
                                            a["delivered_by"] = vol_name
                                db().table("campaign_data").upsert({"id": f"{cid}_runs",  "data": runs}).execute()
                                db().table("campaign_data").upsert({"id": f"{cid}_addrs", "data": addrs}).execute()
                                break
                    except Exception as e:
                        print(f"photo mark_done error: {e}", flush=True)

        return redirect(url_for("vol_deliver", run_id=run_id, vol_token=vol_token))

    # Reload fresh run state from Supabase (always — never use stale cache)
    try:
        rows = db().table("campaign_data").select("data").eq("id", f"{cid}_runs").execute().data
        runs = rows[0]["data"] if rows else []
        run  = next((r for r in runs if r["id"] == run_id), run)
        # Also reload vol_route from fresh run in case stops changed
        fresh_route = next((r for r in run.get("routes", []) if r["volunteer"]["name"] == vol_name), None)
        if fresh_route:
            vol_route = fresh_route
    except Exception as e:
        print(f"vol_deliver reload error: {e}", flush=True)

    done_set = set(run.get("done_keys", []))
    total    = len(vol_route["stops"])
    done_ct  = sum(1 for i in range(total) if f"{vol_name}_{i}" in done_set)

    return render_template("deliver.html",
                           run=run, vol_route=vol_route, vol_name=vol_name,
                           done_set=done_set,
                           total=total, done_ct=done_ct,
                           run_id=run_id, vol_token=vol_token)


@app.route("/deliver/<run_id>/<vol_token>/progress")
def vol_deliver_progress(run_id, vol_token):
    """JSON endpoint for live progress polling."""
    cid, run, vol_name = get_run_by_token(run_id, vol_token)
    if not run:
        return jsonify({"error": "not found"}), 404
    try:
        rows = db().table("campaign_data").select("data")                    .eq("id", f"{cid}_runs").execute().data
        runs = rows[0]["data"] if rows else []
        run  = next((r for r in runs if r["id"] == run_id), run)
    except:
        pass
    done_set = set(run.get("done_keys", []))
    vol_route = next((r for r in run.get("routes",[])
                      if r["volunteer"]["name"] == vol_name), None)
    total   = len(vol_route["stops"]) if vol_route else 0
    done_ct = sum(1 for i in range(total) if f"{vol_name}_{i}" in done_set)
    return jsonify({"done": done_ct, "total": total, "pct": round(done_ct/total*100) if total else 0})


# ── Token index + vol token helpers ───────────────────────────────────────────
def save_token_index(run: dict):
    """Write a fast-lookup index mapping each vol token → {cid, run_id, vol_name}."""
    try:
        idx = {}
        for vt in run.get("vol_tokens", []):
            idx[vt["token"]] = {
                "cid":      run["cid"],
                "run_id":   run["id"],
                "vol_name": vt["vol_name"],
            }
        db().table("campaign_data").upsert({
            "id":   f"token_index_{run['id']}",
            "data": idx,
        }).execute()
    except Exception as e:
        print(f"save_token_index error: {e}", flush=True)


def attach_vol_tokens(run: dict) -> dict:
    """Add a unique share token for each volunteer in a run."""
    tokens = []
    for r in run.get("routes", []):
        tokens.append({
            "vol_name": r["volunteer"]["name"],
            "token":    str(uuid.uuid4()),
        })
    run["vol_tokens"]     = tokens
    run["timestamp_iso"]  = datetime.now().isoformat()
    return run


# ══════════════════════════════════════════════════════════════════════════════
# MISSING / STOLEN SIGNS
# ══════════════════════════════════════════════════════════════════════════════

@app.route("/deliver/<run_id>/<vol_token>/delete_photo", methods=["POST"])
def vol_delete_photo(run_id, vol_token):
    """Allow volunteer to delete their photo for a stop."""
    cid, run, vol_name = get_run_by_token(run_id, vol_token)
    if not run:
        return redirect(url_for("vol_deliver", run_id=run_id, vol_token=vol_token))
    stop_key = request.form.get("stop_key","")
    try:
        rows = db().table("campaign_data").select("data")                    .eq("id", f"{cid}_runs").execute().data
        runs = rows[0]["data"] if rows else []
        for r in runs:
            if r["id"] == run_id:
                if r.get("stop_photos") and stop_key in r["stop_photos"]:
                    del r["stop_photos"][stop_key]
                db().table("campaign_data").upsert({"id": f"{cid}_runs", "data": runs}).execute()
                break
        # Also remove from addrs
        addr_rows = db().table("campaign_data").select("data")                        .eq("id", f"{cid}_addrs").execute().data
        addrs = addr_rows[0]["data"] if addr_rows else []
        vol_route = next((r for r in run.get("routes",[]) if r["volunteer"]["name"]==vol_name), None)
        if vol_route:
            parts = stop_key.rsplit("_", 1)
            stop_idx = int(parts[-1]) if len(parts)==2 and parts[-1].isdigit() else -1
            if stop_idx >= 0 and stop_idx < len(vol_route["stops"]):
                stop_addr = vol_route["stops"][stop_idx]["address"]
                for a in addrs:
                    if a.get("address") == stop_addr:
                        a.pop("photo_url", None)
                        a.pop("photo_taken_at", None)
                db().table("campaign_data").upsert({"id": f"{cid}_addrs", "data": addrs}).execute()
    except Exception as e:
        print(f"delete_photo error: {e}", flush=True)
    return redirect(url_for("vol_deliver", run_id=run_id, vol_token=vol_token))


@app.route("/constituents/flag_missing", methods=["POST"])
@login_required
def flag_missing():
    d    = get_data()
    addr = request.form.get("address","")
    note = request.form.get("missing_note","").strip()
    for a in d["addrs"]:
        if a["address"] == addr:
            a["missing"] = True
            a["missing_date"] = datetime.now().strftime("%b %d, %Y")
            a["missing_note"] = note
            break
    save_session("addrs", d["addrs"])
    return redirect(request.referrer or url_for("constituents"))

@app.route("/constituents/unflag_missing", methods=["POST"])
@login_required
def unflag_missing():
    d    = get_data()
    addr = request.form.get("address","")
    for a in d["addrs"]:
        if a["address"] == addr:
            a.pop("missing", None)
            a.pop("missing_date", None)
            a.pop("missing_note", None)
            break
    save_session("addrs", d["addrs"])
    return redirect(request.referrer or url_for("constituents"))


if __name__ == "__main__":
    app.run(debug=True, port=5000)
