import os, math, uuid, hashlib, requests, urllib.parse, base64, json, csv, io
from datetime import datetime, timedelta
from functools import wraps
from flask import (Flask, render_template, request, session,
                   redirect, url_for, jsonify, Response)
from flask_session import Session
from supabase import create_client
from geopy.geocoders import Nominatim

# ── bcrypt ─────────────────────────────────────────────────────────────────────
try:
    import bcrypt
    def hash_password(pw):
        return bcrypt.hashpw(pw.encode(), bcrypt.gensalt()).decode()
    def check_password(pw, hashed):
        try:
            if hashed.startswith("$2"):
                return bcrypt.checkpw(pw.encode(), hashed.encode())
            return hashlib.sha256(pw.encode()).hexdigest() == hashed
        except: return False
except ImportError:
    def hash_password(pw): return hashlib.sha256(pw.encode()).hexdigest()
    def check_password(pw, hashed): return hashlib.sha256(pw.encode()).hexdigest() == hashed

# ── Token encryption ───────────────────────────────────────────────────────────
try:
    from cryptography.fernet import Fernet
    _raw_key = os.environ.get("INTEGRATION_KEY","")
    _fernet  = Fernet(_raw_key.encode()) if _raw_key else None
except: _fernet = None

def encrypt_token(t):
    if not t: return ""
    if _fernet: return _fernet.encrypt(t.encode()).decode()
    return base64.b64encode(t.encode()).decode()

def decrypt_token(s):
    if not s: return ""
    if _fernet:
        try: return _fernet.decrypt(s.encode()).decode()
        except: return ""
    try: return base64.b64decode(s.encode()).decode()
    except: return ""

# ── Integration registry ───────────────────────────────────────────────────────
INTEGRATIONS = {
    "ngpvan":        {"name":"NGP VAN","logo":"🗳️","color":"#1a5fa8","status":"coming_soon",
                      "description":"Voter file, contact history, survey responses",
                      "auth_url":os.environ.get("VAN_AUTH_URL",""),"token_url":os.environ.get("VAN_TOKEN_URL",""),
                      "client_id":os.environ.get("VAN_CLIENT_ID",""),"client_secret":os.environ.get("VAN_CLIENT_SECRET",""),
                      "scope":"contacts voterFile","docs":"https://developers.ngpvan.com/van-api"},
    "nationbuilder": {"name":"NationBuilder","logo":"🏛️","color":"#e8562a","status":"coming_soon",
                      "description":"People database, donations, events, tags",
                      "auth_url":"https://{slug}.nationbuilder.com/oauth/authorize",
                      "token_url":"https://{slug}.nationbuilder.com/oauth/token",
                      "client_id":os.environ.get("NB_CLIENT_ID",""),"client_secret":os.environ.get("NB_CLIENT_SECRET",""),
                      "scope":"people donations","docs":"https://nationbuilder.com/api_documentation"},
    "actblue":       {"name":"ActBlue","logo":"💙","color":"#2655a0","status":"coming_soon",
                      "description":"Donation records, donor contact info",
                      "auth_url":"","token_url":"","client_id":os.environ.get("ACTBLUE_CLIENT_ID",""),
                      "client_secret":os.environ.get("ACTBLUE_CLIENT_SECRET",""),"scope":"",
                      "docs":"https://secure.actblue.com/docs/api"},
    "catalist":      {"name":"Catalist","logo":"📊","color":"#2d6a4f","status":"coming_soon",
                      "description":"National voter file, modeling scores",
                      "auth_url":"","token_url":"","client_id":os.environ.get("CATALIST_CLIENT_ID",""),
                      "client_secret":os.environ.get("CATALIST_CLIENT_SECRET",""),"scope":"",
                      "docs":"https://catalist.us"},
}

# ── App setup ──────────────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY","dev-secret-change-me")
app.config["SESSION_TYPE"]       = "filesystem"
app.config["SESSION_FILE_DIR"]   = "/tmp/flask_sessions"
app.config["SESSION_PERMANENT"]  = False
app.config["SESSION_USE_SIGNER"] = True
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024
Session(app)

SUPABASE_URL    = os.environ.get("SUPABASE_URL")
SUPABASE_KEY    = os.environ.get("SUPABASE_KEY")
SUPABASE_BUCKET = "sign-photos"

if SUPABASE_URL: print(f"Supabase OK: {SUPABASE_URL[:40]}", flush=True)
else: print("WARNING: SUPABASE_URL not set!", flush=True)

COLORS     = ["red","blue","green","orange","purple","darkred","cadetblue","darkgreen"]
HEX_COLORS = ["#e74c3c","#3498db","#2ecc71","#f39c12","#9b59b6","#c0392b","#5f9ea0","#27ae60"]

def db(): return create_client(SUPABASE_URL, SUPABASE_KEY)
def cid(): return session.get("cid")

def rows(result):
    """Extract plain-dict rows from a Supabase execute() result, safe for tojson."""
    try:
        data = result.data or []
        return [dict(r) for r in data]
    except:
        return []

def sanitize(obj):
    """Recursively convert Supabase objects to plain dicts/lists for JSON serialization."""
    if obj is None: return None
    if isinstance(obj, dict): return {k: sanitize(v) for k,v in obj.items()}
    if isinstance(obj, list): return [sanitize(i) for i in obj]
    if isinstance(obj, (str, int, float, bool)): return obj
    # Convert any unknown type (like Supabase model objects) to string or None
    try: return str(obj)
    except: return None

# ── Auth decorator ─────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "cid" not in session: return redirect(url_for("login_page"))
        return f(*args, **kwargs)
    return decorated

# ── Geocoding ──────────────────────────────────────────────────────────────────
_geocache = {}
def geocode(addr):
    if addr in _geocache: return _geocache[addr]
    try:
        r = requests.get("https://geocoding.geo.census.gov/geocoder/locations/onelineaddress",
            params={"address":addr,"benchmark":"2020","format":"json"},timeout=5)
        m = r.json().get("result",{}).get("addressMatches",[])
        if m:
            c = m[0]["coordinates"]
            res = (c["y"],c["x"]); _geocache[addr]=res; return res
    except: pass
    try:
        loc = Nominatim(user_agent="routeops").geocode(addr,timeout=5)
        if loc:
            res = (loc.latitude,loc.longitude); _geocache[addr]=res; return res
    except: pass
    return None, None

# ── Routing helpers ────────────────────────────────────────────────────────────
def hav(a,b):
    R=6371; la1,lo1,la2,lo2=map(math.radians,[a[0],a[1],b[0],b[1]])
    return R*2*math.asin(math.sqrt(math.sin((la2-la1)/2)**2+math.cos(la1)*math.cos(la2)*math.sin((lo2-lo1)/2)**2))

def osrm_matrix(pts):
    try:
        coords=";".join(f"{b},{a}" for a,b in pts)
        r=requests.get(f"https://router.project-osrm.org/table/v1/driving/{coords}?annotations=distance",timeout=20)
        d=r.json()
        if d.get("code")=="Ok": return [[x/1000 for x in row] for row in d["distances"]]
    except: pass
    return [[hav(pts[i],pts[j]) for j in range(len(pts))] for i in range(len(pts))]

def osrm_route(wps):
    try:
        coords=";".join(f"{b},{a}" for a,b in wps)
        r=requests.get(f"https://router.project-osrm.org/route/v1/driving/{coords}?overview=full&geometries=geojson",timeout=20)
        d=r.json()
        if d.get("code")=="Ok": return [[p[1],p[0]] for p in d["routes"][0]["geometry"]["coordinates"]]
    except: pass
    return [[a,b] for a,b in wps]

def solve_tsp(fm,hi,stops):
    if not stops: return [],0.0
    n=len(stops); sub=[[fm[stops[i]][stops[j]] for j in range(n)] for i in range(n)]
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
    br,bc=None,1e18
    for s in range(n):
        ro=two_opt(nn(s)); fr=[stops[x] for x in ro]
        cost=fm[hi][fr[0]]+sum(fm[fr[k]][fr[k+1]] for k in range(len(fr)-1))+fm[fr[-1]][hi]
        if cost<bc: bc=cost; br=fr
    return br,round(bc*0.621371,2)

def gmaps_url(o,d): return f"https://www.google.com/maps/dir/{urllib.parse.quote(o)}/{urllib.parse.quote(d)}"

# CSV detection
FMAP={"addr":["address","street_address","addr","street","address1"],
      "first":["first_name","firstname","fname","first"],"last":["last_name","lastname","lname","last"],
      "email":["email","email_address"],"phone":["phone","phone_number","mobile","cell"],
      "city":["city","town"],"state":["state","state_code"],"zip":["zip","zipcode","zip_code","postal_code"]}
def detect_col(cols,key):
    cl={c.lower().strip().replace(" ","_"):c for c in cols}
    for k in FMAP.get(key,[]): 
        if k in cl: return cl[k]
    return None

# ── Photo upload ───────────────────────────────────────────────────────────────
def upload_photo(campaign_id, run_stop_id, file_bytes, mime):
    try:
        safe = str(run_stop_id).replace("-","")
        path = f"{campaign_id}/{safe}_{uuid.uuid4().hex[:6]}.jpg"
        print(f"upload_photo path={path} size={len(file_bytes)}", flush=True)
        db().storage.from_(SUPABASE_BUCKET).upload(path, file_bytes,
            {"content-type": mime, "cache-control": "3600", "upsert": "true"})
        url_obj = db().storage.from_(SUPABASE_BUCKET).get_public_url(path)
        # supabase-py v2 returns a string directly; v1 returns an object
        if isinstance(url_obj, str):
            url = url_obj
        elif hasattr(url_obj, "public_url"):
            url = url_obj.public_url
        elif hasattr(url_obj, "url"):
            url = url_obj.url
        elif isinstance(url_obj, dict):
            url = url_obj.get("publicUrl") or url_obj.get("public_url") or url_obj.get("url","")
        else:
            url = str(url_obj)
        # Strip any Supabase object wrapper if it somehow ended up as repr
        if url.startswith("<") or "object at 0x" in url:
            print(f"upload_photo: bad url repr={url}", flush=True)
            return ""
        print(f"upload_photo success url={url}", flush=True)
        return url
    except Exception as e:
        print(f"upload_photo error: {e}", flush=True)
        return ""

# ── Integration helpers ────────────────────────────────────────────────────────
def get_integrations(campaign_id):
    try:
        rows = db().table("campaign_integrations").select("*").eq("campaign_id",campaign_id).execute().data
        return {r["provider"]:r for r in rows}
    except: return {}

def save_integration(campaign_id, provider, data):
    try:
        db().table("campaign_integrations").upsert(
            {"campaign_id":campaign_id,"provider":provider,**data},
            on_conflict="campaign_id,provider").execute()
    except Exception as e: print(f"save_integration error: {e}", flush=True)

def delete_integration(campaign_id, provider):
    try:
        db().table("campaign_integrations").delete().eq("campaign_id",campaign_id).eq("provider",provider).execute()
    except Exception as e: print(f"delete_integration error: {e}", flush=True)

# ── _deliver_stop — single source of truth for marking a stop done ─────────────
def _deliver_stop(stop_id, campaign_id, delivered_by):
    try:
        now = datetime.now()
        stops = db().table("run_stops").select("*").eq("id",stop_id).execute().data
        if not stops: return
        stop = stops[0]
        db().table("run_stops").update({
            "status":"delivered",
            "delivered_at": now.isoformat(),
            "delivered_by": delivered_by,
        }).eq("id",stop_id).execute()
        if stop.get("constituent_id"):
            db().table("constituents").update({
                "status":"delivered",
                "delivered_date": now.strftime("%b %d, %Y"),
                "delivered_by": delivered_by,
            }).eq("id",stop["constituent_id"]).execute()
        # update run done_count
        all_stops = db().table("run_stops").select("id,status").eq("run_id",stop["run_id"]).execute().data or []
        done  = sum(1 for s in all_stops if s["status"]=="delivered")
        total = len(all_stops)
        db().table("runs").update({
            "done_count": done,
            "status": "complete" if done>=total else "active",
        }).eq("id",stop["run_id"]).execute()
    except Exception as e:
        print(f"_deliver_stop error: {e}", flush=True)

# ══════════════════════════════════════════════════════════════════════════════
# AUTH
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/", methods=["GET","POST"])
def login_page():
    if "cid" in session: return redirect(url_for("volunteers"))
    error = None
    if request.method == "POST":
        action = request.form.get("action")
        email  = request.form.get("email","").lower().strip()
        pw     = request.form.get("password","")
        if action == "login":
            try:
                res = db().table("campaign_accounts").select("*").eq("email",email).execute()
                if not res.data: error="No account found with that email."
                elif not check_password(pw, res.data[0]["password_hash"]): error="Wrong password."
                else:
                    a=res.data[0]; session.clear()
                    session["cid"]=a["id"]; session["cname"]=a["campaign_name"]
                    return redirect(url_for("volunteers"))
            except Exception as e: error=str(e)
        elif action == "signup":
            cname=request.form.get("cname","").strip(); pw2=request.form.get("password2","")
            if not cname or not email or not pw: error="All fields required."
            elif pw!=pw2: error="Passwords don't match."
            elif len(pw)<6: error="Password must be 6+ characters."
            else:
                try:
                    ex=db().table("campaign_accounts").select("id").eq("email",email).execute()
                    if ex.data: error="Email already registered."
                    else:
                        nid=str(uuid.uuid4())
                        db().table("campaign_accounts").insert({
                            "id":nid,"campaign_name":cname,
                            "email":email,"password_hash":hash_password(pw)
                        }).execute()
                        session.clear(); session["cid"]=nid; session["cname"]=cname
                        return redirect(url_for("volunteers"))
                except Exception as e: error=str(e)
    return render_template("login.html", error=error)

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login_page"))

# ══════════════════════════════════════════════════════════════════════════════
# VOLUNTEERS
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/volunteers", methods=["GET","POST"])
@login_required
def volunteers():
    campaign_id = cid(); cname = session.get("cname","Campaign"); msg = None
    if request.method == "POST":
        action = request.form.get("action")
        if action == "add":
            street=request.form.get("street","").strip(); city=request.form.get("city","").strip()
            state=request.form.get("state","").strip(); zipcode=request.form.get("zip","").strip()
            name=request.form.get("name","").strip()
            if name and street and city and state and zipcode:
                addr=f"{street}, {city}, {state} {zipcode}"
                lat,lng=geocode(addr)
                skills_raw=request.form.get("skills","").strip()
                try:
                    db().table("volunteers").insert({
                        "id":str(uuid.uuid4()),"campaign_id":campaign_id,
                        "name":name,"first_name":request.form.get("vfirst","").strip(),
                        "last_name":request.form.get("vlast","").strip(),
                        "email":request.form.get("email","").strip(),
                        "phone":request.form.get("phone","").strip(),
                        "address":addr,"lat":lat,"lng":lng,
                        "has_vehicle":request.form.get("has_vehicle")=="1",
                        "skills":[s.strip() for s in skills_raw.split(",") if s.strip()],
                        "availability":request.form.get("availability","").strip(),
                        "shirt_size":request.form.get("shirt_size","").strip(),
                        "note":request.form.get("vnote","").strip(),
                        "joined_date":datetime.now().date().isoformat(),
                    }).execute()
                    msg=f"✅ {name} added!"
                except Exception as e: msg=f"❌ {e}"
            else: msg="❌ Name, street, city, state, ZIP required."

        elif action == "update_vol":
            vid=request.form.get("vol_id_key")
            if vid:
                skills_raw=request.form.get("skills","").strip()
                try:
                    db().table("volunteers").update({
                        "name":request.form.get("name","").strip(),
                        "first_name":request.form.get("first_name","").strip(),
                        "last_name":request.form.get("last_name","").strip(),
                        "email":request.form.get("email","").strip(),
                        "phone":request.form.get("phone","").strip(),
                        "availability":request.form.get("availability","").strip(),
                        "shirt_size":request.form.get("shirt_size","").strip(),
                        "skills":[s.strip() for s in skills_raw.split(",") if s.strip()],
                        "has_vehicle":request.form.get("has_vehicle")=="1",
                        "emergency_contact":request.form.get("emergency_contact","").strip(),
                        "emergency_phone":request.form.get("emergency_phone","").strip(),
                        "note":request.form.get("note","").strip(),
                    }).eq("id",vid).eq("campaign_id",campaign_id).execute()
                    msg="✅ Volunteer updated."
                except Exception as e: msg=f"❌ {e}"

        elif action == "delete":
            vid=request.form.get("vol_id")
            try: db().table("volunteers").delete().eq("id",vid).eq("campaign_id",campaign_id).execute()
            except Exception as e: msg=f"❌ {e}"

        elif action == "import_csv":
            f=request.files.get("csv_file")
            if f:
                content=f.read().decode("utf-8-sig"); reader=csv.DictReader(io.StringIO(content))
                cols=reader.fieldnames or []; added=0
                for row in reader:
                    fn=row.get(detect_col(cols,"first"),"").strip() if detect_col(cols,"first") else ""
                    ln=row.get(detect_col(cols,"last"),"").strip() if detect_col(cols,"last") else ""
                    name=(fn+" "+ln).strip()
                    if not name: continue
                    ac=detect_col(cols,"addr"); cc=detect_col(cols,"city")
                    sc=detect_col(cols,"state"); zc=detect_col(cols,"zip")
                    addr=row.get(ac,"").strip() if ac else ""
                    parts=[p for p in [row.get(cc,"").strip() if cc else "",
                                       row.get(sc,"").strip() if sc else "",
                                       row.get(zc,"").strip() if zc else ""] if p]
                    if parts: addr+=", "+", ".join(parts)
                    lat,lng=geocode(addr) if addr else (None,None)
                    ec=detect_col(cols,"email"); pc=detect_col(cols,"phone")
                    try:
                        db().table("volunteers").insert({
                            "id":str(uuid.uuid4()),"campaign_id":campaign_id,
                            "name":name,"first_name":fn,"last_name":ln,
                            "email":row.get(ec,"").strip() if ec else "",
                            "phone":row.get(pc,"").strip() if pc else "",
                            "address":addr,"lat":lat,"lng":lng,
                        }).execute(); added+=1
                    except: pass
                msg=f"Imported {added} volunteers."

        elif action == "clear":
            try: db().table("volunteers").delete().eq("campaign_id",campaign_id).execute(); msg="All volunteers cleared."
            except Exception as e: msg=f"❌ {e}"

        return redirect(url_for("volunteers"))

    vols=sanitize(db().table("volunteers").select("*").eq("campaign_id",campaign_id).order("name").execute().data or [])
    return render_template("volunteers.html", d={"vols":vols,"cname":cname,"cid":campaign_id}, msg=msg)

# ══════════════════════════════════════════════════════════════════════════════
# CONSTITUENTS
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/constituents", methods=["GET","POST"])
@login_required
def constituents():
    campaign_id=cid(); cname=session.get("cname","Campaign"); msg=None
    if request.method == "POST":
        action=request.form.get("action")

        if action == "add":
            street=request.form.get("street","").strip(); city=request.form.get("city","").strip()
            state=request.form.get("state","").strip(); zipcode=request.form.get("zip","").strip()
            if street and city and state and zipcode:
                addr=f"{street}, {city}, {state} {zipcode}"
                lat,lng=geocode(addr)
                fn=request.form.get("first_name","").strip(); ln=request.form.get("last_name","").strip()
                tags_raw=request.form.get("tags","").strip()
                score=request.form.get("support_score","")
                try:
                    db().table("constituents").insert({
                        "id":str(uuid.uuid4()),"campaign_id":campaign_id,
                        "address":addr,"lat":lat,"lng":lng,
                        "first_name":fn,"last_name":ln,"contact":(fn+" "+ln).strip(),
                        "phone":request.form.get("phone","").strip(),
                        "email":request.form.get("email","").strip(),
                        "note":request.form.get("note","").strip(),
                        "voter_id":request.form.get("voter_id","").strip(),
                        "party":request.form.get("party","").strip(),
                        "precinct":request.form.get("precinct","").strip(),
                        "support_score":int(score) if score.isdigit() else None,
                        "relationship":request.form.get("relationship","unknown"),
                        "sign_requested":request.form.get("sign_requested")=="1",
                        "volunteer_interest":request.form.get("volunteer_interest")=="1",
                        "donor":request.form.get("donor")=="1",
                        "tags":[t.strip() for t in tags_raw.split(",") if t.strip()],
                        "status":"pending",
                    }).execute()
                    msg="✅ Address added!"
                except Exception as e: msg=f"❌ {e}"
            else: msg="❌ Street, city, state, ZIP required."

        elif action == "update_voter":
            cst_id=request.form.get("voter_id_key")
            if cst_id:
                tags_raw=request.form.get("tags","").strip()
                score=request.form.get("support_score","")
                try:
                    db().table("constituents").update({
                        "first_name":request.form.get("first_name","").strip(),
                        "last_name":request.form.get("last_name","").strip(),
                        "phone":request.form.get("phone","").strip(),
                        "email":request.form.get("email","").strip(),
                        "note":request.form.get("note","").strip(),
                        "voter_id":request.form.get("voter_id","").strip(),
                        "party":request.form.get("party","").strip(),
                        "precinct":request.form.get("precinct","").strip(),
                        "ward":request.form.get("ward","").strip(),
                        "relationship":request.form.get("relationship","unknown"),
                        "language":request.form.get("language","").strip(),
                        "best_contact_time":request.form.get("best_contact_time","").strip(),
                        "support_score":int(score) if score.isdigit() else None,
                        "canvass_result":request.form.get("canvass_result","").strip(),
                        "canvass_date":request.form.get("canvass_date","").strip(),
                        "canvassed_by":request.form.get("canvassed_by","").strip(),
                        "donation_amount":request.form.get("donation_amount","").strip(),
                        "tags":[t.strip() for t in tags_raw.split(",") if t.strip()],
                        "sign_requested":request.form.get("sign_requested")=="1",
                        "volunteer_interest":request.form.get("volunteer_interest")=="1",
                        "donor":request.form.get("donor")=="1",
                        "voted_2024g":request.form.get("voted_2024g")=="1",
                        "voted_2024p":request.form.get("voted_2024p")=="1",
                        "voted_2022g":request.form.get("voted_2022g")=="1",
                        "voted_2022p":request.form.get("voted_2022p")=="1",
                        "voted_2020g":request.form.get("voted_2020g")=="1",
                    }).eq("id",cst_id).eq("campaign_id",campaign_id).execute()
                    msg="✅ Updated."
                except Exception as e: msg=f"❌ {e}"

        elif action == "delete":
            cst_id=request.form.get("cst_id")
            try: db().table("constituents").delete().eq("id",cst_id).eq("campaign_id",campaign_id).execute()
            except Exception as e: msg=f"❌ {e}"

        elif action in ("clear_all","clear_pending","clear_delivered"):
            try:
                q=db().table("constituents").delete().eq("campaign_id",campaign_id)
                if action=="clear_pending": q=q.eq("status","pending")
                elif action=="clear_delivered": q=q.eq("status","delivered")
                q.execute(); msg="Cleared."
            except Exception as e: msg=f"❌ {e}"

        elif action == "import_csv":
            f=request.files.get("csv_file")
            if f:
                content=f.read().decode("utf-8-sig"); reader=csv.DictReader(io.StringIO(content))
                cols=reader.fieldnames or []; added=0
                for row in reader:
                    ac=detect_col(cols,"addr"); cc=detect_col(cols,"city")
                    sc=detect_col(cols,"state"); zc=detect_col(cols,"zip")
                    addr=row.get(ac,"").strip() if ac else ""
                    if not addr: continue
                    parts=[p for p in [row.get(cc,"").strip() if cc else "",
                                       row.get(sc,"").strip() if sc else "",
                                       row.get(zc,"").strip() if zc else ""] if p]
                    if parts: addr+=", "+", ".join(parts)
                    fn_col=detect_col(cols,"first"); ln_col=detect_col(cols,"last")
                    fn=row.get(fn_col,"").strip() if fn_col else ""
                    ln=row.get(ln_col,"").strip() if ln_col else ""
                    ec=detect_col(cols,"email"); pc=detect_col(cols,"phone")
                    lat,lng=geocode(addr)
                    try:
                        db().table("constituents").insert({
                            "id":str(uuid.uuid4()),"campaign_id":campaign_id,
                            "address":addr,"lat":lat,"lng":lng,
                            "first_name":fn,"last_name":ln,"contact":(fn+" "+ln).strip(),
                            "email":row.get(ec,"").strip() if ec else "",
                            "phone":row.get(pc,"").strip() if pc else "",
                            "status":"pending",
                        }).execute(); added+=1
                    except: pass
                msg=f"Imported {added} addresses."

        return redirect(url_for("constituents"))

    addrs=sanitize(db().table("constituents").select("*").eq("campaign_id",campaign_id).order("created_at").execute().data or [])
    return render_template("constituents.html", d={"addrs":addrs,"cname":cname,"cid":campaign_id}, msg=msg)

@app.route("/constituents/flag_missing", methods=["POST"])
@login_required
def flag_missing():
    campaign_id=cid(); cst_id=request.form.get("cst_id",""); note=request.form.get("missing_note","").strip()
    db().table("constituents").update({
        "missing":True,"missing_date":datetime.now().strftime("%b %d, %Y"),"missing_note":note,
    }).eq("id",cst_id).eq("campaign_id",campaign_id).execute()
    return redirect(request.referrer or url_for("constituents"))

@app.route("/constituents/unflag_missing", methods=["POST"])
@login_required
def unflag_missing():
    campaign_id=cid(); cst_id=request.form.get("cst_id","")
    db().table("constituents").update({
        "missing":False,"missing_date":None,"missing_note":None,
    }).eq("id",cst_id).eq("campaign_id",campaign_id).execute()
    return redirect(request.referrer or url_for("constituents"))

@app.route("/constituents/export")
@login_required
def export_csv():
    campaign_id=cid()
    # Only load minimal constituent data for stats — full data loaded via viewport API
    addrs_raw = db().table("constituents")        .select("id,address,lat,lng,status,missing,first_name,last_name,photo_url")        .eq("campaign_id",campaign_id).execute().data or []
    addrs = sanitize(addrs_raw)
    output=io.StringIO()
    fields=["status","address","contact","first_name","last_name","phone","email",
            "party","support_score","precinct","voter_id","note","delivered_date","delivered_by","tags"]
    writer=csv.DictWriter(output,fieldnames=fields,extrasaction="ignore")
    writer.writeheader()
    for a in addrs:
        if isinstance(a.get("tags"),list): a["tags"]=", ".join(a["tags"])
        writer.writerow({f:a.get(f,"") for f in fields})
    return Response(output.getvalue(),mimetype="text/csv",
                    headers={"Content-Disposition":"attachment;filename=constituents.csv"})

# ══════════════════════════════════════════════════════════════════════════════
# DELIVERY RUN
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/delivery-run", methods=["GET","POST"])
@app.route("/dispatch", methods=["GET","POST"])
@login_required
def delivery_run():
    campaign_id=cid(); cname=session.get("cname","Campaign"); msg=None

    if request.method == "POST":
        action=request.form.get("action")
        if action in ("optimize","proximity"):
            sel_vol_ids=request.form.getlist("selected_vols")
            sel_cst_ids=request.form.getlist("selected_addrs")
            print(f"optimize: {len(sel_vol_ids)} vols, {len(sel_cst_ids)} stops, action={action}", flush=True)
            if not sel_vol_ids or not sel_cst_ids:
                msg="❌ Select at least one volunteer and one address."
            else:
                # Re-fetch from DB fresh for POST to avoid stale sanitized data
                all_vols=db().table("volunteers").select("*").eq("campaign_id",campaign_id).execute().data or []
                all_addrs=db().table("constituents").select("*").eq("campaign_id",campaign_id).eq("status","pending").execute().data or []
                sel_vols=[dict(v) for v in all_vols if str(v["id"]) in sel_vol_ids]
                sel_addrs=[dict(a) for a in all_addrs if str(a["id"]) in sel_cst_ids]
                print(f"matched: {len(sel_vols)} vols, {len(sel_addrs)} addrs", flush=True)
                if not sel_vols or not sel_addrs:
                    msg="❌ Could not match selected volunteers or addresses. Please try again."
                    vols=sanitize(all_vols); addrs=sanitize([a for a in all_addrs])
                    addr_coords=[{"id":a["id"],"lat":a.get("lat"),"lng":a.get("lng")} for a in addrs if a.get("lat")]
                    return render_template("delivery_run.html",d={"vols":vols,"addrs":addrs,"cname":cname,"cid":campaign_id},msg=msg,addr_coords=addr_coords)
                # Geocode missing
                for v in sel_vols:
                    if not v.get("lat") and v.get("address"):
                        lat,lng=geocode(v["address"])
                        if lat:
                            v["lat"]=lat; v["lng"]=lng
                            db().table("volunteers").update({"lat":lat,"lng":lng}).eq("id",v["id"]).execute()
                for a in sel_addrs:
                    if not a.get("lat") and a.get("address"):
                        lat,lng=geocode(a["address"])
                        if lat:
                            a["lat"]=lat; a["lng"]=lng
                            db().table("constituents").update({"lat":lat,"lng":lng}).eq("id",a["id"]).execute()

                routes=[]
                # Only work with geocoded points to avoid index misalignment
                geo_vols=[v for v in sel_vols if v.get("lat") and v.get("lng")]
                geo_addrs=[a for a in sel_addrs if a.get("lat") and a.get("lng")]
                print(f"geocoded: {len(geo_vols)} vols, {len(geo_addrs)} addrs", flush=True)
                if not geo_vols:
                    msg="❌ No volunteers have coordinates. Ensure volunteer addresses are complete."
                elif not geo_addrs:
                    msg="❌ No stop addresses could be geocoded."
                elif action=="optimize":
                    # Matrix indices: 0..nv-1 = vols, nv..nv+na-1 = addrs
                    all_geo = geo_vols + geo_addrs
                    fm = osrm_matrix([(x["lat"],x["lng"]) for x in all_geo])
                    nv = len(geo_vols)
                    na = len(geo_addrs)
                    stop_indices = list(range(nv, nv+na))
                    chunks = [[] for _ in geo_vols]
                    for i, si in enumerate(stop_indices):
                        chunks[i % nv].append(si)
                    for vi, v in enumerate(geo_vols):
                        order, dist = solve_tsp(fm, vi, chunks[vi])
                        stops = [geo_addrs[si-nv] for si in order]
                        wps = [(v["lat"],v["lng"])] + [(s["lat"],s["lng"]) for s in stops]
                        geom = osrm_route(wps) if len(wps) > 1 else []
                        routes.append({"volunteer":v,"stops":stops,"distance_miles":dist,"geometry":geom})
                else:
                    used=set(); per_vol=max(1,len(geo_addrs)//len(geo_vols))
                    for v in geo_vols:
                        remaining=[a for a in geo_addrs if a["id"] not in used]
                        remaining.sort(key=lambda a:hav((v["lat"],v["lng"]),(a["lat"],a["lng"])))
                        stops=remaining[:per_vol]
                        for s in stops: used.add(s["id"])
                        wps=[(v["lat"],v["lng"])]+[(s["lat"],s["lng"]) for s in stops]
                        geom=osrm_route(wps) if len(wps)>1 else []
                        dist=round(sum(hav((v["lat"],v["lng"]),(s["lat"],s["lng"])) for s in stops)*0.621371,2)
                        routes.append({"volunteer":v,"stops":stops,"distance_miles":dist,"geometry":geom})

                print(f"routes built: {len(routes)}, msg={msg}", flush=True)
                if routes and not msg:
                    try:
                        run_id=str(uuid.uuid4())
                        n_vols=len([r for r in routes if r["stops"]])
                        n_stops=sum(len(r["stops"]) for r in routes)
                        dispatch_type=request.form.get("dispatch_type","sign_delivery")
                        dispatch_notes=request.form.get("dispatch_notes","").strip()
                        routing_method=action  # optimize or proximity
                        auto_name=f"{datetime.now().strftime('%b %d')} · {n_vols} vol{'s' if n_vols!=1 else ''} · {n_stops} stop{'s' if n_stops!=1 else ''}"
                        print(f"inserting run: {run_id} name={auto_name} type={dispatch_type}", flush=True)
                        db().table("runs").insert({
                            "id":run_id,"campaign_id":campaign_id,
                            "name":auto_name,"status":"active",
                            "run_type":dispatch_type,"total_stops":n_stops,"done_count":0,
                            "notes":dispatch_notes or None,
                        }).execute()
                        for route in routes:
                            vol=route["volunteer"]
                            geom_json=json.dumps(route.get("geometry",[]))
                            for order,stop in enumerate(route["stops"]):
                                db().table("run_stops").insert({
                                    "id":str(uuid.uuid4()),"run_id":run_id,"campaign_id":campaign_id,
                                    "constituent_id":str(stop["id"]),"volunteer_id":str(vol["id"]),
                                    "volunteer_name":vol["name"],"stop_order":order,
                                    "address":stop["address"],
                                    "route_geometry":geom_json if order==0 else None,
                                    "distance_miles":route.get("distance_miles"),
                                    "status":"pending",
                                }).execute()
                            db().table("vol_tokens").insert({
                                "id":str(uuid.uuid4()),"run_id":run_id,"campaign_id":campaign_id,
                                "volunteer_id":str(vol["id"]),"volunteer_name":vol["name"],
                                "token":str(uuid.uuid4()),
                                "expires_at":(datetime.now()+timedelta(hours=72)).isoformat(),
                            }).execute()
                        print(f"run saved successfully, redirecting to map", flush=True)
                        session["active_run_id"]=run_id
                        return redirect(url_for("map_page"))
                    except Exception as e:
                        print(f"ERROR saving run: {e}", flush=True)
                        import traceback; traceback.print_exc()
                        msg=f"❌ Error saving run: {e}"
                elif not routes:
                    msg="❌ No routes built — check that volunteers and addresses have valid coordinates."
        return redirect(url_for("delivery_run"))

    # GET — load fresh data
    vols=sanitize(db().table("volunteers").select("*").eq("campaign_id",campaign_id).order("name").execute().data or [])
    addrs=sanitize(db().table("constituents").select("*").eq("campaign_id",campaign_id).eq("status","pending").order("address").execute().data or [])
    for v in vols:
        if not v.get("lat") and v.get("address"):
            lat,lng=geocode(v["address"])
            if lat: v["lat"]=lat; v["lng"]=lng
    addr_coords=[{"id":a["id"],"lat":a.get("lat"),"lng":a.get("lng")} for a in addrs if a.get("lat")]
    import json as _json
    dispatch_types=[
        {"id":"sign_delivery","label":"Sign Delivery","icon":"🪧","desc":"Drop off yard signs, photo proof required"},
        {"id":"lit_drop",     "label":"Lit Drop",     "icon":"📚","desc":"Leave literature at doors, no photo needed"},
        {"id":"door_knock",   "label":"Door Knock",   "icon":"🚪","desc":"Canvassing — track contacts at each door"},
        {"id":"sign_recovery","label":"Sign Recovery","icon":"🔄","desc":"Collect missing or damaged signs"},
        {"id":"gotv",         "label":"GOTV",         "icon":"🗳️","desc":"Get Out The Vote — staging and call lists"},
        {"id":"general",      "label":"General",      "icon":"📋","desc":"Custom volunteer dispatch"},
    ]
    return render_template("dispatch.html",
                           d={"vols":vols,"addrs":addrs,"cname":cname,"cid":campaign_id},
                           msg=msg,
                           dispatch_types=dispatch_types,
                           addr_coords_json=_json.dumps(addr_coords))

# ══════════════════════════════════════════════════════════════════════════════
# MAP
# ══════════════════════════════════════════════════════════════════════════════
def _build_map_routes(run_id):
    try:
        stops=db().table("run_stops").select("*").eq("run_id",run_id).order("volunteer_name,stop_order").execute().data or []
    except: return []
    by_vol={}
    for s in stops:
        vn=s.get("volunteer_name") or "Unknown"
        if vn not in by_vol: by_vol[vn]=[]
        by_vol[vn].append(s)
    routes=[]
    for vn,vol_stops in by_vol.items():
        vol={"name":vn,"address":"","lat":None,"lng":None}
        vid=vol_stops[0].get("volunteer_id","")
        if vid:
            try:
                vr=db().table("volunteers").select("*").eq("id",vid).execute().data
                if vr: vol=vr[0]
            except: pass
        geom=[]
        try: geom=json.loads(vol_stops[0].get("route_geometry") or "[]")
        except: pass
        routes.append({"volunteer":vol,"stops":vol_stops,"geometry":geom})
    return routes

@app.route("/map")
@login_required
def map_page():
    campaign_id=cid(); cname=session.get("cname","Campaign")
    active_run_id=session.get("active_run_id")
    # Only load minimal constituent data for stats — full data loaded via viewport API
    addrs_raw = db().table("constituents")        .select("id,address,lat,lng,status,missing,first_name,last_name,photo_url")        .eq("campaign_id",campaign_id).execute().data or []
    addrs = sanitize(addrs_raw)
    runs_raw=db().table("runs").select("*").eq("campaign_id",campaign_id).order("created_at",desc=True).execute().data or []
    runs=[]
    for run in runs_raw:
        stops=db().table("run_stops").select("id,status,volunteer_name").eq("run_id",run["id"]).execute().data or []
        run["total_stops"]=len(stops)
        run["done_count"]=sum(1 for s in stops if s["status"]=="delivered")
        run["vol_names"]=list({s["volunteer_name"] for s in stops if s.get("volunteer_name")})
        run["routes"]=_build_map_routes(run["id"])
        runs.append(run)
    active_run=next((r for r in runs if r["id"]==active_run_id), runs[0] if runs else None)
    # Safe JSON-serializable version of active_run for JS
    safe_active_run=None
    if active_run:
        safe_active_run={
            "id": active_run["id"],
            "name": active_run["name"],
            "status": active_run["status"],
            "total_stops": active_run["total_stops"],
            "done_count": active_run["done_count"],
            "vol_names": active_run["vol_names"],
            "routes": [
                {
                    "volunteer": {
                        "name": r["volunteer"].get("name",""),
                        "address": r["volunteer"].get("address",""),
                        "lat": r["volunteer"].get("lat"),
                        "lng": r["volunteer"].get("lng"),
                    },
                    "stops": [
                        {
                            "id": s.get("id",""),
                            "address": s.get("address",""),
                            "status": s.get("status","pending"),
                            "volunteer_name": s.get("volunteer_name",""),
                            "photo_url": s.get("photo_url"),
                            "photo_taken_at": s.get("photo_taken_at"),
                            "lat": None, "lng": None,
                        }
                        for s in r["stops"]
                    ],
                    "geometry": r.get("geometry",[]),
                }
                for r in active_run.get("routes",[])
            ],
        }
    # Enrich stop coordinates from constituents for map rendering
    if safe_active_run:
        addr_map={a["address"]:{"lat":a.get("lat"),"lng":a.get("lng")} for a in addrs}
        for route in safe_active_run["routes"]:
            for stop in route["stops"]:
                coords=addr_map.get(stop["address"],{})
                stop["lat"]=coords.get("lat"); stop["lng"]=coords.get("lng")
    # Build safe serializable runs list for JS (includes routes+stops for map rendering)
    addr_coord_map = {a["address"]:{"lat":a.get("lat"),"lng":a.get("lng")} for a in addrs}
    safe_runs = []
    for r in runs:
        safe_routes = []
        for route in r.get("routes", []):
            vol = route.get("volunteer") or {}
            safe_stops = []
            for s in route.get("stops", []):
                coords = addr_coord_map.get(s.get("address",""), {})
                safe_stops.append({
                    "id":           s.get("id",""),
                    "address":      s.get("address",""),
                    "status":       s.get("status","pending"),
                    "volunteer_name": s.get("volunteer_name",""),
                    "contact":      s.get("contact",""),
                    "phone":        s.get("phone",""),
                    "photo_url":    s.get("photo_url"),
                    "lat":          coords.get("lat"),
                    "lng":          coords.get("lng"),
                })
            safe_routes.append({
                "volunteer": {
                    "name":    vol.get("name",""),
                    "address": vol.get("address",""),
                    "lat":     vol.get("lat"),
                    "lng":     vol.get("lng"),
                },
                "stops":    safe_stops,
                "geometry": route.get("geometry",[]),
            })
        delivered_ids = {s["id"] for route in r.get("routes",[]) for s in route.get("stops",[]) if s.get("status")=="delivered"}
        safe_runs.append({
            "id":          r["id"],
            "name":        r["name"],
            "status":      r["status"],
            "total_stops": r["total_stops"],
            "done_count":  r["done_count"],
            "vol_names":   r["vol_names"],
            "done_keys":   list(delivered_ids),
            "routes":      safe_routes,
        })
    import json as _json

    def _safe_dumps(obj):
        """JSON serialize, replacing any non-serializable values with null."""
        def default(o):
            return None
        return _json.dumps(obj, default=default)

    return render_template("map.html",
                           d={"addrs":addrs,"runs":runs,"cname":cname,"cid":campaign_id},
                           active_run=safe_active_run,
                           runs=safe_runs,
                           HEX_COLORS=HEX_COLORS,
                           addrs_json=_safe_dumps(addrs),
                           active_run_json=_safe_dumps(safe_active_run) if safe_active_run else "null",
                           runs_json=_safe_dumps(safe_runs),
                           hex_colors_json=_safe_dumps(HEX_COLORS))

@app.route("/map/select/<run_id>")
@login_required
def select_run(run_id):
    session["active_run_id"]=run_id; return redirect(url_for("map_page"))

# ══════════════════════════════════════════════════════════════════════════════
# ROUTES PAGE
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/routes", methods=["GET","POST"])
@login_required
def routes_page():
    campaign_id=cid(); cname=session.get("cname","Campaign"); msg=None
    if request.method == "POST":
        action=request.form.get("action"); run_id=request.form.get("run_id","")
        if action=="delete_run":
            db().table("runs").delete().eq("id",run_id).eq("campaign_id",campaign_id).execute(); msg="Run deleted."
        elif action=="rename_run":
            name=request.form.get("new_name","").strip()
            if name: db().table("runs").update({"name":name}).eq("id",run_id).eq("campaign_id",campaign_id).execute()
        elif action=="close_run":
            db().table("runs").update({"status":"complete"}).eq("id",run_id).eq("campaign_id",campaign_id).execute()
        elif action=="reopen_run":
            db().table("runs").update({"status":"active"}).eq("id",run_id).eq("campaign_id",campaign_id).execute()
        elif action=="mark_stop_done":
            _deliver_stop(request.form.get("stop_id",""),campaign_id,"campaign")
        elif action=="unmark_stop":
            stop_id=request.form.get("stop_id","")
            db().table("run_stops").update({"status":"pending","delivered_at":None}).eq("id",stop_id).execute()
        return redirect(url_for("routes_page"))

    runs_raw=sanitize(db().table("runs").select("*").eq("campaign_id",campaign_id).order("created_at",desc=True).execute().data or [])
    print(f"[routes] campaign={campaign_id} runs_raw={len(runs_raw)}", flush=True)
    selected_run_id=request.args.get("run_id")
    runs=[]
    for run in runs_raw:
        stops=sanitize(db().table("run_stops").select("*").eq("run_id",run["id"]).order("volunteer_name,stop_order").execute().data or [])
        tokens=sanitize(db().table("vol_tokens").select("*").eq("run_id",run["id"]).execute().data or [])
        done_count=sum(1 for s in stops if s["status"]=="delivered")
        total=len(stops)
        pct=round(done_count/total*100) if total else 0
        # Build per-volunteer route groups
        by_vol={}
        for s in stops:
            vn=s.get("volunteer_name","Unknown")
            if vn not in by_vol: by_vol[vn]={"volunteer_name":vn,"stops":[],"distance_miles":s.get("distance_miles")}
            by_vol[vn]["stops"].append(s)
        route_groups=list(by_vol.values())
        run.update({
            "stops":stops,"total_stops":total,"done_count":done_count,"pct":pct,
            "vol_names":list({s["volunteer_name"] for s in stops if s.get("volunteer_name")}),
            "vol_tokens":tokens,"routes":route_groups,
            "timestamp":run.get("created_at","")[:16].replace("T"," ") if run.get("created_at") else "",
            "type":run.get("run_type","optimized"),
            "done_keys":[s["id"] for s in stops if s["status"]=="delivered"],
        })
        runs.append(run)
    selected_run=next((r for r in runs if r["id"]==selected_run_id),None)
    return render_template("routes.html", d={"runs":runs,"cname":cname,"cid":campaign_id},
                           runs=runs, selected_run=selected_run, msg=msg)

# ══════════════════════════════════════════════════════════════════════════════
# VOLUNTEER DELIVERY PORTAL  (public)
# ══════════════════════════════════════════════════════════════════════════════
def _get_token(vol_token):
    try:
        rows=db().table("vol_tokens").select("*").eq("token",vol_token).execute().data
        return rows[0] if rows else None
    except Exception as e:
        print(f"_get_token error: {e}",flush=True); return None

@app.route("/deliver/<run_id>/<vol_token>", methods=["GET","POST"])
def vol_deliver(run_id, vol_token):
    tok=_get_token(vol_token)
    if not tok or tok["run_id"]!=run_id: return render_template("deliver_invalid.html"),404
    try:
        exp=datetime.fromisoformat(tok["expires_at"].replace("Z",""))
        if datetime.now()>exp: return render_template("deliver_expired.html"),410
    except: pass
    campaign_id=tok["campaign_id"]; vol_name=tok["volunteer_name"]
    run_rows=db().table("runs").select("*").eq("id",run_id).execute().data
    if not run_rows: return render_template("deliver_invalid.html"),404
    run=run_rows[0]

    if request.method == "POST":
        action=request.form.get("action"); stop_id=request.form.get("stop_id","")
        if action=="mark_done" and stop_id:
            _deliver_stop(stop_id,campaign_id,vol_name)

        elif action=="upload_photo" and stop_id:
            photo_file=request.files.get("photo")
            lat=request.form.get("lat"); lng=request.form.get("lng")
            if photo_file and photo_file.filename:
                file_bytes=photo_file.read()
                url=upload_photo(campaign_id,stop_id,file_bytes,photo_file.mimetype)
                if url:
                    now=datetime.now()
                    # Store photo on the run_stop row — single source of truth
                    db().table("run_stops").update({
                        "photo_url":url,
                        "photo_taken_at":now.strftime("%b %d, %Y %I:%M %p"),
                        "photo_lat":float(lat) if lat else None,
                        "photo_lng":float(lng) if lng else None,
                    }).eq("id",stop_id).execute()
                    # Mirror onto constituent
                    stop_rows=db().table("run_stops").select("constituent_id").eq("id",stop_id).execute().data
                    if stop_rows and stop_rows[0].get("constituent_id"):
                        db().table("constituents").update({
                            "photo_url":url,"photo_taken_at":now.strftime("%b %d, %Y %I:%M %p"),
                        }).eq("id",stop_rows[0]["constituent_id"]).execute()
                    # Auto-mark delivered
                    _deliver_stop(stop_id,campaign_id,vol_name)
                    # Audit log
                    try:
                        cst_id=stop_rows[0]["constituent_id"] if stop_rows else None
                        db().table("sign_photos").insert({
                            "id":str(uuid.uuid4()),"run_stop_id":stop_id,
                            "run_id":run_id,"campaign_id":campaign_id,
                            "constituent_id":cst_id,"volunteer_name":vol_name,
                            "photo_url":url,
                            "lat":float(lat) if lat else None,
                            "lng":float(lng) if lng else None,
                        }).execute()
                    except Exception as e: print(f"sign_photos insert error: {e}",flush=True)
                else:
                    print("upload_photo returned empty URL — photo NOT saved",flush=True)

        elif action=="delete_photo" and stop_id:
            db().table("run_stops").update({"photo_url":None,"photo_taken_at":None}).eq("id",stop_id).execute()

        return redirect(url_for("vol_deliver",run_id=run_id,vol_token=vol_token))

    # Always load fresh from DB
    stops=db().table("run_stops").select("*")\
              .eq("run_id",run_id).eq("volunteer_name",vol_name)\
              .order("stop_order").execute().data or []
    total=len(stops); done_ct=sum(1 for s in stops if s["status"]=="delivered")
    return render_template("deliver.html",
                           run=run,stops=stops,vol_name=vol_name,
                           total=total,done_ct=done_ct,
                           run_id=run_id,vol_token=vol_token)

@app.route("/deliver/<run_id>/<vol_token>/progress")
def vol_deliver_progress(run_id, vol_token):
    tok=_get_token(vol_token)
    if not tok: return jsonify({"error":"not found"}),404
    stops=db().table("run_stops").select("id,status")\
              .eq("run_id",run_id).eq("volunteer_name",tok["volunteer_name"]).execute().data or []
    total=len(stops); done=sum(1 for s in stops if s["status"]=="delivered")
    return jsonify({"done":done,"total":total,"pct":round(done/total*100) if total else 0})


# ══════════════════════════════════════════════════════════════════════════════
# MAP VIEWPORT API  — returns only constituents visible in current bounds
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/api/constituents")
@login_required
def api_constituents():
    campaign_id = cid()
    try:
        south = float(request.args.get("south", 0))
        north = float(request.args.get("north", 0))
        west  = float(request.args.get("west",  0))
        east  = float(request.args.get("east",  0))
        status_filter = request.args.get("status", "all")  # all | pending | delivered
    except ValueError:
        return jsonify([])

    try:
        q = db().table("constituents")            .select("id,address,lat,lng,status,missing,first_name,last_name,party,precinct,support_score,photo_url")            .eq("campaign_id", campaign_id)            .gte("lat", south).lte("lat", north)            .gte("lng", west).lte("lng", east)
        if status_filter != "all":
            q = q.eq("status", status_filter)
        rows = sanitize(q.limit(2000).execute().data or [])
        return jsonify(rows)
    except Exception as e:
        print(f"api_constituents error: {e}", flush=True)
        return jsonify([])

@app.route("/api/constituents/stats")
@login_required
def api_constituent_stats():
    campaign_id = cid()
    try:
        all_rows = db().table("constituents")            .select("id,status,missing")            .eq("campaign_id", campaign_id).execute().data or []
        total    = len(all_rows)
        placed   = sum(1 for r in all_rows if r.get("status") == "delivered")
        pending  = total - placed
        missing  = sum(1 for r in all_rows if r.get("missing"))
        return jsonify({"total": total, "placed": placed, "pending": pending, "missing": missing})
    except Exception as e:
        return jsonify({"total":0,"placed":0,"pending":0,"missing":0})

# ══════════════════════════════════════════════════════════════════════════════
# ANALYTICS
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/analytics")
@login_required
def analytics():
    from collections import defaultdict
    campaign_id=cid(); cname=session.get("cname","Campaign")
    all_csts=sanitize(db().table("constituents").select("id,status,party,support_score,sign_requested,donor,volunteer_interest,delivered_date,delivered_by").eq("campaign_id",campaign_id).execute().data or [])
    all_runs=sanitize(db().table("runs").select("*").eq("campaign_id",campaign_id).execute().data or [])
    all_stops=sanitize(db().table("run_stops").select("id,status,volunteer_name,delivered_at,photo_url").eq("campaign_id",campaign_id).execute().data or [])
    all_photos=sanitize(db().table("sign_photos").select("id,volunteer_name,taken_at").eq("campaign_id",campaign_id).execute().data or [])

    total_csts=len(all_csts); total_placed=sum(1 for a in all_csts if a["status"]=="delivered")
    pct_complete=round(total_placed/total_csts*100) if total_csts else 0

    # Signs placed per day — last 14 days
    placed_by_day=defaultdict(int)
    for a in all_csts:
        if a["status"]=="delivered" and a.get("delivered_date"):
            placed_by_day[a["delivered_date"]]+=1
    days_data=[]
    for i in range(13,-1,-1):
        d=(datetime.now()-timedelta(days=i)).strftime("%b %d")
        days_data.append({"date":d,"count":placed_by_day.get(d,0)})

    # Volunteer leaderboard
    vol_stats=defaultdict(lambda:{"name":"","placed":0,"photos":0})
    for s in all_stops:
        vn=s["volunteer_name"] or "Unknown"
        vol_stats[vn]["name"]=vn
        if s["status"]=="delivered": vol_stats[vn]["placed"]+=1
        if s.get("photo_url"):       vol_stats[vn]["photos"]+=1
    leaderboard=sorted(vol_stats.values(),key=lambda x:x["placed"],reverse=True)

    # Party breakdown
    party_counts=defaultdict(int)
    for a in all_csts: party_counts[a.get("party") or "Unknown"]+=1

    # Support score distribution
    score_counts=defaultdict(int)
    for a in all_csts:
        s=a.get("support_score")
        if s: score_counts[str(s)]+=1

    # Run completion
    run_stats=[]
    for run in all_runs:
        rs=db().table("run_stops").select("id,status").eq("run_id",run["id"]).execute().data or []
        done=sum(1 for s in rs if s["status"]=="delivered"); total=len(rs)
        run_stats.append({"name":run["name"],"done":done,"total":total,
                          "pct":round(done/total*100) if total else 0,"status":run["status"]})

    return render_template("analytics.html", d={
        "cname":cname,"cid":campaign_id,
        "total_csts":total_csts,"total_placed":total_placed,
        "total_pending":total_csts-total_placed,"pct_complete":pct_complete,
        "total_runs":len(all_runs),"total_photos":len(all_photos),
        "sign_requests":sum(1 for a in all_csts if a.get("sign_requested")),
        "days_data":days_data,"leaderboard":leaderboard,
        "party_counts":dict(party_counts),"score_counts":dict(score_counts),
        "run_stats":run_stats,
    })

# ══════════════════════════════════════════════════════════════════════════════
# OUTREACH / EMAILS
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/outreach")
@login_required
def outreach():
    campaign_id=cid(); cname=session.get("cname","Campaign")
    active_run_id=session.get("active_run_id")
    if not active_run_id:
        runs=db().table("runs").select("*").eq("campaign_id",campaign_id).order("created_at",desc=True).execute().data
        active_run_id=runs[0]["id"] if runs else None
    emails=[]
    if active_run_id:
        tokens=sanitize(db().table("vol_tokens").select("*").eq("run_id",active_run_id).execute().data or [])
        for tok in tokens:
            stops=db().table("run_stops").select("*")\
                      .eq("run_id",active_run_id).eq("volunteer_name",tok["volunteer_name"])\
                      .order("stop_order").execute().data or []
            vr=sanitize(db().table("volunteers").select("*").eq("id",tok.get("volunteer_id","")).execute().data or [])
            vol=vr[0] if vr else {"name":tok["volunteer_name"],"email":"","phone":"","address":""}
            body="\n".join([f"Hi {vol['name']},",f"\nThank you for volunteering for {cname}!",
                            f"\nYou have {len(stops)} stop{'s' if len(stops)!=1 else ''}:\n"]+
                           [f"  Stop {i+1}: {s['address']}\n  Directions: {gmaps_url(vol.get('address',''), s['address'])}" for i,s in enumerate(stops)]+
                           [f"\nThank you!\n{cname} Team"])
            subj=f"{cname} - Your Yard Sign Delivery Route"
            share_url=request.host_url.rstrip("/")+url_for("vol_deliver",run_id=active_run_id,vol_token=tok["token"])
            vp=(vol.get("phone","") or "").translate(str.maketrans("","","- ()"))
            stops_txt="\n".join([f"  {i+1}. {s['address'].split(',')[0]}" for i,s in enumerate(stops)])
            txt=f"Hi {vol['name']}! {cname} here. {len(stops)} stop{'s' if len(stops)!=1 else ''} today:\n{stops_txt}\nDelivery link: {share_url}"
            emails.append({
                "volunteer":vol,"body":body,"subj":subj,"share_url":share_url,
                "mailto":f"mailto:{vol.get('email','')}?"+urllib.parse.urlencode({"subject":subj,"body":body}) if vol.get("email") else "",
                "sms":f"sms:{vp}&body={urllib.parse.quote(txt)}" if vp else "",
                "txt":txt,
            })
    return render_template("emails.html",d={"cname":cname,"cid":campaign_id},emails=emails,
                           bulk_mailto="",bulk_sms="",
                           all_em_count=len([e for e in emails if e["volunteer"].get("email")]),
                           all_ph_count=len([e for e in emails if e["volunteer"].get("phone")]))

# ══════════════════════════════════════════════════════════════════════════════
# SEARCH
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/routes/search")
@login_required
def routes_search():
    campaign_id=cid(); cname=session.get("cname","Campaign"); q=request.args.get("q","").strip().lower()
    results={"vols":[],"addrs":[]}
    if q:
        vols=db().table("volunteers").select("*").eq("campaign_id",campaign_id).execute().data or []
        addrs_raw=db().table("constituents").select("id,address,lat,lng,status,missing,first_name,last_name,photo_url").eq("campaign_id",campaign_id).execute().data or []
        addrs=sanitize(addrs_raw)
        results["vols"]=[v for v in vols if q in json.dumps(v).lower()]
        results["addrs"]=[a for a in addrs if q in json.dumps(a).lower()]
    return render_template("routes_search.html",d={"cname":cname,"cid":campaign_id},q=q,results=results)

# ══════════════════════════════════════════════════════════════════════════════
# INTEGRATIONS
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/integrations", methods=["GET","POST"])
@login_required
def integrations_page():
    campaign_id=cid(); intgs=get_integrations(campaign_id); msg=None
    if request.method == "POST":
        action=request.form.get("action"); provider=request.form.get("provider","")
        if action=="disconnect":
            delete_integration(campaign_id,provider)
            msg=f"Disconnected {INTEGRATIONS.get(provider,{}).get('name',provider)}."
        elif action=="manual_api_key":
            api_key=request.form.get("api_key","").strip()
            if api_key:
                save_integration(campaign_id,provider,{
                    "status":"connected","access_token_enc":encrypt_token(api_key),
                    "auth_type":"api_key","connected_at":datetime.now().isoformat(),
                    "nb_slug":request.form.get("nb_slug","").strip(),
                })
                msg=f"Connected {INTEGRATIONS.get(provider,{}).get('name',provider)}."
        return redirect(url_for("integrations_page"))
    return render_template("integrations.html",integrations=INTEGRATIONS,connected=intgs,msg=msg)

@app.route("/integrations/connect/<provider>")
@login_required
def oauth_connect(provider):
    cfg=INTEGRATIONS.get(provider)
    if not cfg or cfg.get("status")=="coming_soon" or not cfg.get("client_id"):
        return redirect(url_for("integrations_page"))
    nb_slug=request.args.get("slug","").strip()
    auth_url=cfg["auth_url"].replace("{slug}",nb_slug) if provider=="nationbuilder" else cfg["auth_url"]
    if provider=="nationbuilder": session["nb_slug"]=nb_slug
    state=hashlib.sha256(f"{session['cid']}{app.secret_key}".encode()).hexdigest()
    session["oauth_state"]=state
    callback=url_for("oauth_callback",provider=provider,_external=True)
    params={"response_type":"code","client_id":cfg["client_id"],
            "redirect_uri":callback,"scope":cfg.get("scope",""),"state":state}
    return redirect(auth_url+"?"+urllib.parse.urlencode(params))

@app.route("/integrations/callback/<provider>")
@login_required
def oauth_callback(provider):
    cfg=INTEGRATIONS.get(provider,{}); code=request.args.get("code"); state=request.args.get("state")
    campaign_id=session["cid"]
    expected=hashlib.sha256(f"{campaign_id}{app.secret_key}".encode()).hexdigest()
    if state!=expected or not code: return redirect(url_for("integrations_page"))
    nb_slug=session.pop("nb_slug","")
    token_url=cfg.get("token_url","")
    if provider=="nationbuilder" and nb_slug: token_url=token_url.replace("{slug}",nb_slug)
    callback=url_for("oauth_callback",provider=provider,_external=True)
    try:
        resp=requests.post(token_url,data={
            "grant_type":"authorization_code","code":code,"redirect_uri":callback,
            "client_id":cfg["client_id"],"client_secret":cfg["client_secret"],
        },timeout=15)
        token_data=resp.json()
    except Exception as e:
        print(f"OAuth error: {e}",flush=True); return redirect(url_for("integrations_page"))
    access_token=token_data.get("access_token","")
    if not access_token: return redirect(url_for("integrations_page"))
    save_integration(campaign_id,provider,{
        "status":"connected","access_token_enc":encrypt_token(access_token),
        "refresh_token_enc":encrypt_token(token_data.get("refresh_token","")),
        "token_expiry":(datetime.now()+timedelta(seconds=token_data.get("expires_in",3600))).isoformat(),
        "auth_type":"oauth2","connected_at":datetime.now().isoformat(),
        "nb_slug":nb_slug,"scopes":cfg.get("scope",""),
    })
    return redirect(url_for("integrations_page"))

if __name__ == "__main__":
    app.run(debug=True, port=5000)
