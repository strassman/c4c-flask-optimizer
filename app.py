import os, math, uuid, hashlib, requests, urllib.parse
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, session, redirect, url_for, jsonify
from flask_session import Session
from supabase import create_client
from geopy.geocoders import Nominatim

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
    keys = ["vols","addrs","run_ids","done","history"]
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

def get_data():
    """Get campaign data from session cache."""
    cid = session["cid"]
    if session.get("loaded_for") != cid:
        d = load_all(cid)
        session["vols"]    = d["vols"]    or []
        session["addrs"]   = d["addrs"]   or []
        session["run_ids"] = d["run_ids"] or []
        session["done"]    = d["done"]    or []
        session["history"] = d["history"] or []
        session["loaded_for"] = cid
    return {
        "vols":    session.get("vols", []),
        "addrs":   session.get("addrs", []),
        "run_ids": session.get("run_ids", []),
        "done":    {c["key"]:c for c in session.get("done", [])},
        "history": session.get("history", []),
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
                d["vols"].append({"name":name,
                    "email":request.form.get("email","").strip(),
                    "phone":request.form.get("phone","").strip(),
                    "address":addr})
                save_session("vols", d["vols"])
                msg = f"✅ {name} added!"
            else:
                msg = "❌ Name, street, city, state, ZIP required."
        elif action == "delete":
            name = request.form.get("name")
            d["vols"] = [v for v in d["vols"] if v["name"] != name]
            save_session("vols", d["vols"])
            msg = "Volunteer removed."
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
                entry = {"id":str(uuid.uuid4()),"address":addr,
                    "contact":request.form.get("contact","").strip(),
                    "phone":request.form.get("phone","").strip(),
                    "email":request.form.get("email","").strip(),
                    "note":request.form.get("note","").strip(),
                    "sign_requested": request.form.get("sign_requested") == "1",
                    "status":"pending"}
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
                session["routes"] = routes
                session["prox"]   = None
                rec={"timestamp":datetime.now().strftime("%b %d, %Y at %I:%M %p"),"routes":routes}
                d["history"]=[rec]+(d["history"] or [])
                save_session("history", d["history"])
                return redirect(url_for("map_page"))
            else:  # proximity
                clusters={i:[] for i in range(len(vr))}
                for x in dr:
                    best=min(range(len(vr)),key=lambda vi:hav((vr[vi]["lat"],vr[vi]["lng"]),(x["lat"],x["lng"])))
                    clusters[best].append(x)
                prox_routes=[]
                for vi,vol in enumerate(vr):
                    if not clusters[vi]: continue
                    prox_routes.append({"volunteer":vol,"stops":clusters[vi],
                        "distance_miles":"—","road_geometry":None,
                        "color":COLORS[vi%len(COLORS)],"hex":HEX_COLORS[vi%len(HEX_COLORS)]})
                # Convert clusters to list-of-lists for JSON compatibility
                clusters_list = [clusters[i] for i in range(len(vr))]
                session["prox"]   = {"volunteers":vr,"clusters":clusters_list,
                    "timestamp":datetime.now().strftime("%b %d, %Y at %I:%M %p")}
                session["routes"] = prox_routes
                # Save to history so Routes page shows it
                rec = {"timestamp": datetime.now().strftime("%b %d, %Y at %I:%M %p") + " (proximity)",
                       "routes": prox_routes}
                d["history"] = [rec] + (d["history"] or [])
                save_session("history", d["history"])
                return redirect(url_for("map_page"))
        return redirect(url_for("delivery_run"))

    avail = session.get("avail", [])
    return render_template("delivery_run.html", d=d, msg=msg, avail=avail)

# ══════════════════════════════════════════════════════════════════════════════
# MAP
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/map")
@login_required
def map_page():
    d         = get_data()
    routes    = session.get("routes", [])
    prox      = session.get("prox", None)
    done_keys = list(d["done"].keys())

    # Build all_pending_routes: deduplicated stops across ALL history
    # keyed by address so same address doesn't appear twice across runs
    seen_addresses = set()
    all_pending_routes = []
    for rec in d["history"]:
        for r in rec.get("routes", []):
            vol = r.get("volunteer", {})
            pending_stops = []
            for i, s in enumerate(r.get("stops", [])):
                key = vol.get("name","") + "_" + str(i)
                addr = s.get("address","")
                if key not in done_keys and addr not in seen_addresses and addr:
                    pending_stops.append({"stop": s, "index": i})
                    seen_addresses.add(addr)
            if pending_stops:
                all_pending_routes.append({
                    "volunteer": vol,
                    "stops_with_index": pending_stops,
                    "hex": r.get("hex", "#4a9eff"),
                    "color": r.get("color", "blue"),
                })

    return render_template("map.html", d=d, routes=routes, prox=prox,
                           done_keys=done_keys,
                           all_pending_routes=all_pending_routes,
                           HEX_COLORS=HEX_COLORS, COLORS=COLORS)

@app.route("/map/reset")
@login_required
def map_reset():
    session.pop("routes", None)
    session.pop("prox", None)
    return redirect(url_for("map_page"))

# ══════════════════════════════════════════════════════════════════════════════
# ROUTES HISTORY
# ══════════════════════════════════════════════════════════════════════════════
@app.route("/routes", methods=["GET","POST"])
@login_required
def routes_page():
    d = get_data()
    if request.method == "POST":
        action = request.form.get("action")
        if action == "delete_run":
            ri = int(request.form.get("run_index",0))
            if 0 <= ri < len(d["history"]):
                d["history"].pop(ri)
                save_session("history", d["history"])
                if d["history"]:
                    session["routes"] = d["history"][0]["routes"]
                else:
                    session["routes"] = []
        elif action == "mark_done":
            key  = request.form.get("key")
            addr = request.form.get("address")
            vid  = request.form.get("volunteer")
            stop = int(request.form.get("stop_num",0))
            done = {c["key"]:c for c in session.get("done",[])}
            done[key]={"key":key,"address":addr,"volunteer":vid,"stop_num":stop,
                       "delivered_date":datetime.now().strftime("%b %d, %Y")}
            session["done"] = list(done.values())
            save_data(d["cid"],"done",session["done"])
            for a in d["addrs"]:
                if a["address"]==addr:
                    a["status"]="delivered"
                    a["delivered_date"]=datetime.now().strftime("%b %d, %Y")
            save_session("addrs",d["addrs"])
        elif action == "unmark_done":
            key  = request.form.get("key")
            addr = request.form.get("address")
            done = {c["key"]:c for c in session.get("done",[])}
            done.pop(key,None)
            session["done"] = list(done.values())
            save_data(d["cid"],"done",session["done"])
            for a in d["addrs"]:
                if a["address"]==addr: a["status"]="pending"
            save_session("addrs",d["addrs"])
        return redirect(url_for("routes_page"))
    done = {c["key"]:c for c in session.get("done",[])}
    return render_template("routes.html", d=d, done=done, gmaps_url=gmaps_url)

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

if __name__ == "__main__":
    app.run(debug=True, port=5000)
