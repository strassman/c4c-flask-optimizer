#!/usr/bin/env python3
"""
score_sign_locations.py
-----------------------
Fetches MDOT SHA road segment polylines with AADT + speed limits,
scores each segment for yard sign visibility, and stores to Supabase.

The map renders these as colored road lines (green/yellow/red) like
Apple Maps traffic — not dots. Click a segment for the full breakdown.

Data sources (free, no API key):
  Layer 1 — AADT Segments (polyline): FeatureServer/1
  Layer 0 — Speed limits (point):     MD_RoadwayPostedSpeedLimits/MapServer/0
  Layer 9 — MTA Bus stops (point):    MD_Transit/FeatureServer/9

Legal filter: IS_SHA_MAINTAINED=Y segments excluded (state ROW illegal).
"""

import os, sys, math, json, time, requests
from supabase import create_client

SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://zzonrxvtvbgxyitoyuia.supabase.co")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")
CAMPAIGN_ID  = os.environ.get("CAMPAIGN_ID", "demo-conway-2024")

# Bounding box — Baltimore/Catonsville area
BBOX = {"xmin":-77.0,"ymin":39.15,"xmax":-76.35,"ymax":39.55}
MAX_SPEED   = 45
MIN_AADT    = 1500
TOP_N       = 400

SEGMENTS_URL = "https://geodata.md.gov/imap/rest/services/Transportation/MD_AnnualAverageDailyTraffic/FeatureServer/1/query"
SPEED_URL    = "https://geodata.md.gov/imap/rest/services/Transportation/MD_RoadwayPostedSpeedLimits/MapServer/0/query"
TRANSIT_URL  = "https://geodata.md.gov/imap/rest/services/Transportation/MD_Transit/FeatureServer/9/query"

def haversine_m(lat1,lng1,lat2,lng2):
    R=6_371_000; φ1,φ2=math.radians(lat1),math.radians(lat2)
    dφ=math.radians(lat2-lat1); dλ=math.radians(lng2-lng1)
    a=math.sin(dφ/2)**2+math.cos(φ1)*math.cos(φ2)*math.sin(dλ/2)**2
    return R*2*math.atan2(math.sqrt(a),math.sqrt(1-a))

def arcgis_query(url, extra, retries=3):
    params = {
        "f":"json","outFields":"*","returnGeometry":"true",
        "geometryType":"esriGeometryEnvelope","inSR":"4326","outSR":"4326",
        "geometry":json.dumps({"xmin":BBOX["xmin"],"ymin":BBOX["ymin"],
                               "xmax":BBOX["xmax"],"ymax":BBOX["ymax"],
                               "spatialReference":{"wkid":4326}}),
        "spatialRel":"esriSpatialRelIntersects",
        "resultOffset":0,"resultRecordCount":2000,
    }
    params.update(extra)
    all_feats=[]; offset=0
    while True:
        params["resultOffset"]=offset
        for attempt in range(retries):
            try:
                r=requests.get(url,params=params,timeout=45)
                data=r.json(); break
            except Exception as e:
                if attempt==retries-1: return all_feats
                time.sleep(2**attempt)
        feats=data.get("features",[])
        all_feats.extend(feats)
        if len(feats)<2000: break
        offset+=2000; time.sleep(0.3)
    return all_feats

def centroid(paths):
    """Compute centroid lat/lng from a polyline paths array."""
    pts=[]
    for path in paths:
        pts.extend(path)
    if not pts: return None,None
    return sum(p[1] for p in pts)/len(pts), sum(p[0] for p in pts)/len(pts)

def fetch_segments():
    print("📡 Fetching MDOT AADT road segments (polylines)...")
    feats = arcgis_query(SEGMENTS_URL, {
        "where": f"AADT >= {MIN_AADT}",
        "outFields": "ROADNAME,AADT,FUNC_CLASS,IS_SHA_MAINTAINED,MUNICIPALITY,COUNTY,SPEED_LIMIT",
    })
    segments=[]
    for f in feats:
        g=f.get("geometry",{}); a=f.get("attributes",{})
        paths=g.get("paths",[])
        if not paths: continue
        # Legal filter — skip SHA maintained (state ROW)
        if a.get("IS_SHA_MAINTAINED")=="Y": continue
        # Skip interstates/expressways
        try:
            if int(a.get("FUNC_CLASS") or 9)<=2: continue
        except: pass
        aadt=a.get("AADT") or 0
        if not aadt: continue
        lat,lng=centroid(paths)
        if not lat: continue
        # Speed limit — some segments have it directly, others need matching
        sl=a.get("SPEED_LIMIT")
        try: sl=int(sl) if sl else None
        except: sl=None
        segments.append({
            "road_name": a.get("ROADNAME") or "",
            "aadt": int(aadt),
            "speed_limit": sl,
            "func_class": a.get("FUNC_CLASS"),
            "municipality": a.get("MUNICIPALITY") or "",
            "county": a.get("COUNTY") or "",
            "lat": lat, "lng": lng,
            "paths": paths,  # keep geometry for map rendering
        })
    print(f"  → {len(segments)} eligible segments")
    return segments

def fetch_speed_points():
    print("📡 Fetching speed limit signs...")
    feats=arcgis_query(SPEED_URL,{"where":"1=1","outFields":"SPEED_LIM"})
    pts=[]
    for f in feats:
        g=f.get("geometry",{}); a=f.get("attributes",{})
        lat,lng=g.get("y"),g.get("x")
        if not lat or not lng: continue
        try: sl=int(a.get("SPEED_LIM") or 0)
        except: continue
        if sl>0: pts.append({"lat":lat,"lng":lng,"speed_limit":sl})
    print(f"  → {len(pts)} speed signs")
    return pts

def match_speeds(segments, speed_pts, radius=250):
    print("🔗 Matching speed limits to segments...")
    matched=0
    for seg in segments:
        if seg["speed_limit"]: continue  # already has one
        best_d=float("inf"); best_sl=None
        for sp in speed_pts:
            d=haversine_m(seg["lat"],seg["lng"],sp["lat"],sp["lng"])
            if d<best_d: best_d=d; best_sl=sp["speed_limit"]
        seg["speed_limit"]= best_sl if best_d<=radius else 35
        if best_d<=radius: matched+=1
    print(f"  → {matched} matched from speed signs, rest defaulted to 35mph")
    return segments

def fetch_transit():
    print("📡 Fetching MTA bus stops...")
    feats=arcgis_query(TRANSIT_URL,{"where":"1=1","outFields":"STOP_NAME"})
    stops=[]
    for f in feats:
        g=f.get("geometry",{}); a=f.get("attributes",{})
        lat,lng=g.get("y"),g.get("x")
        if lat and lng: stops.append({"lat":lat,"lng":lng,"name":a.get("STOP_NAME") or ""})
    print(f"  → {len(stops)} bus stops")
    return stops

def enrich(segments, transit_stops, db):
    print("🚌 Adding transit + supporter bonuses...")
    # Fetch supporters once
    supporters=db.table("constituents").select("lat,lng")        .eq("campaign_id",CAMPAIGN_ID).in_("party",["DEM","UNA"])        .gte("support_score",60)        .gte("lat",BBOX["ymin"]).lte("lat",BBOX["ymax"])        .gte("lng",BBOX["xmin"]).lte("lng",BBOX["xmax"])        .limit(50000).execute().data or []
    print(f"  → {len(supporters)} supporters in bbox")
    for seg in segments:
        # Transit: any stop within 150m of segment centroid
        seg["near_transit"]=False; seg["transit_stop"]=""
        for stop in transit_stops:
            if haversine_m(seg["lat"],seg["lng"],stop["lat"],stop["lng"])<=150:
                seg["near_transit"]=True; seg["transit_stop"]=stop["name"]; break
        # Supporters within 400m
        seg["supporter_count"]=sum(
            1 for s in supporters
            if s.get("lat") and s.get("lng")
            and haversine_m(seg["lat"],seg["lng"],s["lat"],s["lng"])<=400
        )
    return segments

def score(segments):
    print("📊 Scoring segments...")
    for seg in segments:
        sl=max(seg.get("speed_limit") or 35, 10)
        if sl>MAX_SPEED: seg["score"]=0; seg["tier"]="D"; continue
        base = seg["aadt"] * (25/sl)
        transit  = base*0.25 if seg.get("near_transit") else 0
        density  = base*0.15 if seg.get("supporter_count",0)>=3 else 0
        seg["score"]=round(base+transit+density,1)
        if   seg["score"]>=8000: seg["tier"]="A"
        elif seg["score"]>=4000: seg["tier"]="B"
        elif seg["score"]>=2000: seg["tier"]="C"
        else:                    seg["tier"]="D"
    ranked=sorted(segments,key=lambda x:x["score"],reverse=True)
    for t in "ABCD":
        n=sum(1 for s in ranked if s["tier"]==t)
        if n: print(f"  Tier {t}: {n}")
    return ranked

def write(scored, db):
    print(f"💾 Writing top {TOP_N} to Supabase...")
    db.table("sign_suggestions").delete().eq("campaign_id",CAMPAIGN_ID).execute()
    rows=[]
    for seg in scored[:TOP_N]:
        sl=seg.get("speed_limit") or 35
        if sl>MAX_SPEED: continue
        rows.append({
            "campaign_id":    CAMPAIGN_ID,
            "lat":            round(seg["lat"],6),
            "lng":            round(seg["lng"],6),
            "road_name":      seg["road_name"],
            "aadt":           seg["aadt"],
            "speed_limit":    sl,
            "near_transit":   seg.get("near_transit",False),
            "transit_stop":   seg.get("transit_stop",""),
            "supporter_count":seg.get("supporter_count",0),
            "score":          seg["score"],
            "tier":           seg["tier"],
            "municipality":   seg.get("municipality",""),
            "path_json":      json.dumps(seg["paths"]),  # polyline geometry
        })
    for i in range(0,len(rows),100):
        db.table("sign_suggestions").insert(rows[i:i+100]).execute()
    print(f"  → {len(rows)} rows written ✅")
    if rows:
        top=scored[0]
        print(f"\n✅ Top: {top['road_name']} — {top['aadt']:,} cars/day "
              f"@ {top['speed_limit']}mph → score {top['score']:,.0f} (Tier {top['tier']})")

def main():
    if not SUPABASE_KEY:
        print("❌ Set SUPABASE_KEY env var"); sys.exit(1)
    db=create_client(SUPABASE_URL,SUPABASE_KEY)
    segs   = fetch_segments()
    speeds = fetch_speed_points()
    segs   = match_speeds(segs,speeds)
    segs   = [s for s in segs if (s.get("speed_limit") or 35)<=MAX_SPEED]
    print(f"  → {len(segs)} segments after speed filter")
    transit= fetch_transit()
    segs   = enrich(segs,transit,db)
    scored = score(segs)
    write(scored,db)

if __name__=="__main__":
    main()
