#!/usr/bin/env python3
"""
score_sign_locations.py
-----------------------
Fetches public Maryland traffic + transit data, scores road segments
for yard sign placement visibility, and writes top candidates to Supabase.

Data sources (all free, no API key needed):
  1. MDOT SHA AADT Points  — daily car volume per location
     https://geodata.md.gov/imap/rest/services/Transportation/MD_AnnualAverageDailyTraffic/FeatureServer/0
  2. MDOT SHA Speed Limits — posted speed per road segment
     https://geodata.md.gov/imap/rest/services/Transportation/MD_RoadwayPostedSpeedLimits/MapServer/0
  3. Maryland MTA Bus Stops — transit foot traffic proximity bonus
     https://geodata.md.gov/imap/rest/services/Transportation/MD_Transit/FeatureServer/9

Scoring formula:
  base_score   = AADT × (25 / speed_limit)          # speed-adjusted impressions
  transit_bonus= base_score × 0.25  if bus stop ≤150m
  density_bonus= base_score × 0.15  if ≥3 supporters within 400m
  final_score  = base_score + transit_bonus + density_bonus

Legal filter:
  SHA-maintained roads (IS_STATE_HWY = true) are EXCLUDED — placing
  signs in state right-of-way is illegal under MD Transportation §8-208.
  Divided highways / interstates filtered by functional class ≥ 1.
"""

import os, sys, math, json, time, requests
from supabase import create_client

# ── Config ────────────────────────────────────────────────────────────────────
SUPABASE_URL = os.environ.get("SUPABASE_URL", "https://zzonrxvtvbgxyitoyuia.supabase.co")
SUPABASE_KEY = os.environ.get("SUPABASE_KEY", "")  # set via env
CAMPAIGN_ID  = os.environ.get("CAMPAIGN_ID", "demo-conway-2024")

# Bounding box — Baltimore County / Catonsville area (expand as needed)
BBOX = {
    "xmin": -77.0,  "ymin": 39.15,
    "xmax": -76.35, "ymax": 39.55,
}
MAX_SPEED_ALLOWED = 45   # skip roads faster than this (ineffective for signs)
MIN_AADT          = 2000 # skip roads with fewer than 2k cars/day
TOP_N             = 300  # store top N candidates in Supabase

# MDOT ArcGIS REST endpoints
AADT_URL    = "https://geodata.md.gov/imap/rest/services/Transportation/MD_AnnualAverageDailyTraffic/FeatureServer/0/query"
SPEED_URL   = "https://geodata.md.gov/imap/rest/services/Transportation/MD_RoadwayPostedSpeedLimits/MapServer/0/query"
TRANSIT_URL = "https://geodata.md.gov/imap/rest/services/Transportation/MD_Transit/FeatureServer/9/query"

# ── Helpers ───────────────────────────────────────────────────────────────────
def haversine_m(lat1, lng1, lat2, lng2):
    """Distance in meters between two lat/lng points."""
    R = 6_371_000
    φ1, φ2 = math.radians(lat1), math.radians(lat2)
    dφ = math.radians(lat2 - lat1)
    dλ = math.radians(lng2 - lng1)
    a = math.sin(dφ/2)**2 + math.cos(φ1)*math.cos(φ2)*math.sin(dλ/2)**2
    return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))

def arcgis_query(url, params, retries=3):
    """Query an ArcGIS FeatureServer with pagination support."""
    base = {
        "f": "json",
        "outFields": "*",
        "returnGeometry": "true",
        "geometryType": "esriGeometryEnvelope",
        "inSR": "4326",
        "outSR": "4326",
        "geometry": json.dumps({
            "xmin": BBOX["xmin"], "ymin": BBOX["ymin"],
            "xmax": BBOX["xmax"], "ymax": BBOX["ymax"],
            "spatialReference": {"wkid": 4326}
        }),
        "spatialRel": "esriSpatialRelIntersects",
        "resultOffset": 0,
        "resultRecordCount": 2000,
    }
    base.update(params)
    all_features = []
    offset = 0
    while True:
        base["resultOffset"] = offset
        for attempt in range(retries):
            try:
                r = requests.get(url, params=base, timeout=30)
                data = r.json()
                break
            except Exception as e:
                if attempt == retries - 1:
                    print(f"  ⚠ fetch failed after {retries} tries: {e}")
                    return all_features
                time.sleep(2 ** attempt)
        features = data.get("features", [])
        all_features.extend(features)
        if len(features) < 2000:
            break  # no more pages
        offset += 2000
        time.sleep(0.3)  # be polite to the API
    return all_features

# ── Step 1: Fetch AADT points ─────────────────────────────────────────────────
def fetch_aadt():
    print("📡 Fetching MDOT AADT traffic count points...")
    features = arcgis_query(AADT_URL, {
        "where": f"AADT >= {MIN_AADT}",
        "outFields": "ROADNAME,AADT,COUNTY,FUNC_CLASS,IS_SHA_MAINTAINED,MUNICIPALITY",
    })
    points = []
    for f in features:
        g = f.get("geometry", {})
        a = f.get("attributes", {})
        lat, lng = g.get("y"), g.get("x")
        if not lat or not lng: continue

        # Legal filter: skip SHA-maintained (state right-of-way)
        if a.get("IS_SHA_MAINTAINED") == "Y":
            continue
        # Skip interstates / expressways (functional class 1-2)
        fc = a.get("FUNC_CLASS") or 0
        try:
            if int(fc) <= 2: continue
        except: pass

        aadt = a.get("AADT") or 0
        if not aadt: continue

        points.append({
            "lat": lat, "lng": lng,
            "road_name": a.get("ROADNAME") or "",
            "aadt": int(aadt),
            "county": a.get("COUNTY") or "",
            "municipality": a.get("MUNICIPALITY") or "",
            "func_class": fc,
        })
    print(f"  → {len(points)} eligible AADT points (SHA ROW excluded)")
    return points

# ── Step 2: Fetch speed limits and match to AADT points ──────────────────────
def fetch_speed_limits():
    print("📡 Fetching MDOT speed limit signs...")
    features = arcgis_query(SPEED_URL, {
        "where": "1=1",
        "outFields": "MP_INT_RTE_NAME,SPEED_LIM,ROUTEID,COUNTY",
    })
    speeds = []
    for f in features:
        g = f.get("geometry", {})
        a = f.get("attributes", {})
        # Speed limit points have x/y geometry
        lat = g.get("y") or (g.get("paths", [[[]]])[0][0][1] if g.get("paths") else None)
        lng = g.get("x") or (g.get("paths", [[[]]])[0][0][0] if g.get("paths") else None)
        if not lat or not lng: continue
        sl = a.get("SPEED_LIM")
        if not sl: continue
        try: sl = int(sl)
        except: continue
        speeds.append({"lat": lat, "lng": lng, "speed_limit": sl})
    print(f"  → {len(speeds)} speed limit signs fetched")
    return speeds

def match_speed_to_aadt(aadt_points, speed_points, radius_m=300):
    """For each AADT point, find the nearest speed limit sign within radius."""
    print("🔗 Matching speed limits to traffic points...")
    matched = 0
    for pt in aadt_points:
        best_dist = float("inf")
        best_speed = None
        for sp in speed_points:
            d = haversine_m(pt["lat"], pt["lng"], sp["lat"], sp["lng"])
            if d < best_dist:
                best_dist = d
                best_speed = sp["speed_limit"]
        if best_speed and best_dist <= radius_m:
            pt["speed_limit"] = best_speed
            matched += 1
        else:
            pt["speed_limit"] = 35  # default assumption if no nearby sign
    print(f"  → {matched}/{len(aadt_points)} points matched to speed signs")
    return aadt_points

# ── Step 3: Fetch MTA bus stops ───────────────────────────────────────────────
def fetch_transit_stops():
    print("📡 Fetching MTA bus stops...")
    features = arcgis_query(TRANSIT_URL, {
        "where": "1=1",
        "outFields": "STOP_NAME,ROUTES",
    })
    stops = []
    for f in features:
        g = f.get("geometry", {})
        a = f.get("attributes", {})
        lat, lng = g.get("y"), g.get("x")
        if lat and lng:
            stops.append({
                "lat": lat, "lng": lng,
                "name": a.get("STOP_NAME") or "",
                "routes": a.get("ROUTES") or "",
            })
    print(f"  → {len(stops)} transit stops fetched")
    return stops

def add_transit_bonus(aadt_points, transit_stops, radius_m=150):
    """Mark AADT points within 150m of a bus stop."""
    print("🚌 Computing transit proximity bonus...")
    bonused = 0
    for pt in aadt_points:
        pt["near_transit"] = False
        pt["transit_stop"] = ""
        for stop in transit_stops:
            d = haversine_m(pt["lat"], pt["lng"], stop["lat"], stop["lng"])
            if d <= radius_m:
                pt["near_transit"] = True
                pt["transit_stop"] = stop["name"]
                bonused += 1
                break
    print(f"  → {bonused} points near a transit stop")
    return aadt_points

# ── Step 4: Supporter density from Supabase ──────────────────────────────────
def add_supporter_density(aadt_points, db, radius_m=400):
    """Count DEM/UNA voters with support_score >= 60 near each point."""
    print("🗳  Computing supporter density from voter file...")
    # Pull all supporters in the bounding box once
    supporters = db.table("constituents")\
        .select("lat,lng")\
        .eq("campaign_id", CAMPAIGN_ID)\
        .in_("party", ["DEM", "UNA"])\
        .gte("support_score", 60)\
        .gte("lat", BBOX["ymin"]).lte("lat", BBOX["ymax"])\
        .gte("lng", BBOX["xmin"]).lte("lng", BBOX["xmax"])\
        .limit(50000).execute().data or []
    print(f"  → {len(supporters)} supporters in bounding box")
    for pt in aadt_points:
        count = sum(
            1 for s in supporters
            if s.get("lat") and s.get("lng")
            and haversine_m(pt["lat"], pt["lng"], s["lat"], s["lng"]) <= radius_m
        )
        pt["supporter_count"] = count
    return aadt_points

# ── Step 5: Score everything ──────────────────────────────────────────────────
def score_points(aadt_points):
    print("📊 Scoring sign placement candidates...")
    for pt in aadt_points:
        sl = max(pt.get("speed_limit", 35), 10)  # avoid div/0
        # Core score: traffic adjusted for speed (lower speed = more readable)
        base = pt["aadt"] * (25 / sl)
        # Transit bonus: pedestrians at bus stops add dwell time
        transit = base * 0.25 if pt.get("near_transit") else 0
        # Supporter density: prioritise areas with your voters
        density = base * 0.15 if pt.get("supporter_count", 0) >= 3 else 0
        pt["score"] = round(base + transit + density, 1)
        # Human-readable score tier
        if pt["score"] >= 8000:   pt["tier"] = "A"
        elif pt["score"] >= 4000: pt["tier"] = "B"
        elif pt["score"] >= 2000: pt["tier"] = "C"
        else:                     pt["tier"] = "D"
    scored = sorted(aadt_points, key=lambda x: x["score"], reverse=True)
    print(f"  → Tier A: {sum(1 for p in scored if p['tier']=='A')}  "
          f"B: {sum(1 for p in scored if p['tier']=='B')}  "
          f"C: {sum(1 for p in scored if p['tier']=='C')}")
    return scored

# ── Step 6: Write to Supabase ─────────────────────────────────────────────────
def write_to_supabase(scored_points, db):
    print(f"💾 Writing top {TOP_N} candidates to Supabase...")
    # Clear old suggestions for this campaign
    db.table("sign_suggestions").delete().eq("campaign_id", CAMPAIGN_ID).execute()

    rows = []
    for pt in scored_points[:TOP_N]:
        rows.append({
            "campaign_id":    CAMPAIGN_ID,
            "lat":            round(pt["lat"], 6),
            "lng":            round(pt["lng"], 6),
            "road_name":      pt.get("road_name") or "",
            "aadt":           pt["aadt"],
            "speed_limit":    pt.get("speed_limit", 35),
            "near_transit":   pt.get("near_transit", False),
            "transit_stop":   pt.get("transit_stop") or "",
            "supporter_count":pt.get("supporter_count", 0),
            "score":          pt["score"],
            "tier":           pt["tier"],
            "municipality":   pt.get("municipality") or "",
        })

    # Batch insert in chunks of 100
    for i in range(0, len(rows), 100):
        db.table("sign_suggestions").insert(rows[i:i+100]).execute()
    print(f"  → {len(rows)} rows written ✅")

# ── Main ──────────────────────────────────────────────────────────────────────
def main():
    if not SUPABASE_KEY:
        print("❌ Set SUPABASE_KEY environment variable before running.")
        sys.exit(1)

    db = create_client(SUPABASE_URL, SUPABASE_KEY)

    aadt   = fetch_aadt()
    if not aadt:
        print("❌ No AADT data returned — check network/API status")
        sys.exit(1)

    speeds  = fetch_speed_limits()
    aadt    = match_speed_to_aadt(aadt, speeds)

    # Filter out roads over the speed threshold now that we have speeds
    aadt = [p for p in aadt if p.get("speed_limit", 35) <= MAX_SPEED_ALLOWED]
    print(f"  → {len(aadt)} points after speed filter (≤{MAX_SPEED_ALLOWED}mph)")

    transit = fetch_transit_stops()
    aadt    = add_transit_bonus(aadt, transit)
    aadt    = add_supporter_density(aadt, db)
    scored  = score_points(aadt)
    write_to_supabase(scored, db)

    print(f"\n✅ Done. Top location: {scored[0]['road_name']} — "
          f"{scored[0]['aadt']:,} cars/day @ {scored[0]['speed_limit']}mph "
          f"→ score {scored[0]['score']:,.0f}")

if __name__ == "__main__":
    main()
