"""Internet Archive coverage via narrow CDX queries (wide prefix queries time out).
For each channel: captures of the listing URL t.me/s/<ch> (exact) and, for a seeded random sample of posts plus all
posts with observed edits or disappearances, captures of the single-post URL t.me/<ch>/<id> (any query string).
Usage: python3 wayback2.py history.json out.json [per_channel]"""
import json, random, re, sys, time, threading, requests
from concurrent.futures import ThreadPoolExecutor
H = json.load(open(sys.argv[1])); OUT = sys.argv[2]; K = int(sys.argv[3]) if len(sys.argv) > 3 else 10
FROM, TO = "20261026", "20261117"
s = requests.Session(); s.headers["User-Agent"] = "academic research (archive coverage study)"
lock = threading.Lock()
try:
    out = json.load(open(OUT))
except Exception:
    out = {"listing": {}, "posts": {}}


def cdx(url, match):
    for k in range(5):
        try:
            r = s.get("http://web.archive.org/cdx/search/cdx", timeout=60, params=dict(url=url, matchType=match, output="json",
                      fl="timestamp,original,statuscode", **{"from": FROM, "to": TO}))
            if r.status_code == 200:
                rows = r.json() if r.text.strip() else []
                return rows[1:] if rows else []
        except Exception:
            pass
        time.sleep(5 * (k + 1))
    return None


by = {}
for k in H["posts"]:
    c, i = k.split("/"); by.setdefault(c, []).append(int(i))
special = {f"{e['ch']}/{e['id']}" for e in H["edits"] + H["disappear"]}
jobs = []
for c in sorted(by):
    if c not in out["listing"]:
        jobs.append(("L", c, None))
    ids = sorted(by[c]); rng = random.Random(c)
    sample = set(rng.sample(ids, min(K, len(ids)))) | {int(k.split("/")[1]) for k in special if k.split("/")[0] == c}
    for i in sorted(sample):
        if f"{c}/{i}" not in out["posts"]:
            jobs.append(("P", c, i))
random.Random(7).shuffle(jobs)  # partial completion = random sample
print("jobs", len(jobs), flush=True)


def run(j):
    t, c, i = j
    if t == "L":
        res = cdx(f"t.me/s/{c}", "exact")
    else:
        rows = cdx(f"t.me/{c}/{i}", "exact")
        res = None if rows is None else [r for r in rows if re.match(rf"https?://t\.me/{re.escape(c)}/{i}(\?|$|/)", r[1], re.I)]
    with lock:
        (out["listing"] if t == "L" else out["posts"])[c if t == "L" else f"{c}/{i}"] = res
    time.sleep(0.5)


with ThreadPoolExecutor(3) as pool:
    for n, _ in enumerate(pool.map(run, jobs)):
        if n % 20 == 0:
            with lock:
                json.dump(out, open(OUT, "w"))
            print(n, flush=True)
json.dump(out, open(OUT, "w")); print("done", flush=True)
