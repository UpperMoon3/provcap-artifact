"""Confirm deletions: fetch single-post embeds (t.me/<ch>/<id>?embed=1) into a separate ProvCap archive.
Usage: python3 probe.py ARCH_PROBE targets.json out.json label
targets.json: list of [channel, id]
"""
import json, os, sys, time, random
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from provcap import Acquirer
from tgparse import embed_status

root, tf, out, label = sys.argv[1:5]
targets = json.load(open(tf))
acq = Acquirer(root)
acq.begin(label)
res = json.load(open(out)) if os.path.exists(out) else {}


def one(t):
    ch, i = t
    html, e = acq.fetch(f"https://t.me/{ch}/{i}?embed=1&mode=tme", "probe")
    time.sleep(0.5 + random.random() * 0.5)
    return f"{ch}/{i}", dict(status=embed_status(html) if html else "error", seq=e["seq"] if e else None,
                             t=e["t_resp"] if e else None)


with ThreadPoolExecutor(8) as pool:
    for k, v in pool.map(one, targets):
        res[k] = v
s = acq.seal()
json.dump(res, open(out, "w"), indent=0)
from collections import Counter
print(Counter(v["status"] for v in res.values()), "seal", s["merkle_root"][:16], [t.get("gen_time") for t in s["tsr"]])
