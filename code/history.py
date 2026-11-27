"""Derive post-level version histories and edit / disappearance events from a ProvCap archive.

Every derived fact keeps a pointer (ledger seq) to the WARC record it was parsed from, so each
claimed version of a post can be traced back to time-stamped raw bytes.
Usage: python3 history.py ARCH OUT.json
"""
import difflib, io, json, os, re, sys
from collections import defaultdict
from datetime import datetime
from warcio.archiveiterator import ArchiveIterator

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from provcap import sha256
from tgparse import parse_page

NUM = re.compile(r"\d[\d\s.,]*\d|\d")
URL = re.compile(r"https?://\S+|t\.me/\S+", re.I)


def ts(s):
    return datetime.fromisoformat(s).timestamp()


def read_captures(root, purposes=("head", "deep")):
    L = []
    for l in open(f"{root}/ledger.jsonl"):
        try:
            L.append(json.loads(l))
        except ValueError:
            break  # partially written tail while acquisition is running
    files = {}
    for e in L:
        if e["kind"] != "capture" or e["purpose"] not in purposes or e["status"] != 200:
            continue
        p = f"{root}/{e['warc']}"
        if p not in files:
            files[p] = open(p, "rb").read()
        blob = files[p][e["off"]:e["off"] + e["len"]]
        assert sha256(blob) == e["rec_sha256"], e["seq"]
        for r in ArchiveIterator(io.BytesIO(blob)):
            if r.rec_type == "response":
                yield e, r.content_stream().read().decode("utf-8", "replace")


def classify_edit(a, b):
    kinds = []
    if a["text"] != b["text"]:
        kinds.append("text")
    if a["media"] != b["media"]:
        kinds.append("media")
    if a["fwd"] != b["fwd"]:
        kinds.append("fwd")
    sm = difflib.SequenceMatcher(None, a["text"], b["text"], autojunk=False)
    changed = sum(max(i2 - i1, j2 - j1) for op, i1, i2, j1, j2 in sm.get_opcodes() if op != "equal")
    rel = changed / max(1, len(a["text"]), len(b["text"]))
    nums_a, nums_b = set(NUM.findall(a["text"])), set(NUM.findall(b["text"]))
    urls_a, urls_b = set(URL.findall(a["text"])), set(URL.findall(b["text"]))
    if "text" not in kinds:
        cat = "media-only" if "media" in kinds else "other"
    elif not a["text"]:
        cat = "caption-added"
    elif not b["text"]:
        cat = "text-removed"
    elif rel <= 0.02:
        cat = "typo"
    elif nums_a != nums_b and rel <= 0.25:
        cat = "figures"
    elif urls_a != urls_b and rel <= 0.25:
        cat = "links"
    elif rel <= 0.25:
        cat = "minor-rewording"
    else:
        cat = "substantial"
    return dict(kinds=kinds, rel_change=round(rel, 4), chars_changed=changed, category=cat,
                numbers_changed=nums_a != nums_b, links_changed=urls_a != urls_b)


def build(root):
    obs = defaultdict(list)          # (ch,id) -> observations sorted by capture time
    pages = []                       # (t, ch, seq, epoch, purpose, ids, covered range)
    cache_f = f"{root}/../parse_cache.json"
    cache = json.load(open(cache_f)) if os.path.exists(cache_f) else {}
    for e, html in read_captures(root):
        if e["rec_sha256"] not in cache:
            cache[e["rec_sha256"]] = parse_page(html)
        posts = cache[e["rec_sha256"]]
        if not posts:
            continue
        ch = posts[0]["ch"]
        seen = set()
        for p in posts:
            seen.add(p["id"]); seen.update(p["album"])
            obs[(ch, p["id"])].append(dict(seq=e["seq"], epoch=e["epoch"], t=e["t_resp"], tc=ts(e["t_resp"]),
                                           pub=p["t"], text=p["text"], media=p["media"], fwd=p["fwd"],
                                           edited=p["edited"], chash=p["chash"], album=p["album"]))
        ids = [p["id"] for p in posts]
        pages.append(dict(t=ts(e["t_resp"]), ch=ch, seq=e["seq"], epoch=e["epoch"], purpose=e["purpose"],
                          seen=seen, lo=min(ids), hi=max(ids)))
    json.dump(cache, open(cache_f, "w"), ensure_ascii=False)
    for k in obs:
        obs[k].sort(key=lambda o: o["tc"])
    album_members = defaultdict(set)
    for (ch, i), os_ in obs.items():
        for o in os_:
            album_members[ch].update(o["album"])
    edits, flags, disappear, flaps = [], [], [], []
    for (ch, i), os_ in obs.items():
        for a, b in zip(os_, os_[1:]):
            if a["chash"] != b["chash"] and a["text"] == b["text"] and a["media"] == b["media"]:
                # forward attribution rendered with/without source link: server-side rendering variance
                flaps.append(dict(ch=ch, id=i, fwd_before=a["fwd"], fwd_after=b["fwd"]))
                continue
            if a["chash"] != b["chash"]:
                d = classify_edit(a, b)
                edits.append(dict(ch=ch, id=i, pub=a["pub"], t_before=a["t"], t_after=b["t"], seq_before=a["seq"],
                                  seq_after=b["seq"], flag_before=a["edited"], flag_after=b["edited"],
                                  before=a["text"], after=b["text"], **d))
            if not a["edited"] and b["edited"]:
                flags.append(dict(ch=ch, id=i, pub=a["pub"], t_before=a["t"], t_after=b["t"],
                                  content_changed=(a["text"], a["media"]) != (b["text"], b["media"])))
    by_ch = defaultdict(list)
    for pg in pages:
        by_ch[pg["ch"]].append(pg)
    for ch, pgs in by_ch.items():
        pgs.sort(key=lambda p: p["t"])
        for (c, i), os_ in obs.items():
            if c != ch:
                continue
            last = os_[-1]
            later = [p for p in pgs if p["t"] > last["tc"] and p["lo"] < i < p["hi"] and i not in p["seen"]]
            if later and i not in album_members[ch]:
                disappear.append(dict(ch=ch, id=i, pub=last["pub"], t_last_seen=last["t"], seq_last_seen=last["seq"],
                                      t_first_missing=datetime.fromtimestamp(later[0]["t"]).astimezone().isoformat(),
                                      seq_first_missing=later[0]["seq"], text=last["text"], edited=last["edited"],
                                      n_obs=len(os_)))
    return obs, pages, edits, flags, disappear, flaps


if __name__ == "__main__":
    root, out = sys.argv[1], sys.argv[2]
    obs, pages, edits, flags, dis, flaps = build(root)
    allpost = {k: dict(pub=v[0]["pub"], n_obs=len(v), first=v[0]["t"], last=v[-1]["t"], edited_first=v[0]["edited"],
                       edited_last=v[-1]["edited"], media=bool(v[-1]["media"]), text_len=len(v[-1]["text"]),
                       versions=len({o["chash"] for o in v}), fwd=bool(v[-1]["fwd"])) for k, v in obs.items()}
    json.dump(dict(posts={f"{c}/{i}": v for (c, i), v in allpost.items()}, edits=edits, flags=flags, disappear=dis, flaps=flaps,
                   pages=[{k: v for k, v in p.items() if k != "seen"} | {"n_seen": len(p["seen"])} for p in pages]),
              open(out, "w"), ensure_ascii=False)
    print("posts", len(obs), "pages", len(pages), "edits", len(edits), "flag flips", len(flags), "disappear", len(dis), "render flaps", len(flaps))
