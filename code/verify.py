"""Independent verifier for a ProvCap archive.

Checks (i) the hash chain of the ledger, (ii) every WARC record against its ledger digest and
metadata, (iii) every epoch seal (Merkle root, ledger head) and (iv) the RFC 3161 tokens on each
seal, including the gap between the claimed seal time and the TSA generation time, and (v) time binding:
captures follow the previous seal and each seal follows the last response of its epoch within 60 s.
Usage: python3 verify.py ARCH [--no-tsa] [--witness witness.jsonl]
"""
import hashlib, io, json, os, subprocess, sys
from datetime import datetime, timezone
from warcio.archiveiterator import ArchiveIterator

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from provcap import canon, entry_hash, merkle_root, sha256

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CA = {"freetsa": ["-CAfile", f"{HERE}/tsa/cacert.pem", "-untrusted", f"{HERE}/tsa/tsa.crt"],
      "digicert": ["-CAfile", next((c for c in (os.environ.get("SSL_CERT_FILE"), "/etc/ssl/cert.pem",
                                                "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt")
                                       if c and os.path.exists(c)), "/etc/ssl/cert.pem")]}
MAX_TSA_SKEW = 60  # seconds between claimed seal time and TSA genTime
MAX_SEAL_DELAY = 60  # seconds between the last response of an epoch and its seal
REQUIRED_TSAS = {"freetsa", "digicert"}  # policy: every seal carries a token from each TSA


def verify(root, tsa=True, witness=None, tsa_cache=None):
    rep = dict(entries=0, captures=0, seals=0, bad_chain=[], bad_records=[], bad_meta=[], bad_seals=[], bad_tsa=[],
               bad_time=[], unsealed=0, witness_missing=[])
    L = [json.loads(l) for l in open(f"{root}/ledger.jsonl")]
    rep["entries"] = len(L)
    prev = "0" * 64
    for i, e in enumerate(L):
        if e.get("seq") != i or e.get("prev") != prev or entry_hash(e) != e.get("h"):
            rep["bad_chain"].append(i)
        prev = e.get("h")
    blobs = {}
    for e in L:
        if e["kind"] != "capture":
            continue
        rep["captures"] += 1
        p = f"{root}/{e['warc']}"
        if p not in blobs:
            blobs[p] = open(p, "rb").read() if os.path.exists(p) else b""
        blob = blobs[p][e["off"]:e["off"] + e["len"]]
        if sha256(blob) != e["rec_sha256"]:
            rep["bad_records"].append(e["seq"]); continue
        ok = False
        try:
            for r in ArchiveIterator(io.BytesIO(blob)):
                if r.rec_type == "response":
                    body = r.content_stream().read()
                    ok = (sha256(body) == e["payload_sha256"] and r.rec_headers["WARC-Date"] == e["t_resp"]
                          and r.rec_headers["WARC-Target-URI"] == e["url"]
                          and r.rec_headers.get("X-Payload-SHA256") == e["payload_sha256"])
        except Exception:
            ok = False
        if not ok:
            rep["bad_meta"].append(e["seq"])
    # coverage: ledger-referenced byte ranges must tile every WARC file exactly (no orphan bytes)
    rep["orphan_bytes"] = []
    ranges = {}
    for e in L:
        if e["kind"] == "capture":
            ranges.setdefault(e["warc"], []).append((e["off"], e["off"] + e["len"]))
    for w in set(ranges) | {f"warc/{f}" for f in os.listdir(f"{root}/warc")}:
        size = os.path.getsize(f"{root}/{w}") if os.path.exists(f"{root}/{w}") else 0
        pos = 0
        for a, b in sorted(ranges.get(w, [])):
            if a != pos:
                break
            pos = b
        if pos != size:
            rep["orphan_bytes"].append(w)
    # time binding: captures follow the previous seal, and each seal follows its epoch within MAX_SEAL_DELAY,
    # so every record's claimed time lies within one epoch (+ delay) of a time-stamped seal
    prev_t, last_resp = None, {}
    for e in L:
        try:
            if e["kind"] == "capture":
                tq, tr = datetime.fromisoformat(e["t_req"]), datetime.fromisoformat(e["t_resp"])
                if tr < tq or (prev_t is not None and tq < prev_t):
                    rep["bad_time"].append(e["seq"])
                last_resp[e["epoch"]] = max(last_resp.get(e["epoch"], tr), tr)
            elif e["kind"] == "seal":
                sp = f"{root}/{e['seal']}"
                ts = datetime.fromisoformat(json.load(open(sp))["t"]) if os.path.exists(sp) else None
                lr = last_resp.get(e["epoch"])
                if ts is None or (lr is not None and not 0 <= (ts - lr).total_seconds() <= MAX_SEAL_DELAY):
                    rep["bad_time"].append(e["seq"])
                prev_t = ts or prev_t
        except Exception:
            rep["bad_time"].append(e.get("seq"))
    last_seal = -1
    for e in L:
        if e["kind"] != "seal":
            continue
        rep["seals"] += 1
        leaves = [x["h"] for x in L[:e["seq"]] if x.get("epoch") == e["epoch"] and x["kind"] != "seal"]
        sp = f"{root}/{e['seal']}"
        msg = json.load(open(sp)) if os.path.exists(sp) else {}
        good = (merkle_root(leaves) == e["merkle_root"] == msg.get("merkle_root")
                and sha256(canon(msg)) == e["seal_sha256"] and msg.get("ledger_head") == L[e["seq"] - 1]["h"]
                and msg.get("n_leaves") == len(leaves))
        if not good:
            rep["bad_seals"].append(e["seq"])
        last_seal = e["seq"]
        if witness is not None and e["seal_sha256"] not in witness:
            rep["witness_missing"].append(e["seq"])
        if tsa:
            have = {t["tsa"] for t in e["tsr"] if "error" not in t}
            for miss in sorted(REQUIRED_TSAS - have):
                rep["bad_tsa"].append((e["seq"], miss + ":missing"))
            for t in e["tsr"]:
                if "error" in t:
                    continue
                tp = f"{root}/{t['tsr']}"
                key = (sha256(open(tp, "rb").read()) if os.path.exists(tp) else None, sha256(open(sp, "rb").read()) if os.path.exists(sp) else None, t["tsa"])
                if tsa_cache is not None and key in tsa_cache:
                    vok = tsa_cache[key]
                else:
                    r = subprocess.run(["openssl", "ts", "-verify", "-data", sp, "-in", tp] + CA[t["tsa"]],
                                       capture_output=True, text=True) if os.path.exists(tp) and os.path.exists(sp) else None
                    vok = bool(r) and "Verification: OK" in (r.stdout + r.stderr)
                    if tsa_cache is not None:
                        tsa_cache[key] = vok
                skew_ok = True
                try:
                    gt = datetime.strptime(t["gen_time"].replace(" GMT", ""), "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
                    skew_ok = abs((gt - datetime.fromisoformat(msg.get("t"))).total_seconds()) <= MAX_TSA_SKEW
                except Exception:
                    skew_ok = False
                if not (vok and skew_ok and key[0] == t["sha256"]):
                    rep["bad_tsa"].append((e["seq"], t["tsa"]))
    if witness is not None:
        present = {e["seal_sha256"] for e in L if e["kind"] == "seal"}
        rep["witness_missing"] += [w for w in witness if w not in present]
    rep["unsealed"] = len(L) - 1 - last_seal
    rep["ok"] = not any(rep[k] for k in ("bad_chain", "bad_records", "bad_meta", "orphan_bytes", "bad_seals", "bad_tsa", "bad_time", "witness_missing"))
    return rep


if __name__ == "__main__":
    root = sys.argv[1]
    w = None
    if "--witness" in sys.argv:
        w = {json.loads(l)["seal_sha256"] for l in open(sys.argv[sys.argv.index("--witness") + 1])}
    r = verify(root, tsa="--no-tsa" not in sys.argv, witness=w)
    print(json.dumps({k: (v if not isinstance(v, list) else (len(v), v[:5])) for k, v in r.items()}, indent=1))
