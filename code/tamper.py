"""Tamper-evidence experiment: apply evidence-tampering operations under three adversary levels
and check which integrity scheme detects them.

Schemes:  S1 file manifest (SHA-256 per file) | S2 WARC block/payload digests | S3 hash-chained ledger
          S4 ledger + Merkle seals + RFC 3161 tokens | S5 = S4 + external witness of seal digests
          S6 signed WACZ package (one collector signature + RFC 3161 token over the package manifest)
Adversary: A1 naive (edits bytes, recomputes nothing) | A2 format-aware (recomputes WARC digests and
           the manifest) | A3 full (also re-chains the ledger and recomputes Merkle seals; keeps or
           re-requests TSA tokens; holds the collector's signing key)
A3+fresh: obtains new tokens from both TSAs and writes the current time into every rewritten seal, while
          keeping the original capture times (the forger wants the evidence to keep its original date)
Usage: python3 tamper.py ARCH_SMALL witness.jsonl out.json [trials]
"""
import base64, copy, gzip, hashlib, io, json, os, random, re, shutil, sys, tempfile, zlib
from warcio.archiveiterator import ArchiveIterator
from warcio.warcwriter import WARCWriter
from warcio.statusandheaders import StatusAndHeaders

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from provcap import canon, entry_hash, merkle_root, sha256, Acquirer
from verify import verify
import wacz_sign
from datetime import datetime, timezone

SRC, WIT, OUT = sys.argv[1:4]
N = int(sys.argv[4]) if len(sys.argv) > 4 else 30
WITNESS = {json.loads(l)["seal_sha256"] for l in open(WIT)}
TSA_CACHE = {}
WKEY = wacz_sign.load_key(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "wacz_key.pem"))
WPUB = wacz_sign.pub_der(WKEY)


def manifest(root):
    m = {}
    for d, _, fs in os.walk(root):
        for f in fs:
            p = os.path.join(d, f); r = os.path.relpath(p, root)
            if r != "manifest.json":
                m[r] = sha256(open(p, "rb").read())
    return m


def check_manifest(root):
    m = json.load(open(f"{root}/manifest.json"))
    return m == manifest(root)


def check_warc_digests(root):
    for f in os.listdir(f"{root}/warc"):
        try:
            for r in ArchiveIterator(open(f"{root}/warc/{f}", "rb"), check_digests=True):
                r.content_stream().read()
                if r.digest_checker.passed is False:
                    return False
        except Exception:
            return False
    return True


# ---------- archive model ----------
def load(root):
    L = [json.loads(l) for l in open(f"{root}/ledger.jsonl")]
    files = {}
    for e in L:
        if e["kind"] == "capture":
            files.setdefault(e["warc"], open(f"{root}/{e['warc']}", "rb").read())
    units = {}  # warc path -> list of [seq or None, blob]
    for e in L:
        if e["kind"] == "capture":
            units.setdefault(e["warc"], []).append([e["seq"], files[e["warc"]][e["off"]:e["off"] + e["len"]]])
    return L, units


def parse_unit(blob):
    recs = []
    for r in ArchiveIterator(io.BytesIO(blob)):
        recs.append(dict(type=r.rec_type, uri=r.rec_headers["WARC-Target-URI"],
                         wh=[(k, v) for k, v in r.rec_headers.headers if k not in ("WARC-Payload-Digest", "WARC-Block-Digest", "Content-Length", "WARC-Type", "WARC-Target-URI", "WARC-Warcinfo-ID")],
                         old_dig={k: v for k, v in r.rec_headers.headers if k in ("WARC-Payload-Digest", "WARC-Block-Digest")},
                         http=(r.http_headers.statusline, r.http_headers.headers, r.http_headers.protocol),
                         body=r.content_stream().read()))
    return recs


def build_unit(recs, stale=False):
    """Serialise records; stale=True keeps the original digest headers (naive adversary)."""
    out = b""
    for x in recs:
        buf = io.BytesIO(); w = WARCWriter(buf, gzip=False)
        sl, hh, proto = x["http"]
        hh = [(k, str(len(x["body"]))) if k.lower() == "content-length" else (k, v) for k, v in hh]
        if x["type"] == "request":
            http = StatusAndHeaders(f"{proto} {sl}", hh, is_http_request=True)
            rec = w.create_warc_record(x["uri"], "request", http_headers=http, warc_headers_dict=dict(x["wh"]))
        else:
            http = StatusAndHeaders(sl, hh, protocol=proto)
            if not stale:
                x["wh"] = [(k, sha256(x["body"])) if k == "X-Payload-SHA256" else (k, v) for k, v in x["wh"]]
            rec = w.create_warc_record(x["uri"], "response", payload=io.BytesIO(x["body"]), http_headers=http,
                                       warc_headers_dict=dict(x["wh"]))
        w.write_record(rec)
        raw = buf.getvalue()
        if stale:
            for k, v in x["old_dig"].items():
                raw = re.sub(rf"{k}: [^\r]*".encode(), f"{k}: {v}".encode(), raw, count=1)
        co = zlib.compressobj(6, zlib.DEFLATED, 31)
        out += co.compress(raw) + co.flush()
    return out


def write_archive(root, L, units, tsr_files):
    os.makedirs(f"{root}/warc", exist_ok=True); os.makedirs(f"{root}/seals", exist_ok=True)
    for path, us in units.items():
        open(f"{root}/{path}", "wb").write(b"".join(b for _, b in us))
    with open(f"{root}/ledger.jsonl", "w") as f:
        for e in L:
            f.write(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n")
    for rel, data in tsr_files.items():
        open(f"{root}/{rel}", "wb").write(data)


def rechain(L, units, root_src, token_fn=None):
    """Full adversary: fix offsets/digests, renumber, re-chain, recompute Merkle seals; optionally
    obtain fresh RFC 3161 tokens for every rewritten seal (token_fn)."""
    blob_of = {}
    for path, us in units.items():
        off = 0
        for seq, b in us:
            if seq is not None:
                blob_of[seq] = (path, off, b)
            off += len(b)
    seals_out, tsr_out = {}, {}
    newL, prev = [], "0" * 64
    for e in L:
        e = dict(e)
        if e["kind"] == "capture" and e["seq"] in blob_of:
            path, off, b = blob_of[e["seq"]]
            recs = parse_unit(b)
            resp = [r for r in recs if r["type"] == "response"][0]
            d = zlib.decompressobj(31); d.decompress(b); reqlen = len(b) - len(d.unused_data)
            e.update(warc=path, off=off, len=len(b), resp_off=off + reqlen, rec_sha256=sha256(b),
                     payload_sha256=sha256(resp["body"]), t_resp=dict(resp["wh"])["WARC-Date"])
        e["seq"] = len(newL); e["prev"] = prev
        if e["kind"] == "seal":
            leaves = [x["h"] for x in newL if x.get("epoch") == e["epoch"] and x["kind"] != "seal"]
            msg = json.loads(open(f"{root_src}/{e['seal']}").read())
            msg.update(merkle_root=merkle_root(leaves), ledger_head=newL[-1]["h"], n_leaves=len(leaves), ledger_seq=len(newL))
            changed = canon(msg) != open(f"{root_src}/{e['seal']}", "rb").read()
            if token_fn and changed:  # fresh tokens can only carry the present time
                now = datetime.now(timezone.utc).isoformat(timespec="milliseconds")
                msg["t"] = now; e["t"] = now
            seals_out[e["seal"]] = canon(msg)
            e.update(merkle_root=msg["merkle_root"], n_leaves=len(leaves), seal_sha256=sha256(canon(msg)))
            if token_fn and changed:
                e["tsr"] = []
                for tsa in ("freetsa", "digicert"):
                    tok, gt = token_fn(canon(msg), tsa)
                    rel = e["seal"] + f".{tsa}.tsr"; tsr_out[rel] = tok
                    e["tsr"].append(dict(tsa=tsa, tsr=rel, sha256=sha256(tok), gen_time=gt))
        e.pop("h", None); e["h"] = entry_hash(e)
        newL.append(e); prev = e["h"]
    return newL, seals_out, tsr_out


def fresh_token(seal_bytes, name, workdir):
    import subprocess, requests
    p = f"{workdir}/s.json"; open(p, "wb").write(seal_bytes)
    subprocess.run(["openssl", "ts", "-query", "-data", p, "-sha256", "-cert", "-out", p + ".tsq"], check=True, capture_output=True)
    r = requests.post("https://freetsa.org/tsr", data=open(p + ".tsq", "rb").read(), headers={"Content-Type": "application/timestamp-query"}, timeout=30)
    txt = subprocess.run(["openssl", "ts", "-reply", "-in", "/dev/stdin", "-text"], input=r.content, capture_output=True).stdout.decode()
    gt = [l.split(":", 1)[1].strip() for l in txt.splitlines() if l.startswith("Time stamp:")]
    return r.content, gt[0] if gt else None


# ---------- tampering operations ----------
def back2(ts):
    """Shift an ISO timestamp two days into the past, keeping its format."""
    from datetime import timedelta
    d = datetime.fromisoformat(ts.replace("Z", "+00:00")) - timedelta(days=2)
    return ts[:0] + d.isoformat(timespec="milliseconds" if "." in ts else "seconds").replace("+00:00", "Z" if ts.endswith("Z") else "+00:00")


def alter_payload(body, rng):
    s = body.decode("utf-8", "replace")
    m = list(re.finditer(r'(tgme_widget_message_text[^>]*>)([^<]{20,})', s))
    if not m:
        return None
    x = rng.choice(m)
    txt = x.group(2)
    nums = list(re.finditer(r"\d+", txt))
    if nums:
        n = rng.choice(nums); new = txt[:n.start()] + str(int(n.group()) + rng.randint(1, 9)) + txt[n.end():]
    else:
        k = rng.randrange(len(txt)); new = txt[:k] + "не " + txt[k:]
    return (s[:x.start(2)] + new + s[x.end(2):]).encode()


def op_apply(op, L, units, rng, adv):
    op_apply.target = None
    caps = [(path, i) for path, us in units.items() for i, (seq, _) in enumerate(us)]
    stale = adv == "A1"
    if op == "T1_modify":
        while True:
            path, i = rng.choice(caps)
            recs = parse_unit(units[path][i][1]); resp = [r for r in recs if r["type"] == "response"][0]
            nb = alter_payload(resp["body"], rng)
            if nb:
                break
        resp["body"] = nb
        units[path][i][1] = build_unit(recs, stale)
        op_apply.target = units[path][i][0]
    elif op == "T2_delete":
        path, i = rng.choice(caps)
        seq = units[path][i][0]; del units[path][i]
        op_apply.target = seq
        if adv == "A3":
            L[:] = [e for e in L if e["seq"] != seq]
    elif op == "T3_insert":
        while True:  # fabricate a capture: a copy of a real record with altered post text
            path, i = rng.choice(caps)
            recs = parse_unit(units[path][i][1])
            resp = [r for r in recs if r["type"] == "response"][0]
            nb = alter_payload(resp["body"], rng)
            if nb:
                break
        resp["body"] = nb
        for r in recs:
            r["wh"] = [(k, ("<urn:uuid:%032x>" % rng.getrandbits(128)) if k == "WARC-Record-ID" else v) for k, v in r["wh"]]
        newseq = -1 - rng.randrange(10 ** 6)
        units[path].insert(i + 1, [newseq if adv == "A3" else None, build_unit(recs, stale)])
        op_apply.target = units[path][i + 2][0] if i + 2 < len(units[path]) else "orphan"
        if adv == "A3":
            orig = [e for e in L if e["seq"] == units[path][i][0]][0]
            j = L.index(orig)
            L.insert(j + 1, dict(orig, seq=newseq))
    elif op == "T4_backdate":
        path, i = rng.choice(caps)
        recs = parse_unit(units[path][i][1])
        for r in recs:
            r["wh"] = [(k, back2(v)) if k == "WARC-Date" else (k, v) for k, v in r["wh"]]
        units[path][i][1] = build_unit(recs, stale)
        op_apply.target = units[path][i][0]
    elif op == "T5_reorder":
        path = rng.choice([p for p in units if len(units[p]) >= 2])
        i, j = rng.sample(range(len(units[path])), 2)
        op_apply.target = min(units[path][i][0], units[path][j][0])
        units[path][i], units[path][j] = units[path][j], units[path][i]
        if adv == "A3":
            si, sj = units[path][j][0], units[path][i][0]
            ii = next(k for k, e in enumerate(L) if e["seq"] == si); jj = next(k for k, e in enumerate(L) if e["seq"] == sj)
            L[ii], L[jj] = L[jj], L[ii]
    elif op == "T6_truncate":
        last_open = max(k for k, e in enumerate(L) if e["kind"] == "epoch_open")
        ep = L[last_open]["epoch"]
        L[:] = L[:last_open]
        units.pop(f"warc/{ep}.warc.gz", None)
        return ep
    return None


OPS = ["T1_modify", "T2_delete", "T3_insert", "T4_backdate", "T5_reorder", "T6_truncate"]
ADVS = ["A1", "A2", "A3"]


def trial(op, adv, seed, fresh=False):
    rng = random.Random(seed)
    wd = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
    dst = f"{wd}/arch"
    shutil.copytree(SRC, dst)
    L, units = load(dst)
    L0 = copy.deepcopy(L)
    dropped = op_apply(op, L, units, rng, adv)
    target = op_apply.target
    tsr = {}
    if adv == "A3":
        L, seals, tsr = rechain(L, units, dst, token_fn=(lambda m, tsa: wacz_sign.tsa_token(m, tsa)) if fresh else None)
        for rel, b in seals.items():
            open(f"{dst}/{rel}", "wb").write(b)
    if adv in ("A1", "A2"):
        # ledger untouched except what the op itself removed (truncation)
        if op != "T6_truncate":
            L = L0
    write_archive(dst, L, units, tsr)
    if op == "T6_truncate" and dropped:
        for f in os.listdir(f"{dst}/seals"):
            if f.startswith(dropped):
                os.remove(f"{dst}/seals/{f}")
        if os.path.exists(f"{dst}/warc/{dropped}.warc.gz"):
            os.remove(f"{dst}/warc/{dropped}.warc.gz")
    sd0 = json.load(open(f"{dst}/wacz/datapackage-digest.json"))["signedData"]
    if adv == "A2":
        wacz_sign.recompute_unsigned(dst)
    elif adv == "A3" and fresh:
        wacz_sign.sign(dst, WKEY, token=lambda sig: wacz_sign.tsa_token(sig, "freetsa"))
    elif adv == "A3":
        wacz_sign.sign(dst, WKEY, created=sd0["created"], keep_token_from=sd0)
    if adv in ("A2", "A3"):
        json.dump(manifest(dst), open(f"{dst}/manifest.json", "w"))
    r = verify(dst, tsa=True, witness=WITNESS, tsa_cache=TSA_CACHE)
    s3 = not (r["bad_chain"] or r["bad_records"] or r["bad_meta"] or r["orphan_bytes"])
    s4 = s3 and not (r["bad_seals"] or r["bad_tsa"] or r["bad_time"])
    res = dict(op=op, adv=adv, seed=seed, fresh_tsa=fresh,
               S1=not check_manifest(dst), S2=not check_warc_digests(dst), S3=not s3, S4=not s4,
               S5=not (s4 and not r["witness_missing"]), S6=not wacz_sign.check(dst, WPUB),
               localized=sorted(set(r["bad_records"] + r["bad_meta"]))[:5], target=target,
               orphans=len(r["orphan_bytes"]), n_bad_seals=len(r["bad_seals"]),
               n_bad_tsa=len(r["bad_tsa"]), n_bad_time=len(r["bad_time"]))
    shutil.rmtree(wd)
    return res


if __name__ == "__main__":
    if not wacz_sign.check(SRC, WPUB):  # sign the untouched package once, with a real token
        wacz_sign.sign(SRC, WKEY, token=lambda sig: wacz_sign.tsa_token(sig, "freetsa"))
    json.dump(manifest(SRC), open(f"{SRC}/manifest.json", "w"))
    # sanity: untouched archive passes every scheme (false-positive check)
    base = dict(S1=not check_manifest(SRC), S2=not check_warc_digests(SRC), S6=not wacz_sign.check(SRC, WPUB))
    r0 = verify(SRC, witness=WITNESS, tsa_cache=TSA_CACHE)
    base.update(verify_ok=r0["ok"])
    results = []
    for op in OPS:
        for adv in ADVS:
            for k in range(N):
                results.append(trial(op, adv, 1000 * OPS.index(op) + 100 * ADVS.index(adv) + k))
            agg = {s: sum(x[s] for x in results if x["op"] == op and x["adv"] == adv) for s in ("S1", "S2", "S3", "S4", "S5", "S6")}
            print(op, adv, agg, flush=True)
    for op in (OPS if int(os.environ.get("FRESH", 3)) > 0 else []):  # A3 with fresh RFC 3161 tokens (real TSA calls)
        for k in range(int(os.environ.get("FRESH", 3))):
            results.append(trial(op, "A3", 90000 + 10 * OPS.index(op) + k, fresh=True))
        print(op, "A3+fresh", {s: sum(x[s] for x in results if x["op"] == op and x.get("fresh_tsa")) for s in ("S1", "S2", "S3", "S4", "S5", "S6")}, flush=True)
    json.dump(dict(baseline=base, trials=results), open(OUT, "w"), indent=0)
    print("baseline (untampered):", base)
