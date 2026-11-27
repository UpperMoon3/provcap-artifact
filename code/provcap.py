"""ProvCap: provenance-preserving acquisition of public social-media pages (Telegram web previews).

Every HTTP exchange is written as a WARC request/response pair (ISO 28500). Each record is
hashed (SHA-256 over the stored gzip member) and appended to a hash-chained ledger. At the end of
every acquisition epoch the ledger head and an RFC 6962-style Merkle root over the epoch's
entries are sealed with RFC 3161 time-stamp tokens from two independent TSAs.

Usage:
  python3 provcap.py monitor --root ARCH --channels ch.txt --interval 600 --since 2026-10-26
  (create ARCH/STOP to trigger a final deep crawl and exit)
"""
import argparse, base64, hashlib, io, json, os, random, socket, ssl, subprocess, sys, threading, time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone

import requests
from warcio.warcwriter import WARCWriter
from warcio.statusandheaders import StatusAndHeaders

TOOL = "provcap/0.3"
UA = "Mozilla/5.0 (academic research; public channel previews)"
TSAS = [("freetsa", "https://freetsa.org/tsr"), ("digicert", "http://timestamp.digicert.com")]


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def canon(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def entry_hash(e):
    return sha256(canon({k: v for k, v in e.items() if k != "h"}))


# ---------- Merkle tree (RFC 6962 / RFC 9162 hashing) ----------
def _leaf(x):
    return hashlib.sha256(b"\x00" + bytes.fromhex(x)).digest()


def _node(a, b):
    return hashlib.sha256(b"\x01" + a + b).digest()


def merkle_root(leaves_hex):
    if not leaves_hex:
        return sha256(b"")
    level = [_leaf(x) for x in leaves_hex]
    return _mth(level).hex()


def _mth(nodes):
    if len(nodes) == 1:
        return nodes[0]
    k = 1
    while k * 2 < len(nodes):
        k *= 2
    return _node(_mth(nodes[:k]), _mth(nodes[k:]))


def inclusion_proof(leaves_hex, i):
    """Audit path for leaf i (RFC 6962 sec. 2.1.1)."""
    nodes = [_leaf(x) for x in leaves_hex]

    def path(m, nodes):
        if len(nodes) == 1:
            return []
        k = 1
        while k * 2 < len(nodes):
            k *= 2
        if m < k:
            return path(m, nodes[:k]) + [("R", _mth(nodes[k:]).hex())]
        return path(m - k, nodes[k:]) + [("L", _mth(nodes[:k]).hex())]

    return path(i, nodes)


def verify_inclusion(leaf_hex, proof, root_hex):
    h = _leaf(leaf_hex)
    for side, sib in proof:
        h = _node(h, bytes.fromhex(sib)) if side == "R" else _node(bytes.fromhex(sib), h)
    return h.hex() == root_hex


# ---------- ledger ----------
class Ledger:
    def __init__(self, path):
        self.path, self.lock = path, threading.Lock()
        self.seq, self.head = 0, "0" * 64
        if os.path.exists(path):
            for line in open(path):
                e = json.loads(line)
                self.seq, self.head = e["seq"] + 1, e["h"]
        self.f = open(path, "a")

    def append(self, e):
        with self.lock:
            e = dict(e, seq=self.seq, prev=self.head)
            e["h"] = entry_hash(e)
            self.f.write(json.dumps(e, ensure_ascii=False, sort_keys=True) + "\n")
            self.f.flush(); os.fsync(self.f.fileno())
            self.seq += 1; self.head = e["h"]
            return e


# ---------- acquirer ----------
class Acquirer:
    def __init__(self, root):
        self.root = root
        os.makedirs(f"{root}/warc", exist_ok=True); os.makedirs(f"{root}/seals", exist_ok=True)
        self.ledger = Ledger(f"{root}/ledger.jsonl")
        self.wlock = threading.Lock()
        self.s = requests.Session(); self.s.headers["User-Agent"] = UA
        self.epoch, self.epoch_leaves, self.warc_path = None, [], None
        # collector identifier written into every epoch; use a pseudonym for anonymised releases
        self.collector = os.environ.get("PROVCAP_COLLECTOR") or socket.gethostname()

    def begin(self, label):
        self.epoch = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{label}"
        self.warc_path = f"warc/{self.epoch}.warc.gz"
        self.epoch_leaves = []
        att = self.attest_endpoint("t.me")
        e = self.ledger.append(dict(kind="epoch_open", epoch=self.epoch, t=now_iso(), tool=TOOL,
                                    host=self.collector, endpoint=att))
        self.epoch_leaves.append(e["h"])

    @staticmethod
    def attest_endpoint(host):
        try:
            ips = sorted({a[4][0] for a in socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)})
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    der = ss.getpeercert(binary_form=True); peer = ss.getpeername()[0]
                    subj = dict(x[0] for x in ss.getpeercert()["subject"])
            return dict(host=host, dns=ips, peer=peer, cert_sha256=sha256(der), cert_cn=subj.get("commonName"))
        except Exception as ex:
            return dict(host=host, error=str(ex))

    def fetch(self, url, purpose, tries=4):
        err = "429"
        for k in range(tries):
            t_req = now_iso()
            try:
                r = self.s.get(url, timeout=25)
            except Exception as ex:
                time.sleep(4 * (k + 1)); err = str(ex); continue
            t_resp = now_iso()
            if r.status_code == 429:
                time.sleep(30 * (k + 1)); continue
            return self._store(url, purpose, r, t_req, t_resp)
        self.ledger.append(dict(kind="fetch_error", epoch=self.epoch, url=url, purpose=purpose, t=now_iso(), err=err))
        return None, None

    def _store(self, url, purpose, r, t_req, t_resp):
        buf = io.BytesIO(); w = WARCWriter(buf, gzip=True)
        body = r.content
        req_h = StatusAndHeaders(f"GET {r.request.path_url} HTTP/1.1",
                                 list(r.request.headers.items()) + [("Host", "t.me")], is_http_request=True)
        req = w.create_warc_record(url, "request", http_headers=req_h,
                                   warc_headers_dict={"WARC-Date": t_req})
        hdrs = [(k, v) for k, v in r.headers.items() if k.lower() not in ("content-encoding", "transfer-encoding")]
        hdrs = [(k, str(len(body))) if k.lower() == "content-length" else (k, v) for k, v in hdrs]
        resp_h = StatusAndHeaders(f"{r.status_code} {r.reason}", hdrs, protocol="HTTP/1.1")
        resp = w.create_warc_record(url, "response", payload=io.BytesIO(body), http_headers=resp_h,
                                    warc_headers_dict={"WARC-Date": t_resp, "WARC-Concurrent-To": req.rec_headers["WARC-Record-ID"],
                                                       "X-Payload-SHA256": sha256(body), "X-Tool": TOOL, "X-Purpose": purpose})
        w.write_record(req); start_resp = buf.tell(); w.write_record(resp)
        blob = buf.getvalue()
        with self.wlock:
            path = f"{self.root}/{self.warc_path}"
            off = os.path.getsize(path) if os.path.exists(path) else 0
            with open(path, "ab") as f:
                f.write(blob); f.flush(); os.fsync(f.fileno())
        e = self.ledger.append(dict(kind="capture", epoch=self.epoch, url=url, purpose=purpose, warc=self.warc_path,
                                    off=off, len=len(blob), resp_off=off + start_resp, rec_sha256=sha256(blob),
                                    payload_sha256=sha256(body), status=r.status_code, t_req=t_req, t_resp=t_resp,
                                    server_date=r.headers.get("date"),
                                    warc_id=resp.rec_headers["WARC-Record-ID"]))
        with self.wlock:
            self.epoch_leaves.append(e["h"])
        return body.decode("utf-8", "replace"), e

    def epoch_entries(self, epoch):
        """Leaves of an epoch = hashes of its non-seal ledger entries, in ledger (seq) order."""
        with self.ledger.lock:
            return [e["h"] for e in map(json.loads, open(self.ledger.path)) if e.get("epoch") == epoch and e["kind"] != "seal"]

    def seal(self, use_tsa=True):
        self.epoch_leaves = self.epoch_entries(self.epoch)
        root = merkle_root(self.epoch_leaves)
        msg = dict(epoch=self.epoch, n_leaves=len(self.epoch_leaves), merkle_root=root,
                   ledger_head=self.ledger.head, ledger_seq=self.ledger.seq, t=now_iso(), tool=TOOL)
        mpath = f"seals/{self.epoch}.json"
        open(f"{self.root}/{mpath}", "wb").write(canon(msg))
        tokens = []
        if use_tsa:
            for name, url in TSAS:
                tokens.append(self.timestamp(f"{self.root}/{mpath}", name, url))
        return self.ledger.append(dict(kind="seal", epoch=self.epoch, seal=mpath, seal_sha256=sha256(canon(msg)),
                                       merkle_root=root, n_leaves=len(self.epoch_leaves), tsr=tokens, t=now_iso()))

    def timestamp(self, path, name, url):
        q, tsr = path + f".{name}.tsq", path + f".{name}.tsr"
        try:
            subprocess.run(["openssl", "ts", "-query", "-data", path, "-sha256", "-cert", "-out", q],
                           check=True, capture_output=True)
            r = requests.post(url, data=open(q, "rb").read(), headers={"Content-Type": "application/timestamp-query"}, timeout=30)
            open(tsr, "wb").write(r.content)
            txt = subprocess.run(["openssl", "ts", "-reply", "-in", tsr, "-text"], capture_output=True, text=True).stdout
            gt = [l.split(":", 1)[1].strip() for l in txt.splitlines() if l.startswith("Time stamp:")]
            return dict(tsa=name, tsr=os.path.relpath(tsr, self.root), sha256=sha256(r.content), gen_time=gt[0] if gt else None)
        except Exception as ex:
            return dict(tsa=name, error=str(ex))


# ---------- Telegram-specific acquisition ----------
def crawl_channel(acq, ch, since_ts, deep, max_pages=60):
    from tgparse import parse_page
    before, n = None, 0
    for p in range(max_pages if deep else 1):
        url = f"https://t.me/s/{ch}" + (f"?before={before}" if before else "")
        html, e = acq.fetch(url, "deep" if deep else "head")
        time.sleep(0.7 + random.random() * 0.6)
        if not html:
            break
        posts = parse_page(html, ch)
        if not posts:
            break
        n += len(posts)
        oldest = min(posts, key=lambda x: x["id"])
        if oldest["ts"] < since_ts or oldest["id"] <= 1:
            break
        before = oldest["id"]
    return n


def monitor(a):
    acq = Acquirer(a.root)
    if a.collector:
        acq.collector = a.collector
    chans = [l.strip() for l in open(a.channels) if l.strip()]
    since = datetime.fromisoformat(a.since + "T00:00:00+00:00").timestamp()
    pool = ThreadPoolExecutor(max_workers=a.workers)
    cyc = 0
    while True:
        stop = os.path.exists(f"{a.root}/STOP")
        deep = cyc == 0 or stop
        t0 = time.time()
        acq.begin("deep" if deep else "head")
        counts = list(pool.map(lambda c: crawl_channel(acq, c, since, deep), chans))
        s = acq.seal()
        if a.witness:  # external append-only witness (e.g. supervisor / case-management system)
            with open(a.witness, "a") as wf:
                wf.write(json.dumps(dict(epoch=s["epoch"], seal_sha256=s["seal_sha256"], t=now_iso())) + "\n")
        print(f"{now_iso()} cycle={cyc} deep={deep} posts={sum(counts)} leaves={s['n_leaves']} "
              f"tsa={[t.get('gen_time') or t.get('error') for t in s['tsr']]} took={time.time()-t0:.0f}s", flush=True)
        if stop or (a.cycles and cyc + 1 >= a.cycles):
            break
        cyc += 1
        time.sleep(max(0, a.interval - (time.time() - t0)))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    sp = ap.add_subparsers(dest="cmd")
    m = sp.add_parser("monitor")
    m.add_argument("--root"); m.add_argument("--channels"); m.add_argument("--interval", type=int, default=600)
    m.add_argument("--since", default="2026-10-26"); m.add_argument("--cycles", type=int, default=0)
    m.add_argument("--workers", type=int, default=8); m.add_argument("--witness", default=None)
    m.add_argument("--collector", default=None, help="collector id recorded in the ledger (default: hostname)")
    a = ap.parse_args()
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    if a.cmd == "monitor":
        monitor(a)
