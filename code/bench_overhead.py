"""Micro-benchmark: local cost of provenance (WARC serialisation + hashing + fsync'd ledger append) per capture,
and verifier throughput. Usage: python3 bench_overhead.py ARCH out.json"""
import io, json, os, sys, tempfile, time, statistics as st
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from provcap import Acquirer, merkle_root, inclusion_proof, verify_inclusion
from history import read_captures
from verify import verify
root, out = sys.argv[1:3]
bodies = [h.encode() for _, h in zip(range(500), (h for e, h in read_captures(root)))]
class R:  # minimal stand-in for a requests.Response
    def __init__(s, b): s.content = b; s.status_code = 200; s.reason = "OK"; s.headers = {"content-type": "text/html", "content-length": str(len(b))}
    class request: path_url = "/s/x"; headers = {"User-Agent": "x"}
tmp = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
a = Acquirer(tmp); a.epoch = "bench"; a.warc_path = "warc/bench.warc.gz"
ts = []
for b in bodies:
    t = time.perf_counter(); a._store("https://t.me/s/x", "bench", R(b), "2026-11-16T00:00:00.000+00:00", "2026-11-16T00:00:00.300+00:00"); ts.append(time.perf_counter() - t)
leaves = [json.loads(l)["h"] for l in open(f"{tmp}/ledger.jsonl")]
t = time.perf_counter(); rt = merkle_root(leaves * 20); t_m = time.perf_counter() - t
pr = inclusion_proof(leaves, 123); ok = verify_inclusion(leaves[123], pr, merkle_root(leaves))
t = time.perf_counter(); r = verify(root, tsa=True); t_v = time.perf_counter() - t
res = dict(n=len(bodies), store_ms_median=1000 * st.median(ts), store_ms_p95=1000 * sorted(ts)[int(.95 * len(ts))],
           merkle_10k_leaves_ms=1000 * t_m, proof_len=len(pr), proof_ok=ok, verify_s=t_v, verify_captures=r["captures"],
           verify_ok=r["ok"], verify_seals=r["seals"])
json.dump(res, open(out, "w"), indent=1); print(res)
