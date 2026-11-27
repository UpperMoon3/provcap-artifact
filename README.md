# ProvCap — review artifact

Code and a sealed test archive for the paper *Forensically Sound OSINT Acquisition: Provenance Tracking and
Detection of Edited and Deleted Social Media Evidence*. This copy is anonymised for review.

ProvCap acquires public web pages (here: public Telegram channel previews at `t.me/s/<channel>`), stores every
HTTP exchange in WARC, links the records in a hash-chained ledger, and seals each acquisition epoch with an
RFC 6962 Merkle root that is time-stamped by two RFC 3161 authorities (FreeTSA, DigiCert) and optionally copied
to an external witness log. An independent verifier checks the archive without trusting the collector.

## Contents

| Path | What it is |
|---|---|
| `code/provcap.py` | acquisition, ledger, Merkle seals, RFC 3161 time-stamping, monitoring loop |
| `code/verify.py` | independent verifier (checks i–vii of Table 1 in the paper) |
| `code/tgparse.py`, `code/history.py` | deterministic parser and derivation of post versions, edits, disappearances |
| `code/probe.py` | single-post probes that confirm deletions (acquired and sealed like any capture) |
| `code/tamper.py`, `code/wacz_sign.py` | verification test (T1–T6 × A1–A3 × S1–S6), incl. the signed-WACZ baseline |
| `code/wayback2.py`, `code/bench_overhead.py` | Internet Archive coverage queries; cost benchmark |
| `archives/test/` | sealed test archive: 10 channels, 5 epochs, 59 captures, 10 RFC 3161 tokens |
| `archives/test_witness.jsonl` | witness log of the test archive's seal digests |
| `archives/tamper_results.json` | per-instance results of the verification test reported in the paper |
| `tsa/` | FreeTSA CA and TSA certificates (DigiCert is verified against the system CA bundle) |
| `channels/` | channel lists used in the field study and in the test archive |

The ledger records a pseudonymous collector id (`collector-A`). The 156 MB field archive is not included
here and will be deposited on acceptance.

## Requirements

Python ≥ 3.9 and OpenSSL ≥ 1.1 on the `PATH` (`openssl ts` is used to verify the tokens).

```bash
pip install -r requirements.txt
```

## 1. Verify the sealed archive (offline)

```bash
python3 code/verify.py archives/test --witness archives/test_witness.jsonl
```

Expected: `"ok": true`, 5 seals, 59 captures, every `bad_*` list empty. The check runs offline: the
tokens are verified against the certificates in `tsa/` and the system CA bundle (set `SSL_CERT_FILE` if
yours is in a non-standard place).

To see the verifier fail, change one byte of a WARC file or one line of `ledger.jsonl` in a copy of the
archive and run it again; the report names the failing record or epoch.

## 2. Re-run the verification test

```bash
FRESH=3 python3 code/tamper.py archives/test archives/test_witness.jsonl out.json 50
```

Each instance copies the archive, applies one operation (T1 modify, T2 delete, T3 insert, T4 backdate,
T5 reorder, T6 truncate) as adversary A1, A2 or A3, and judges the copy with six schemes. `FRESH=3` adds
three A3 instances per operation that obtain new tokens from both TSAs; these, and the first run of the
signed-WACZ baseline S6, send SHA-256 imprints (not data) to FreeTSA and DigiCert. The S6 signing key is
not shipped: on first run a new ECDSA key is created in `data/wacz_key.pem` and the package in
`archives/test/wacz/` is re-signed with it. Set `FRESH=0` to stay offline apart from that one request.

## 3. Acquire and derive

```bash
python3 code/provcap.py monitor --root data/arch --channels channels/channels_small.txt \
    --since 2026-11-26 --interval 600 --cycles 6 --witness data/witness.jsonl --collector my-id
python3 code/verify.py data/arch --witness data/witness.jsonl
python3 code/history.py data/arch history.json
```

`monitor` makes a deep crawl back to `--since`, then a pass over the newest page of every channel each
`--interval` seconds; creating a file `STOP` in the archive root triggers a final deep crawl and exit. Seals
must follow their epoch within 60 s (check vi), so do not re-seal archives later. Please collect politely:
the default delay is 0.7–1.3 s between requests per worker.
