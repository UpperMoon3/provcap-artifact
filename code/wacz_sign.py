"""Emulation of a signed WACZ package (WACZ 1.1.1 + "WACZ Signing and Verification" 0.1.0) used as
baseline S6 in the tamper experiment.

Semantics reproduced from the specification: datapackage.json lists the SHA-256 and size of every file
in the package; datapackage-digest.json holds the hash of datapackage.json and one signedData object
with that hash signed by the collector's key and an RFC 3161 token over the signature; a verifier
checks the file hashes, the signature, the token and that `created` is within 10 minutes of the
token time. Individual record times and their order are not bound by the signature.
"""
import base64, json, os, re, subprocess, tempfile
from datetime import datetime, timezone
import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

import hashlib

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TSA_URL = {"freetsa": "https://freetsa.org/tsr", "digicert": "http://timestamp.digicert.com"}
CA = {"freetsa": ["-CAfile", f"{HERE}/tsa/cacert.pem", "-untrusted", f"{HERE}/tsa/tsa.crt"],
      "digicert": ["-CAfile", next((c for c in (os.environ.get("SSL_CERT_FILE"), "/etc/ssl/cert.pem",
                                                "/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt")
                                       if c and os.path.exists(c)), "/etc/ssl/cert.pem")]}
MAX_CREATED_SKEW = 600  # seconds, per the WACZ signing specification
_cache = {}


def _sha(b):
    return hashlib.sha256(b).hexdigest()


def canon(o):
    return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def tsa_token(data, tsa="freetsa"):
    """Request an RFC 3161 token over `data` (only its SHA-256 imprint leaves this machine)."""
    wd = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
    p = f"{wd}/d.bin"; open(p, "wb").write(data)
    subprocess.run(["openssl", "ts", "-query", "-data", p, "-sha256", "-cert", "-out", p + ".tsq"], check=True, capture_output=True)
    r = requests.post(TSA_URL[tsa], data=open(p + ".tsq", "rb").read(), headers={"Content-Type": "application/timestamp-query"}, timeout=30)
    txt = subprocess.run(["openssl", "ts", "-reply", "-in", "/dev/stdin", "-text"], input=r.content, capture_output=True).stdout.decode()
    gt = [l.split(":", 1)[1].strip() for l in txt.splitlines() if l.startswith("Time stamp:")]
    return r.content, (re.sub(r"\.\d+", "", gt[0]) if gt else None)


def load_key(path):
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        k = ec.generate_private_key(ec.SECP256R1())
        open(path, "wb").write(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                serialization.NoEncryption()))
    return serialization.load_pem_private_key(open(path, "rb").read(), None)


def pub_der(key):
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def resources(root):
    out = []
    for f in sorted(os.listdir(f"{root}/warc")):
        b = open(f"{root}/warc/{f}", "rb").read()
        out.append(dict(name=f, path=f"warc/{f}", hash="sha256:" + _sha(b), bytes=len(b)))
    return out


def write_datapackage(root, created):
    os.makedirs(f"{root}/wacz", exist_ok=True)
    dp = canon(dict(profile="data-package", wacz_version="1.1.1", created=created, resources=resources(root)))
    open(f"{root}/wacz/datapackage.json", "wb").write(dp)
    return "sha256:" + _sha(dp)


def sign(root, key, created=None, token=None, keep_token_from=None):
    """Build and sign the package. token: callable(signature) -> (tsr bytes, gen_time); keep_token_from:
    reuse the token of an earlier signedData (an adversary without access to a TSA)."""
    created = created or datetime.now(timezone.utc).isoformat(timespec="seconds")
    h = write_datapackage(root, created)
    sig = key.sign(h.encode(), ec.ECDSA(hashes.SHA256()))
    if keep_token_from:
        tok, gt = base64.b64decode(keep_token_from["timeSignature"]), keep_token_from["timeGenTime"]
    else:
        tok, gt = token(sig)
    sd = dict(hash=h, created=created, software="wacz-signing-emulation", signature=base64.b64encode(sig).decode(),
              publicKey=base64.b64encode(pub_der(key)).decode(), timeSignature=base64.b64encode(tok).decode(),
              timeGenTime=gt)
    json.dump(dict(path="datapackage.json", hash=h, signedData=sd), open(f"{root}/wacz/datapackage-digest.json", "w"))
    return sd


def recompute_unsigned(root):
    """Format-aware adversary without the signing key: refresh datapackage.json and the digest hash."""
    d = json.load(open(f"{root}/wacz/datapackage-digest.json"))
    created = json.load(open(f"{root}/wacz/datapackage.json"))["created"]
    h = write_datapackage(root, created)
    d["hash"] = h; d["signedData"]["hash"] = h
    json.dump(d, open(f"{root}/wacz/datapackage-digest.json", "w"))


def check(root, expected_pub):
    """True if the package verifies according to the WACZ signing rules."""
    try:
        dpb = open(f"{root}/wacz/datapackage.json", "rb").read()
        dp = json.loads(dpb); d = json.load(open(f"{root}/wacz/datapackage-digest.json")); sd = d["signedData"]
        if dp["resources"] != resources(root):
            return False
        h = "sha256:" + _sha(dpb)
        if not (d["hash"] == h == sd["hash"]):
            return False
        if base64.b64decode(sd["publicKey"]) != expected_pub:
            return False
        sig = base64.b64decode(sd["signature"])
        serialization.load_der_public_key(expected_pub).verify(sig, h.encode(), ec.ECDSA(hashes.SHA256()))
        tok = base64.b64decode(sd["timeSignature"])
        key = (_sha(tok), _sha(sig))
        if key not in _cache:
            wd = tempfile.mkdtemp(dir=os.environ.get("TMPDIR"))
            open(f"{wd}/s", "wb").write(sig); open(f"{wd}/t", "wb").write(tok)
            r = subprocess.run(["openssl", "ts", "-verify", "-data", f"{wd}/s", "-in", f"{wd}/t"] + CA["freetsa"],
                               capture_output=True, text=True)
            _cache[key] = "Verification: OK" in (r.stdout + r.stderr)
        if not _cache[key]:
            return False
        gt = datetime.strptime(sd["timeGenTime"].replace(" GMT", ""), "%b %d %H:%M:%S %Y").replace(tzinfo=timezone.utc)
        return abs((gt - datetime.fromisoformat(sd["created"])).total_seconds()) <= MAX_CREATED_SKEW
    except Exception:
        return False
