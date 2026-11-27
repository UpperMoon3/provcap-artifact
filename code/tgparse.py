"""Deterministic parser for t.me/s/<channel> and t.me/<channel>/<id>?embed=1 pages."""
import hashlib, re
from datetime import datetime
from bs4 import BeautifulSoup

POSTLINK = re.compile(r"https?://t\.me/([A-Za-z0-9_]+)/(\d+)")


def _norm(s):
    return re.sub(r"\s+", " ", s or "").strip()


def parse_page(html, channel=None):
    soup = BeautifulSoup(html, "lxml")
    out = []
    for m in soup.select("div.tgme_widget_message[data-post]"):
        try:
            ch, mid = m["data-post"].split("/"); mid = int(mid)
        except Exception:
            continue
        t = m.select_one("time[datetime]")
        if not t:
            continue
        txt = m.select_one("div.tgme_widget_message_text")
        text = _norm(txt.get_text(" ", strip=True)) if txt else ""
        meta = m.select_one(".tgme_widget_message_meta")
        edited = bool(meta and "edited" in meta.get_text(" ", strip=True).lower())
        media = []
        for el in m.select(".tgme_widget_message_photo_wrap, .tgme_widget_message_video_player, "
                           ".tgme_widget_message_document_wrap, .tgme_widget_message_roundvideo_player, "
                           ".tgme_widget_message_voice_player"):
            toks = [c for c in el.get("class", []) if re.fullmatch(r"[\d_]+", c)]
            media.append(("m:" + "/".join(toks)) if toks else "m:" + el.get("class", ["?"])[0])
        members = set()
        for a in m.select(".tgme_widget_message_grouped_wrap a[href]"):
            mm = POSTLINK.match(a["href"])
            if mm and mm.group(1).lower() == ch.lower():
                members.add(int(mm.group(2)))
        members.discard(mid)
        rp = m.select_one("a.tgme_widget_message_reply[href]")
        rpm = POSTLINK.match(rp["href"]) if rp is not None else None
        reply_to = int(rpm.group(2)) if rpm else None
        fw = m.select_one(".tgme_widget_message_forwarded_from_name")
        fwd = fw.get("href") if fw is not None and fw.get("href") else (fw.get_text(strip=True) if fw is not None else None)
        v = m.select_one("span.tgme_widget_message_views")
        content = {"text": text, "media": sorted(media), "fwd": fwd}
        out.append(dict(ch=ch.lower(), id=mid, t=t["datetime"], ts=datetime.fromisoformat(t["datetime"]).timestamp(),
                        text=text, edited=edited, media=sorted(media), album=sorted(members), fwd=fwd, reply_to=reply_to,
                        views=v.get_text(strip=True) if v else None,
                        chash=hashlib.sha256(repr(sorted(content.items())).encode()).hexdigest()[:16],
                        thash=hashlib.sha256(text.encode()).hexdigest()[:16]))
    return out


def embed_status(html):
    """'not_found' | 'exists' | 'unknown' for a single-post embed page."""
    if "tgme_widget_message_error" in html and "not found" in html.lower():
        return "not_found"
    if "data-post=" in html:
        return "exists"
    return "unknown"
