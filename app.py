"""ThreatTrace AI backend.
Run locally:  pip install flask flask-cors  &&  python app.py
Endpoints (match the dashboard):
  GET /api/dashboard -> emails_analyzed, threats_detected, high_risk,
                        phishing, bec, suspicious, recent_threats
  GET /api/emails    -> list of {id, from, subj, risk, lvl, cls, conf, time,
                        ip, geo, dom, chain, att, date, spf, dkim, dmarc}
Reads sample.db: emails(gid TEXT PRIMARY KEY, ts TEXT, data TEXT JSON).
"""
import json
import os
import sqlite3

from flask import Flask, jsonify, request
from flask_cors import CORS

DB_PATH = os.environ.get("DB_PATH", "sample.db")
THREAT_MIN_RISK = 40  # risk >= this counts as a threat

app = Flask(__name__)
CORS(app)  # lets the HTML dashboard call the API from another origin


def pick(d, *keys, default=None):
    """First present key; ingest.py field names may vary."""
    for k in keys:
        if d.get(k) not in (None, ""):
            return d[k]
    return default


def level(risk):
    if risk >= 90: return "CRITICAL"
    if risk >= 70: return "HIGH"
    if risk >= 40: return "MEDIUM"
    if risk >= 15: return "LOW"
    return "INFO"


def to_num(v, default=0):
    try:
        return float(v) if not isinstance(v, (int, float)) else v
    except (TypeError, ValueError):
        return default


def normalize(gid, ts, raw):
    try:
        d = json.loads(raw) if raw else {}
    except json.JSONDecodeError:
        d = {}
    risk = to_num(pick(d, "risk", "score", "risk_score", default=0))
    return {
        "id": gid,
        "from": pick(d, "from", "sender", default=""),
        "subj": pick(d, "subj", "subject", default=""),
        "risk": risk,
        "lvl": str(pick(d, "lvl", "level", default=level(risk))).upper(),
        "cls": pick(d, "cls", "classification", "verdict", default="Unknown"),
        "conf": pick(d, "conf", "confidence"),
        "time": pick(d, "time", default=ts),
        "ip": pick(d, "ip", "sending_ip", default=""),
        "geo": pick(d, "geo", "location", default=""),
        "dom": pick(d, "dom", "domain", default=""),
        "chain": pick(d, "chain", "url_chain", default=[]),
        "att": pick(d, "att", "attachment", default="None"),
        "date": pick(d, "date", default=ts),
        "spf": pick(d, "spf", default=""),
        "dkim": pick(d, "dkim", default=""),
        "dmarc": pick(d, "dmarc", default=""),
    }


def load_emails():
    con = sqlite3.connect(DB_PATH)
    try:
        rows = con.execute("SELECT gid, ts, data FROM emails ORDER BY ts DESC").fetchall()
    finally:
        con.close()
    return [normalize(*r) for r in rows]


def has(e, *words):
    c = str(e["cls"]).lower()
    return any(w in c for w in words)


@app.get("/api/emails")
def emails():
    items = load_emails()
    limit = request.args.get("limit", type=int)
    return jsonify(items[:limit] if limit else items)


@app.get("/api/dashboard")
def dashboard():
    items = load_emails()
    threats = [e for e in items if e["risk"] >= THREAT_MIN_RISK]
    return jsonify({
        "emails_analyzed": len(items),
        "threats_detected": len(threats),
        "high_risk": sum(1 for e in items if e["lvl"] in ("HIGH", "CRITICAL")),
        "phishing": sum(1 for e in threats if has(e, "phish")),
        "bec": sum(1 for e in threats if has(e, "bec", "business email")),
        "suspicious": sum(1 for e in threats if has(e, "suspicious")),
        "recent_threats": threats[:10],  # already newest first
    })


@app.get("/api/health")
def health():
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)