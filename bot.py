

#!/usr/bin/env python3
# bot.py - NaijaCyberGuardian v2 (advanced, free-friendly)
# Features:
#  - Keyword/pattern scoring
#  - Link extraction + shortener expansion
#  - Domain heuristics (suspicious tld, length, dashes)
#  - Optional WHOIS (if python-whois installed)
#  - Optional Hugging Face transformer classification (if transformers+torch installed)
#  - Local JSON reporting + optional Firebase push
#  - Flask keep-alive /health route for uptime monitors
#
# Recommended requirements (optional heavy ones can be omitted):
# python-telegram-bot==20.3
# flask
# requests
# tldextract
# python-whois   (optional)
# transformers   (optional)
# torch          (optional)

import os
import re
import json
import time
import logging
import threading
from datetime import datetime
from urllib.parse import urlparse
from typing import List, Dict, Any

import requests
import tldextract

from flask import Flask, jsonify
from telegram import Update, __version__ as TG_VER
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes

# Optional imports (transformers/whois). If missing, bot still works.
try:
    from transformers import pipeline
    HF_AVAILABLE = True
except Exception:
    HF_AVAILABLE = False

try:
    import whois as pywhois
    WHOIS_AVAILABLE = True
except Exception:
    WHOIS_AVAILABLE = False

# ---------- Basic config ----------
BOT_TOKEN = os.getenv("BOT_TOKEN")
if not BOT_TOKEN:
    raise RuntimeError("BOT_TOKEN env var is required")

# Optional Firebase (Realtime DB) push (set FIREBASE_URL and FIREBASE_SECRET to enable)
FIREBASE_URL = os.getenv("FIREBASE_URL")      # e.g. https://yourproj.firebaseio.com/reports.json
FIREBASE_SECRET = os.getenv("FIREBASE_SECRET")

# local reports file (useful for debugging / offline storage)
REPORTS_FILE = "reports.json"

# set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("NaijaCyberGuardian")

# ---------- Keyword / pattern lists (tweakable) ----------
KEYWORDS = [
    "bvn", "verify", "cbn", "urgent", "account suspended", "bank login",
    "otp", "one time", "you have won", "congratulations", "click here",
    "tinyurl", "bit.ly", "borrow", "loan approved", "no bvn", "no doc",
    "transfer now", "password", "reset", "blocked", "suspended"
]

# Localized / pidgin patterns (examples)
PIDGIN_PATTERNS = [
    "bros", "abeg", "send me", "help me", "i need money", "naira", "pay small"
]

SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".online", ".info", ".ru", ".tk"}

SHORTENER_HOSTS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "rebrand.ly", "shorturl.at"
}

SUSPICIOUS_SUBSTRINGS = ["verify", "login", "secure", "confirm", "update", "account", "service"]

# ---------- Load optional ML classifier ----------
classifier = None
if HF_AVAILABLE:
    try:
        # Small text-classifier. You can replace model with a smaller one if needed.
        logger.info("Loading HuggingFace pipeline (text-classification)...")
        classifier = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english")
        logger.info("Classifier loaded.")
    except Exception as e:
        logger.warning("HuggingFace pipeline couldn't be loaded: %s", e)
        classifier = None

# ---------- Utility functions ----------
URL_REGEX = re.compile(r"(https?://[^\s]+|www\.[^\s]+)", re.IGNORECASE)

def extract_urls(text: str) -> List[str]:
    if not text:
        return []
    return URL_REGEX.findall(text)

def normalize_url(u: str) -> str:
    # Ensure scheme
    if u.startswith("www."):
        u = "http://" + u
    if not re.match(r"^https?://", u):
        u = "http://" + u
    return u

def expand_url(url: str, timeout: int = 8) -> str:
    """Try to expand shortened URL using HEAD request (follow redirects)."""
    try:
        url0 = normalize_url(url)
        # Use HEAD first; if not allowed, use GET
        resp = requests.head(url0, allow_redirects=True, timeout=timeout)
        if resp.status_code and resp.headers.get("Location"):
            return resp.headers.get("Location")
        # fallback to GET
        resp = requests.get(url0, allow_redirects=True, timeout=timeout)
        return resp.url
    except Exception as e:
        logger.debug("expand_url error for %s: %s", url, e)
        return url

def domain_from_url(url: str) -> str:
    try:
        parsed = urlparse(normalize_url(url))
        return parsed.hostname or ""
    except Exception:
        return ""

def domain_heuristics(domain: str) -> Dict[str, Any]:
    """Return heuristics for domain suspiciousness."""
    heur = {"domain": domain, "suspicious_tld": False, "has_dash": False,
            "length": len(domain or ""), "suspicious_substrings": []}
    if not domain:
        return heur
    # tld check
    lower = domain.lower()
    for tld in SUSPICIOUS_TLDS:
        if lower.endswith(tld):
            heur["suspicious_tld"] = True
    heur["has_dash"] = "-" in domain
    for sub in SUSPICIOUS_SUBSTRINGS:
        if sub in lower:
            heur["suspicious_substrings"].append(sub)
    # domain registration via whois (if available)
    if WHOIS_AVAILABLE:
        try:
            w = pywhois.whois(domain)
            heur["whois_success"] = True
            heur["creation_date"] = str(w.creation_date)
            heur["whois_raw"] = True
        except Exception as e:
            heur["whois_success"] = False
    return heur

def shortener_check(domain: str) -> bool:
    return any(s in domain.lower() for s in SHORTENER_HOSTS)

def compute_keyword_score(text: str) -> Dict[str, Any]:
    """Return a score (0-1) and matched tokens list based on KEYWORDS and PIDGIN patterns."""
    txt = (text or "").lower()
    matches = []
    matches_pidgin = []
    for kw in KEYWORDS:
        if kw in txt:
            matches.append(kw)
    for p in PIDGIN_PATTERNS:
        if p in txt:
            matches_pidgin.append(p)
    # Simple scoring: keywords weigh more than pidgin patterns
    score = min(1.0, (len(matches) * 0.18) + (len(matches_pidgin) * 0.08))
    return {"score": score, "keywords": matches, "pidgin": matches_pidgin}

def ml_classify(text: str) -> Dict[str, Any]:
    """Use HF classifier if available. Return label & score or None."""
    if classifier is None:
        return {"available": False}
    try:
        out = classifier(text[:512])  # limit length
        if isinstance(out, list) and out:
            result = out[0]
            return {"available": True, "label": result.get("label"), "score": float(result.get("score", 0.0))}
        return {"available": True, "label": None, "score": 0.0}
    except Exception as e:
        logger.warning("ml_classify error: %s", e)
        return {"available": False}

def analyze_text(text: str) -> Dict[str, Any]:
    """Combine heuristics + ML to produce final analysis."""
    result = {"text": text, "timestamp": datetime.utcnow().isoformat() + "Z"}
    urls = extract_urls(text)
    result["urls"] = urls
    # keyword score
    kw = compute_keyword_score(text)
    result["keyword"] = kw
    # ml score
    ml = ml_classify(text)
    result["ml"] = ml
    # url analyses
    url_infos = []
    url_suspicious_count = 0
    for u in urls:
        expanded = expand_url(u)
        domain = domain_from_url(expanded)
        heur = domain_heuristics(domain)
        heur["original_url"] = u
        heur["expanded_url"] = expanded
        heur["is_shortener"] = shortener_check(domain)
        # a simple suspiciousness metric for link (0-1)
        link_score = 0.0
        if heur["is_shortener"]:
            link_score += 0.5
        if heur.get("suspicious_tld"):
            link_score += 0.3
        if heur.get("has_dash"):
            link_score += 0.1
        if heur.get("suspicious_substrings"):
            link_score += 0.2
        heur["link_score"] = min(1.0, link_score)
        if heur["link_score"] > 0.3:
            url_suspicious_count += 1
        url_infos.append(heur)
    result["url_infos"] = url_infos
    # combine final score heuristically
    final_score = kw["score"] * 0.6 + (url_suspicious_count * 0.25)
    if ml.get("available"):
        # if ML suggests high probability of negativity, boost score
        if ml.get("label") and ml.get("score"):
            # If ML thinks it's NEGATIVE -> treat as suspicious (this is a heuristic)
            if ml.get("label").upper() in ("NEGATIVE", "LABEL_1", "SUSPICIOUS", "FAKE"):
                final_score = min(1.0, final_score + 0.2 * ml.get("score"))
    result["final_score"] = round(final_score, 3)
    # explanation bits
    reasons = []
    if kw["keywords"]:
        reasons.append("Contains suspicious keywords: " + ", ".join(kw["keywords"]))
    if kw["pidgin"]:
        reasons.append("Contains informal/pidgin patterns: " + ", ".join(kw["pidgin"]))
    for ui in url_infos:
        if ui["link_score"] > 0.25:
            reasons.append(f"Suspicious link detected: {ui['original_url']} -> {ui['expanded_url']}")
    if ml.get("available") and ml.get("label"):
        reasons.append(f"ML classifier: {ml.get('label')} ({ml.get('score'):.2f})")
    result["reasons"] = reasons
    return result

def save_report(report: Dict[str, Any]) -> None:
    """Append anonymized report locally and try to push to Firebase if configured."""
    # minimal anonymization: remove full user names if present (not storing)
    try:
        if os.path.exists(REPORTS_FILE):
            with open(REPORTS_FILE, "r", encoding="utf-8") as f:
                arr = json.load(f)
        else:
            arr = []
    except Exception:
        arr = []
    # append
    short = {
        "timestamp": report.get("timestamp"),
        "final_score": report.get("final_score"),
        "keywords": report.get("keyword", {}).get("keywords", []),
        "pidgin": report.get("keyword", {}).get("pidgin", []),
        "url_count": len(report.get("urls", [])),
        "reasons": report.get("reasons", [])[:5],
    }
    arr.append(short)
    try:
        with open(REPORTS_FILE, "w", encoding="utf-8") as f:
            json.dump(arr[-2000:], f, ensure_ascii=False, indent=2)
    except Exception as e:
        logger.warning("Failed to write local reports file: %s", e)
    # optional Firebase push (simple)
    if FIREBASE_URL and FIREBASE_SECRET:
        try:
            push_url = FIREBASE_URL
            payload = {"data": short}
            # If FIREBASE_URL expects .json at end (Realtime DB)
            headers = {"Content-Type": "application/json"}
            params = {"auth": FIREBASE_SECRET}
            requests.post(push_url, params=params, json=payload, headers=headers, timeout=8)
        except Exception as e:
            logger.warning("Firebase push failed: %s", e)

# ---------- Telegram bot handlers ----------
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "👋 Welcome to NaijaCyberGuardian!\n"
        "Send me any suspicious message, link, or SMS and I'll analyze it for scams.\n\n"
        "Commands:\n"
        "/report - report the last message you received as a scam (stores anonymously)\n"
        "/help - bot help\n"
        "/stats - (admin) show recent summary\n"
    )

async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "Send any message and I'll analyze it.\n"
        "If you see a scam, use /report to add it to the community reports.\n"
        "We do not store personal data beyond anonymized samples."
    )

# admin: basic stats (shows last 10 local reports). Protect by TELEGRAM_ADMIN env var
ADMIN_ID = os.getenv("TELEGRAM_ADMIN")  # set to your Telegram numeric user id to use /stats

async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = str(update.effective_user.id) if update.effective_user else ""
    if ADMIN_ID and user_id != ADMIN_ID:
        await update.message.reply_text("You are not authorized to view stats.")
        return
    try:
        if os.path.exists(REPORTS_FILE):
            with open(REPORTS_FILE, "r", encoding="utf-8") as f:
                arr = json.load(f)
        else:
            arr = []
        last = arr[-10:]
        text = f"Recent {len(arr)} reports (showing last {len(last)}):\n"
        for r in last:
            text += f"- {r['timestamp']} | score:{r['final_score']} | urls:{r['url_count']} | keywords:{','.join(r['keywords'])}\n"
        await update.message.reply_text(text)
    except Exception as e:
        await update.message.reply_text("Failed to read stats: " + str(e))

# store last analysis per chat so /report can reference it
LAST_ANALYSIS_BY_CHAT = {}

async def report_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    chat_id = str(update.effective_chat.id)
    last = LAST_ANALYSIS_BY_CHAT.get(chat_id)
    if not last:
        await update.message.reply_text("No recent message analyzed to report. Send the suspicious message first.")
        return
    # Save report (anonymized)
    save_report(last)
    await update.message.reply_text("Thanks — the suspicious message has been recorded anonymously and will help improve detection.")

async def analyze_handler(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text or ""
    if not text.strip():
        await update.message.reply_text("Please send a non-empty message to analyze.")
        return
    # run analysis
    analysis = analyze_text(text)
    # save to LAST_ANALYSIS_BY_CHAT
    chat_id = str(update.effective_chat.id)
    LAST_ANALYSIS_BY_CHAT[chat_id] = analysis
    # craft reply
    score = analysis.get("final_score", 0.0)
    verdict = "SAFE"
    icon = "✅"
    if score >= 0.7:
        verdict = "SCAM"
        icon = "🚨"
    elif score >= 0.35:
        verdict = "SUSPICIOUS"
        icon = "⚠️"
    reply = f"{icon} Verdict: {verdict}\nScore: {score*100:.0f}%\n"
    if analysis.get("reasons"):
        reply += "Reasons:\n"
        for r in analysis["reasons"][:4]:
            reply += f"- {r}\n"
    # advice
    reply += "\nAdvice:\n"
    if verdict == "SCAM":
        reply += "Do NOT click links or share OTP/BVN. Contact your bank via official channels.\n"
    elif verdict == "SUSPICIOUS":
        reply += "Proceed with caution. Verify the sender via official channels before taking action.\n"
    else:
        reply += "Looks okay but stay cautious. Never share OTPs or BVN.\n"
    reply += "\nTo report this message for community tracking, reply /report"
    await update.message.reply_text(reply)

# ---------- Flask keep-alive server ----------
app = Flask(__name__)

@app.route("/", methods=["GET"])
def index():
    return "NaijaCyberGuardian is running ✅"

@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()}), 200

# ---------- Run both bot and Flask ----------
def start_flask():
    # If Render requires a specific port, it will provide in env PORT
    port = int(os.getenv("PORT", "10000"))
    app.run(host="0.0.0.0", port=port)

def main():
    # create telegram application
    app_bot = ApplicationBuilder().token(BOT_TOKEN).build()
    # handlers
    app_bot.add_handler(CommandHandler("start", start_command))
    app_bot.add_handler(CommandHandler("help", help_command))
    app_bot.add_handler(CommandHandler("report", report_command))
    app_bot.add_handler(CommandHandler("stats", stats_command))
    app_bot.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, analyze_handler))

    # run flask in thread
    t = threading.Thread(target=start_flask, daemon=True)
    t.start()
    logger.info("Flask keep-alive started on port %s", os.getenv("PORT", "10000"))

    # run polling (polling is simple & reliable behind Render's web server)
    logger.info("Starting Telegram polling...")
    app_bot.run_polling()

if __name__ == "__main__":
    main()
