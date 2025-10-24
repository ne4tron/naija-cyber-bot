

import os
import re
import requests
import tldextract
from flask import Flask, request
from transformers import pipeline

# === Telegram Config ===
BOT_TOKEN = os.environ.get("BOT_TOKEN")
BASE_URL = f"https://api.telegram.org/bot{BOT_TOKEN}"

# === Flask App ===
app = Flask(__name__)

# === ML Model (lightweight sentiment model) ===
try:
    classifier = pipeline(
        "text-classification",
        model="distilbert-base-uncased-finetuned-sst-2-english"
    )
except Exception as e:
    classifier = None
    print("⚠️ Could not load model:", e)

# === Scam Keywords ===
SCAM_KEYWORDS = [
    "bvn", "atm", "otp", "reset", "urgent", "verify", "link",
    "password", "account", "bank", "click", "claim", "lottery",
    "reward", "prize", "payment", "transfer", "crypto", "wallet",
    "giveaway", "investment", "fund", "credit"
]


def detect_keywords(text):
    """Find scam-related keywords."""
    found = [kw for kw in SCAM_KEYWORDS if re.search(rf"\b{kw}\b", text, re.IGNORECASE)]
    return found


def check_domain_safety(text):
    """Extract domains and flag suspicious ones."""
    domains = []
    for match in re.findall(r"https?://[^\s]+", text):
        domain = tldextract.extract(match).registered_domain
        if domain:
            domains.append(domain)

    flagged = [
        d for d in domains
        if any(word in d for word in ["verify", "secure", "bank", "auth", "update"])
    ]
    return {"domains": domains, "flagged": flagged}


def ml_score(text):
    """Use ML to get risk sentiment score."""
    if not classifier:
        return {"score": 0.5, "label": "neutral"}

    result = classifier(text[:512])[0]
    score = float(result["score"])
    label = result["label"].lower()
    risk = score if label == "negative" else 1 - score
    return {"score": round(risk, 2), "label": label}


def analyse_message(text):
    """Combine keyword, domain, and ML checks."""
    keywords = detect_keywords(text)
    domains = check_domain_safety(text)
    ml_result = ml_score(text)

    score = min(1.0, len(keywords) * 0.05 + ml_result["score"])
    risk_level = "🟥 High" if score > 0.7 else "🟧 Medium" if score > 0.4 else "🟩 Low"

    response = (
        f"🔍 *Scam Analysis Result:*\n\n"
        f"🧠 *Risk Level:* {risk_level}\n"
        f"📊 *Score:* {round(score * 100, 1)}%\n\n"
    )

    if keywords:
        response += f"🪤 *Keywords:* {', '.join(keywords)}\n"
    if domains["domains"]:
        response += f"🌐 *Domains Found:* {', '.join(domains['domains'])}\n"
    if domains["flagged"]:
        response += f"🚨 *Suspicious Domains:* {', '.join(domains['flagged'])}\n"

    response += f"\n🤖 ML Model Detected: {ml_result['label']} (confidence {ml_result['score']})"
    return response


def send_message(chat_id, text):
    """Send message via Telegram API."""
    url = f"{BASE_URL}/sendMessage"
    data = {"chat_id": chat_id, "text": text, "parse_mode": "Markdown"}
    requests.post(url, json=data)


@app.route("/", methods=["GET"])
def home():
    return "Bot is live!"


@app.route("/webhook", methods=["POST"])
def webhook():
    update = request.get_json()
    if not update:
        return "no update", 400

    message = update.get("message", {})
    chat_id = message.get("chat", {}).get("id")
    text = message.get("text", "")

    if not text or not chat_id:
        return "no message", 200

    if text.lower().startswith("/start"):
        send_message(chat_id, "👋 Hi! I’m your *Naija CyberGuard Bot* 🇳🇬\n\n"
                              "Send me any message, link, or text, and I’ll analyse it for scams.")
    else:
        analysis = analyse_message(text)
        send_message(chat_id, analysis)

    return "ok", 200


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)
