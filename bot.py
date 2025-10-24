
import os
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes
from flask import Flask
import threading

# --- Telegram Bot Logic ---

BOT_TOKEN = os.getenv("BOT_TOKEN")

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("👋 Welcome to NaijaCyberGuardian! Send me a message or link to check for scams.")

async def check_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    text = update.message.text.lower()
    suspicious_keywords = ["bvn", "otp", "verify", "urgent", "account suspended", "bank", "password"]
    suspicious_links = ["bit.ly", "tinyurl", "freegift", "promo"]

    found_keywords = [word for word in suspicious_keywords if word in text]
    found_links = [link for link in suspicious_links if link in text]

    if found_keywords or found_links:
        response = "🚨 Possible scam detected!\n"
        if found_keywords:
            response += f"⚠️ Keywords: {', '.join(found_keywords)}\n"
        if found_links:
            response += f"🔗 Links: {', '.join(found_links)}\n"
    else:
        response = "✅ This message looks safe — but always stay cautious!"

    await update.message.reply_text(response)

app_bot = ApplicationBuilder().token(BOT_TOKEN).build()
app_bot.add_handler(CommandHandler("start", start))
app_bot.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, check_message))

# --- Keep Alive Web Server for Render ---
app_web = Flask(__name__)

@app_web.route('/')
def home():
    return "NaijaCyberGuardian is live and scanning scams 👮‍♂️"

def run_flask():
    app_web.run(host="0.0.0.0", port=10000)

# --- Run both Flask and Bot together ---
if __name__ == '__main__':
    threading.Thread(target=run_flask).start()
    app_bot.run_polling()

