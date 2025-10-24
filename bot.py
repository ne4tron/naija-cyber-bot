import os
import re
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, MessageHandler, filters, ContextTypes

def detect_scam(text):
    text = text.lower()
    red_flags = [
        "urgent", "verify your account", "reset password", "you have won",
        "bank login", "bvn", "otp", "investment offer", "quick money"
    ]
    scam_links = ["bit.ly", "tinyurl", "wa.me", "freegift", "9jamoney", "airtimeoffer"]
    
    flags = [word for word in red_flags if word in text]
    suspicious_links = [link for link in scam_links if link in text]
    
    if flags or suspicious_links:
        return f"🚨 Possible scam detected!\n⚠️ Keywords: {', '.join(flags)}\n🔗 Links: {', '.join(suspicious_links)}"
    return "✅ No obvious scam detected — but always stay alert."

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("👋 Welcome to *NaijaCyberGuardian!* 🇳🇬\n\nSend me any message, link, or SMS to check if it might be a scam.\n\nI'll help you stay safe online 💪", parse_mode="Markdown")

async def scan_message(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_input = update.message.text
    result = detect_scam(user_input)
    await update.message.reply_text(result)

if __name__ == "__main__":
    TOKEN = os.getenv("BOT_TOKEN")
    if not TOKEN:
        raise ValueError("❌ BOT_TOKEN not found. Set it in environment variables.")

    app = ApplicationBuilder().token(TOKEN).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, scan_message))

    print("🤖 NaijaCyberGuardian Bot is running...")
    app.run_polling()
