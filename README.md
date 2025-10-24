# 🛡️ NaijaCyberGuardian Bot 🇳🇬

**A free AI-powered Telegram bot that detects scams, phishing links, and fake messages targeting Nigerians.**

---

## 🚀 Features
✅ Detects common **phishing keywords** (e.g. “verify BVN”, “urgent OTP”, “reset password”)  
✅ Flags **suspicious links** (like `bit.ly`, `tinyurl`, fake “free gift” pages)  
✅ Provides instant **cyber-safety advice** for Nigerian users  
✅ 100% free — runs on **Render + Telegram Bot API**  
✅ Easy to extend with **Firebase** or **AI models** later  

---

## 🧠 How It Works
NaijaCyberGuardian uses simple natural-language heuristics to spot scam patterns and suspicious URLs commonly used in Nigerian online fraud.  
It works **completely offline**, without storing any private user data.

---

## ⚙️ Setup Instructions

### 1️⃣ Create a Telegram Bot
1. Open **Telegram** → search for **@BotFather**
2. Send `/newbot`
3. Choose a name (e.g. `NaijaCyberGuardianBot`)
4. Copy the **API Token** it gives you

### 2️⃣ Deploy on Render (Free Cloud)
1. Go to [Render.com](https://render.com) → Sign in with GitHub  
2. Click **New → Web Service**  
3. Connect this GitHub repo  
4. Set these options:
   - **Environment:** Python  
   - **Build Command:**  
     ```
     pip install -r requirements.txt
     ```
   - **Start Command:**  
     ```
     python bot.py
     ```
5. Add Environment Variable:


Key: BOT_TOKEN
Value: <your Telegram token>

6. Click **Deploy**

After a few minutes, your bot will be live 24/7 🚀  

---

## 💬 Usage
1. Open your bot on Telegram  
2. Send `/start`  
3. Paste any SMS, link, or message you want to verify  

Example:


Your BVN has been suspended, click bit.ly/bankverify


Bot reply:


🚨 Possible scam detected!
⚠️ Keywords: bvn
🔗 Links: bit.ly


---

## 🧩 Folder Structure


naija-cyber-bot/
├── bot.py # Telegram bot logic
├── requirements.txt # Python dependencies
├── render.yaml # Render deployment configuration


---

## 🧰 Future Upgrades
- ✅ Screenshot / logo analysis (AI image detection)
- ✅ Firebase scam report database
- ✅ Dashboard for scam statistics by keyword or region
- ✅ Integration with local authorities (EFCC / NITDA) reporting API

---

## 👨‍💻 Built With
- Python 🐍  
- python-telegram-bot  
- Render (Free Cloud Hosting)  
- Telegram Bot API  

---

## ❤️ Credits
Developed as a free public-safety project to combat online scams in Nigeria.  
**NaijaCyberGuardian** — *Protecting Nigerians, one message at a time.*
