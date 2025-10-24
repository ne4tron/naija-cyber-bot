# Naija CyberGuard Bot 🇳🇬

A free Telegram bot that analyses messages for scams in Nigeria.  
It detects **scam keywords**, **suspicious domains**, and uses a **rule-based Mini-AI** to assign a **risk score** (Low / Medium / High).

---

## ⚡ Features

- Keyword-based scam detection  
- Suspicious domain detection  
- Rule-based Mini-AI risk scoring  
- Risk levels and percentage score  
- Works on **Render Free Tier** (no heavy ML required)  
- 24/7 uptime once deployed  

---

## 📥 Deployment

### 1️⃣ Clone the repository
```bash
git clone <your-repo-url>
cd naija-cyberguard
2️⃣ Install dependencies
bash
Copy code
pip install -r requirements.txt
3️⃣ Set up environment variables
Create a .env file or use Render Environment Variables:

ini
Copy code
BOT_TOKEN=<Your Telegram Bot Token>
PORT=10000
4️⃣ Deploy on Render
Create a new Web Service → Python environment.

Upload this repository or connect GitHub.

Add the environment variables above.

Set Build Command:

nginx
Copy code
pip install -r requirements.txt
Set Start Command:

nginx
Copy code
python bot.py
Deploy.

5️⃣ Set Telegram Webhook
After deployment, run:

bash
Copy code
https://api.telegram.org/bot<YOUR_BOT_TOKEN>/setWebhook?url=<YOUR_RENDER_URL>/webhook
💬 Usage
Start the bot:

bash
Copy code
/start
Send any message, text, or link. Examples:

cpp
Copy code
You have won ₦50,000! Click https://bank-verify-secure.com to claim your reward immediately.
Bot Response:

yaml
Copy code
🔍 Scam Analysis Result:

🧠 Risk Level: 🟥 High
📊 Score: 87.0%

🪤 Keywords Detected: reward, claim, bank, click
🌐 Domains Found: bank-verify-secure.com
🚨 Suspicious Domains: bank-verify-secure.com

🤖 Model: Rule-Based Mini-AI
Other examples:

Normal message → Low risk

Urgent scam text → High risk

🔧 How it Works
Keyword Detection: Checks for common scam-related words like BVN, OTP, verify, reward.

Domain Analysis: Extracts URLs from the message and flags suspicious domains.

Rule-Based Mini-AI: Calculates a risk score using weighted rules:

Keywords → small weight

Suspicious domains → higher weight

Urgency words → extra weight

Risk Level: Converts score to Low, Medium, or High for easy reading.

📦 Files
bot.py → Main bot logic

requirements.txt → Python dependencies

render.yaml → Render deployment configuration

README.md → This file

🛡 Notes
Fully free to deploy on Render Free Tier.

No heavy ML model loaded → avoids out-of-memory errors.

Safe to push to GitHub — your BOT_TOKEN is stored in environment variables, not in the code.

🔗 Links
GitHub Repository: <your-repo-url>

Render Deployment: <your-render-url>

👏 Contribution
Feel free to submit PRs for:

New scam keyword updates

Enhanced suspicious domain detection

Rule improvements for Mini-AI scoring

yaml
Copy code

---

If you want, I can **also package the entire bot** (`bot.py`, `requirements.txt`, `render.yaml`, and this README) **into a single ZIP** ready to upload to Render directly — no editing needed.  

Do you want me to do that next?
