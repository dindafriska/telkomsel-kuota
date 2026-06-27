# 📱 Telkomsel Quota Checker

Python script to check **Telkomsel** (Indonesia) prepaid **quota & balance** via API. Works on Termux (Android) with automatic OTP reading from SMS.

---

## 🚀 Quick Start

### 1. Install dependencies
```bash
pip install pycryptodome
```

### 2. Setup config
```bash
cp config.example.json config.json
nano config.json
```
Edit `config.json` with your **phone number**:
```json
{
  "phone": "628xxxxxxxxx",
  "client_id": "e7126474617aa39eb9e484233c9b0649",
  "client_secret": "P@ssw0rd"
}
```
> `client_id` and `client_secret` are the public web app credentials — no need to change.

### 3. Run
```bash
python cek_telkomsel_ok.py
```

---

## 🧠 How It Works

### First Run (or when session expires)
```
📱 Using saved session...      ← tries saved token first
🔑 Session expired.            ← if 401, does fresh auth
🔐 Sending OTP to 628114xxx...
⏳ Waiting for OTP SMS...
🔐 Submitting OTP 784499...
✅ OTP accepted!
🔐 Getting auth code...
🔐 Getting access token...
✅ Token obtained!

📊 TELKOMSEL QUOTA REPORT

  📦 DATA — 7 GB
  --------------------------------------------------
  • Internet
    Remaining: 7 GB  |  Exp: 2026-06-30

  📦 ENTERTAINMENT — 10.81 GB
  --------------------------------------------------
  • Zoom
    Remaining: 10.81 GB  |  Exp: 2026-06-30
```

### Subsequent Runs (within 5 days)
```
📱 Using saved session...
📊 TELKOMSEL QUOTA REPORT
  ... (instant, no OTP needed)
```

> Tokens are saved in `~/.telkomsel_session.json` and valid for ~5 days.

---

## 📂 Scripts

| Script | Description | Dependencies |
|--------|-------------|-------------|
| `cek_telkomsel_ok.py` | **Recommended** — session reuse + auto OTP fallback | `pycryptodome` |
| `telkomsel_auto.py` | Auto OTP from SMS + quota (pure Python AES) | none |
| `telkomsel_quota.py` | Pure Python, no deps | none |
| `config.example.json` | Configuration template | — |

---

## 🔧 Requirements

- **Python 3.8+**
- **Termux** on Android
- **Termux:API** (`pkg install termux-api`) for SMS reading
- SMS permission granted to Termux

---

## 📡 API Endpoints Used

| Step | Endpoint | Purpose |
|------|----------|---------|
| 1 | `POST .../iam/v1/realms/tsel/authenticate` | OTP login |
| 2 | `GET .../oauth2/realms/tsel/authorize` | Authorization code |
| 3 | `POST .../oauth2/realms/tsel/access_token` | Access token |
| 4 | `POST .../api/subscriber/v5/bonuses` | Quota data |
| 5 | `POST .../api/subscriber/v5/profile` | Balance (currently 404) |

Headers are encrypted using **AES-128-OFB** with password `"production"` — matching Telkomsel's web app (`my.telkomsel.com`) implementation.

---

## ⚠️ Note

The phone number in `config.json` is **your personal data** — the `.gitignore` prevents it from being pushed to GitHub. Only `config.example.json` (with a placeholder number) is tracked.
