# Live Phishing Detection Chrome Extension & ML Backend
**Minor Project - I (Group 16)**
- **Students:** Amarnath Patra (24CSE303) & Aayush Kumar Gupta (24CSE398)
- **Supervisor:** Ms. S. Geetanjali Patra

---

## 📌 Project Overview
The **Live Phishing Detection System** is a real-time browser security application designed to detect and block deceptive phishing websites. It combines a **Manifest V3 Chrome Extension** with a **Python FastAPI Machine Learning Service** trained using a **Random Forest Classifier**.

### Key Features (Week 1 Review Ready)
1. **Real-Time URL Lexical & Feature Extraction**:
   - Analyzes URL length, domain length, IP address presence, HTTPS protocol, suspicious keywords (`login`, `verify`, `account`, `bank`, etc.), subdomains, and hyphenated typosquatting domains.
2. **Scikit-Learn Random Forest Classifier**:
   - Evaluates URL features, computes a risk probability score (0-100%), and classifies websites as **Safe**, **Suspicious**, or **Phishing**.
3. **Chrome Extension Manifest V3 Popup Dashboard**:
   - Dynamic SVG Risk Score Gauge meter with animated status indicators.
   - Breakdown list of detected threat anomalies.
   - One-click Whitelisting and Phishing Reporting modals.
4. **Full-Page Threat Warning Overlay (`content.js`)**:
   - Injects full-screen security alert when a high-risk phishing page is accessed.
   - Interactive options: *"Go Back to Safety"*, *"Trust & Whitelist Domain"*, and *"Proceed Anyways"*.
5. **Options & Security Management Portal**:
   - Full management table for Whitelisted sites with **Import JSON** and **Export JSON** support.
   - Phishing reports log and scan history activity tables.
   - Configurable alert sensitivity slider and FastAPI server endpoint settings.
6. **SQLite Persistent Database**:
   - Stores scan logs, reported phishing URLs, and custom whitelisted sites.

---

## 🚀 How to Run for Project Review

### Step 1: Start the FastAPI Backend Server
Open a terminal in the project directory and run:
```bash
cd backend
python main.py
```
*The server will start at `http://127.0.0.1:8000` and automatically load/train the Random Forest ML model (`phishing_rf_model.pkl`).*

### Step 2: Load the Extension in Google Chrome / Edge / Brave
1. Open Google Chrome and navigate to `chrome://extensions/`.
2. Enable **"Developer mode"** (toggle in top-right corner).
3. Click **"Load unpacked"**.
4. Select the `extension` folder inside this project directory (`c:\Users\LENOVO\OneDrive\Desktop\live phishing\extension`).
5. Pin the **PhishGuard AI** shield icon to your toolbar.

---

## 🧪 Testing Demonstration Scenarios

### Scenario A: Legitimate Website (Safe)
- Navigate to `https://www.google.com` or `https://github.com`.
- Click the extension icon.
- **Expected Result**: Badge displays **`SAFE`** (Green), Risk Score is ~0%, and status shows **SAFE WEBSITE**.

### Scenario B: Phishing Threat Detection & Full-Page Overlay
- Open a test URL containing suspicious phishing features (or test with IP/suspicious parameters e.g., `http://192.168.1.1/login-paypal-security-update-account/verify.php`).
- **Expected Result**:
  - Badge turns **`RISK`** (Red).
  - Full-page security warning overlay appears immediately over the webpage with risk features highlighted.
  - User can click **"Go Back to Safety"** or **"Trust & Whitelist Domain"**.

### Scenario C: Whitelist Management
- Open the Extension Popup and click **"Whitelist Site"** (or open Options Portal via ⚙️ icon).
- **Expected Result**: Domain is added to the SQLite database and bypasses future scanning.

---

## 📂 Project Structure
```
live phishing/
├── backend/
│   ├── main.py                # FastAPI REST API Application
│   ├── feature_extractor.py   # Lexical & Structural URL Feature Extractor
│   ├── train_model.py         # Random Forest Model Training Script
│   ├── database.py            # SQLite Database Connection & CRUD
│   ├── requirements.txt       # Python Dependencies
│   └── test_backend.py        # Automated Backend Test Suite
└── extension/
    ├── manifest.json          # Chrome Manifest V3 Config
    ├── background.js          # Service Worker & Tab Monitor
    ├── content.js & .css      # Full-page Phishing Threat Warning Overlay
    ├── popup/                 # Extension Popup Dashboard (HTML/CSS/JS)
    ├── options/               # Settings & Whitelist Management Portal
    └── icons/                 # Extension Shield Icons (16px, 48px, 128px)
```
