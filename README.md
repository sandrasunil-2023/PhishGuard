# PhishGuard

PhishGuard is an educational phishing URL and social-engineering risk assessment web application. It provides a FastAPI API, a browser dashboard, a scikit-learn URL classifier, and a rule-based message analyzer.

> A scan result is a risk assessment, never proof that a link or message is safe. Do not enter passwords, OTPs, or other sensitive data into a link you do not trust.

## Features

- URL phishing analysis with 33 structural features, risk score, explanation, and batch scanning
- Social-engineering message analysis for urgency, threats, impersonation, credential requests, reward bait, links, and information harvesting
- MongoDB-backed scan metadata history; message bodies are not stored
- A responsive frontend dashboard for results, statistics, and recent scan history

## Run locally

1. Create and activate a Python virtual environment.
2. Install the backend dependencies:

   ```powershell
   .\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
   ```

3. Train the demonstration URL model:

   ```powershell
   Set-Location backend
   ..\.venv\Scripts\python.exe train_model.py
   ```

4. Start MongoDB if you want persisted history. Without MongoDB, scanning still works but history remains unavailable.
5. Serve the API and frontend in separate terminals:

   ```powershell
   Set-Location backend
   ..\.venv\Scripts\python.exe -m uvicorn main:app --reload
   ```

   ```powershell
   Set-Location frontend
   ..\.venv\Scripts\python.exe -m http.server 5500
   ```

6. Open `http://localhost:5500`.

## API endpoints

- `POST /check-url` or `POST /api/scan` with `{ "url": "https://example.com" }`
- `POST /check-message` with `{ "message": "..." }`
- `POST /api/scan/bulk` with `{ "urls": ["...", "..."] }`
- `GET /api/history`, `GET /api/message-history`, and `GET /api/stats`

The URL model is trained on the demonstration dataset in `backend/train_model.py`. Replace that synthetic data with an appropriately licensed, labeled URL dataset before presenting accuracy as real-world performance.
