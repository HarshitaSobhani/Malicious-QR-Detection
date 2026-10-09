# Malicious QR Detection (QR Sentinel)

A QR code security scanner. The Flutter app scans a QR code and a FastAPI backend decides whether the link inside is safe, suspicious or dangerous, before you open it.

## How it works

1. The app scans a QR code and sends its content to `POST /api/analyze`.
2. The backend runs several independent checks and combines them into one verdict with a score and human-readable reasons:
   - **Redirect tracing**: follows the full redirect chain (HTTP, meta-refresh, JavaScript) and flags domain changes.
   - **Heuristics**: suspicious TLDs, IP-based URLs, dangerous file extensions (`.apk`, `.exe`, ...), brand impersonation.
   - **WHOIS**: domain age verification.
   - **Threat feeds**: Google Safe Browsing and PhishTank lookups.
   - **ML classifier**: URL-feature model trained with `train_model.py`.
3. The verdict engine aggregates the signals. Any PhishTank hit is treated as dangerous.

## Repository layout

| Folder | What it is |
|---|---|
| `backend/` | FastAPI service (Python 3.11): analysis pipeline, ML model, Dockerfile |
| `frontend/` | Flutter mobile/web app (`qr_sentinel`): camera scanner and result UI |

## Run the backend

```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # add your own API keys
uvicorn app.main:app --port 8000
```

- Health check: `GET /health`
- Analyze: `POST /api/analyze` with `{"content": "https://example.com"}`
- Docker: `docker build -t qr-sentinel . && docker run -p 8000:8000 --env-file .env qr-sentinel`

## Run the frontend

```bash
cd frontend
flutter pub get
flutter run
```

The backend address is set in `frontend/lib/services/api_service.dart` (`baseUrl`, default `http://127.0.0.1:8000`). Use `http://10.0.2.2:8000` for the Android emulator, or your machine's LAN IP for a physical device.

## Configuration

API keys are read from environment variables and are never committed. See `backend/.env.example`.

| Variable | Purpose |
|---|---|
| `GSB_API_KEY` | Google Safe Browsing lookups (skipped if unset) |
| `PHISHTANK_API_KEY` | PhishTank lookups (optional) |

## Notes

- CORS is currently open (`*`) for development. Restrict `allow_origins` before production.
- QR contents are analysed in-flight and not stored by the backend.
