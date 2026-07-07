<p align="center">
  <img src="https://img.shields.io/badge/Usf--Pnl-VLESS%20Proxy%20Panel-8b5cf6?style=for-the-badge" alt="Usf-Pnl">
  <br>
  <img src="https://img.shields.io/badge/Platform-Hugging%20Face%20Spaces-ffca28?style=flat-square" alt="HF Spaces">
  <img src="https://img.shields.io/badge/Protocol-VLESS%20over%20WS%20%2B%20TLS-3b82f6?style=flat-square" alt="VLESS">
  <img src="https://img.shields.io/badge/License-MIT-10b981?style=flat-square" alt="License">
</p>

## Usf-Pnl

A modern VLESS proxy management panel optimized for **Hugging Face Spaces**. Deploy your own panel with a single token — no server, no domain, no configuration needed.

**Panel Builder:** [https://godde3s.github.io/Usf-Pnl/](https://godde3s.github.io/Usf-Pnl/)

### Features

- **One-Click Deploy** — Enter your HF token, get a working panel in under 2 minutes
- **High Performance** — 256KB relay buffers, TCP_NODELAY, fully async I/O
- **Anti-Fingerprint** — Pre-handshake WebSocket validation, plain root endpoint, proper TLS
- **Modern Dashboard** — Dark/Light theme, purple accent, bilingual (EN/FA), responsive
- **Real-Time Stats** — CPU, memory, traffic charts (Chart.js), connection monitoring
- **Subscription System** — Usage progress bars, expiry countdown, standard `subscription-userinfo` header
- **Quota Management** — Per-inbound traffic limits, connection caps, expiry dates
- **QR Code Support** — Generate QR codes for quick client import

### Quick Deploy

1. Go to [https://godde3s.github.io/Usf-Pnl/](https://godde3s.github.io/Usf-Pnl/)
2. Enter your Hugging Face token (get one at `huggingface.co/settings/tokens` with **write** access)
3. Click **Deploy** — done!

Your panel will be live at `https://<username>-<spacename>.hf.space`

> Default login: `admin` / `admin` — **change it immediately after first login.**

### Manual Deploy

```bash
# Clone this repo
git clone https://github.com/godde3s/Usf-Pnl.git
cd Usf-Pnl

# Create a new HF Space (Docker SDK)
# Then push:
git remote add hf https://huggingface.co/<username>/<space-name>
git push hf main
```

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `7860` | App listen port (HF Spaces uses 7860) |
| `SECRET_KEY` | Random | Encryption key for sessions |
| `PANEL_PASSWORD` | `admin` | Dashboard login password |
| `SPACE_HOST` | Auto | Domain for VLESS link generation |

### Tech Stack

- **Backend:** Python, FastAPI, Uvicorn, asyncio
- **Frontend:** Vanilla HTML/CSS/JS (no framework dependency)
- **Charts:** Chart.js
- **Hosting:** Hugging Face Spaces (Docker SDK)
- **Protocol:** VLESS over WebSocket + TLS

### License

MIT