# Panel

VLESS proxy management panel. Deploy on Render, Railway, Koyeb, or Fly.io.

## Deploy on Render

1. Create a new **Web Service** on [render.com](https://render.com)
2. Connect this GitHub repo, branch `main`
3. Set environment variable `PANEL_PASSWORD` to your desired password
4. Click **Create Web Service**

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | Auto-detect | App listen port |
| `PANEL_PASSWORD` | `admin` | Dashboard login password |

## License

MIT