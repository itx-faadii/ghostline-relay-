# GhostLine Signaling Relay — Deployment Guide

> **What this server does:** The relay brokers WebRTC ICE/SDP handshakes, and for a
> recipient that is offline it holds already-encrypted message blobs until that
> recipient reconnects.  
> It **never sees message plaintext, identities in the clear, or chat history** —
> what it does hold is opaque ciphertext plus the metadata listed in
> [Security Notes](#8-security-notes), and it drops each blob on delivery.
> All chat content is E2E-encrypted between the two devices before it leaves the app.

---

## 1. Prerequisites

- Node.js 18+ (LTS recommended)
- `server/` directory from this repository
- A public domain or IP with a valid TLS certificate (required for `wss://` — Android/iOS reject plain `ws://` on the internet)

---

## 2. Option A — Railway.app (Easiest, Free Tier, Auto-HTTPS/WSS)

### Steps

```bash
# 1. Install Railway CLI
npm install -g @railway/cli

# 2. Login
railway login

# 3. Inside the server/ directory
cd server

# 4. Initialize Railway project
railway init

# 5. Deploy
railway up
```

> **Windows Users:** If `railway` is not recognized after `npm install -g`, run this first in PowerShell (one-time fix):
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
> ```
> Then restart your terminal. The npm global scripts folder (`%AppData%\npm`) must be in your PATH.

Railway auto-assigns a `wss://your-project.railway.app` URL with TLS. No extra config needed.

### Environment Variables (Railway Dashboard → Variables)
| Variable | Value |
|---|---|
| `PORT` | `8787` (or leave blank — Railway sets `PORT` automatically) |

### Getting your URL
Go to **Railway Dashboard → Deployments → Domain**. Use that as your relay URL in the app, e.g.:
```
wss://ghostline-relay-production-e0f8.up.railway.app
```

---

## 3. Option B — Render.com (Free Node.js Web Service)

### Steps

1. Push the `server/` directory to a GitHub repo (or use a monorepo).
2. Go to [render.com](https://render.com) → **New → Web Service**.
3. Connect your repository.
4. Set:
   - **Build Command:** `npm install`
   - **Start Command:** `node signaling_server.js`
   - **Environment:** Node
5. Click **Deploy**. Render gives you a `wss://your-service.onrender.com` URL automatically.

### Environment Variables (Render Dashboard → Environment)
| Variable | Value |
|---|---|
| `PORT` | `10000` (Render default; `signaling_server.js` reads `process.env.PORT`) |

---

## 4. Option C — Fly.io (Global Anycast, Free Tier)

### Steps

```bash
# 1. Install flyctl
# macOS/Linux:
curl -L https://fly.io/install.sh | sh
# Windows:
iwr https://fly.io/install.ps1 -useb | iex

# 2. Login
flyctl auth login

# 3. Inside server/ directory
cd server

# 4. Launch (follow interactive prompts — select Node.js, pick region)
flyctl launch

# 5. Deploy
flyctl deploy
```

Fly.io assigns a `wss://your-app.fly.dev` URL with TLS globally distributed.

### fly.toml (auto-generated, but verify these settings)
```toml
[http_service]
  internal_port = 8787
  force_https = true

[[vm]]
  memory = "256mb"
  cpu_kind = "shared"
  cpus = 1
```

---

## 5. Option D — Self-Hosted VPS (DigitalOcean / Hetzner / Any Linux VPS)

### Step 1: Prepare the server

```bash
# Connect via SSH
ssh root@your-server-ip

# Install Node.js 18+
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -
apt-get install -y nodejs

# Install PM2 (process manager)
npm install -g pm2
```

### Step 2: Upload and run the relay

```bash
# Upload server/ directory (from your local machine)
scp -r server/ root@your-server-ip:/opt/ghostline-relay/

# On the server
cd /opt/ghostline-relay
npm install
pm2 start signaling_server.js --name ghostline-relay
pm2 save
pm2 startup
```

### Step 3: Configure nginx reverse proxy with TLS

Install nginx and Certbot:

```bash
apt-get install -y nginx certbot python3-certbot-nginx
```

Create `/etc/nginx/sites-available/ghostline-relay`:

```nginx
server {
    listen 80;
    server_name relay.yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8787;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

Enable and get TLS certificate:

```bash
ln -s /etc/nginx/sites-available/ghostline-relay /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx

# Get free TLS cert from Let's Encrypt
certbot --nginx -d relay.yourdomain.com
```

Your relay is now live at:
```
wss://relay.yourdomain.com
```

---

## 6. Connecting the App to Your Relay

In the GhostLine app → **Connect** page:

1. Tap the **Relay Presets** button (shield icon) or type in the relay URL field.
2. Enter your relay URL, e.g. `wss://ghostline-relay.railway.app`
3. Tap **Test Relay** to verify connectivity before pairing.

The relay URL is saved encrypted in the vault for future connections.

---

## 7. Compile-Time Default Relay (Optional)

To bake your relay URL into the app binary at build time:

```bash
flutter build apk --dart-define=GHOSTLINE_RELAY_URL=wss://relay.yourdomain.com
flutter build ios --dart-define=GHOSTLINE_RELAY_URL=wss://relay.yourdomain.com
```

To also pin the TLS certificate SHA-256 fingerprint:

```bash
flutter build apk \
  --dart-define=GHOSTLINE_RELAY_URL=wss://relay.yourdomain.com \
  --dart-define=RELAY_CERT_SHA256=<sha256-fingerprint-hex>
```

Leaving `RELAY_CERT_SHA256` unset means the relay is validated against the
device's normal trust store only, so any CA-issued certificate for your domain
is accepted. Always set it for production builds.

The client refuses a `ws://` relay unless the host is loopback, the Android
emulator gateway (`10.0.2.2`) or a private LAN range, so a cleartext relay
cannot be configured for a public hostname by accident.

Get the cert pin fingerprint:
```bash
# OpenSSL (replace your domain)
echo | openssl s_client -connect relay.yourdomain.com:443 2>/dev/null \
  | openssl x509 -noout -fingerprint -sha256 \
  | sed 's/SHA256 Fingerprint=//'
```

---

## 8. Security Notes

| Property | Value |
|---|---|
| **Message content** | Never seen in plaintext — every `store` blob arrives sealed by the sender against the recipient's static offline key (`OfflineEnvelopeCipher`, ephemeral X25519 → HKDF-SHA256 → AES-256-GCM). It is deliberately **not** the Double Ratchet, and is never decrypted here |
| **Data retained** | Offline store-and-forward only: opaque blobs until the recipient registers, then dropped. Bounded at 500 messages / 8 MB per recipient, 64 MB across the process, 40 KB per blob, 7-day TTL (purged every 10 minutes). Restarting the relay loses every undelivered blob |
| **Metadata retained while queued** | Recipient Connection ID, sender Connection ID, sender-chosen message id, blob size, arrival time |
| **Identity** | The relay mints a fresh 16-byte nonce per socket and accepts `register` only with an Ed25519 signature over `GHOSTLINE-REGISTER-v1\|<peerId>\|<challenge>`, spent after one use. A captured frame therefore cannot be replayed on a later socket to claim another device's mailbox, and only Ed25519 is accepted so no other key type can claim an id. **Consequence: a client predating this exchange cannot register at all** — both peers and the relay must run the same generation |
| **Rate limiting** | Max 64 KB per signaling message enforced in `signaling_server.js` |
| **Peer count** | In-memory only; resets on server restart |

`stored` blobs are chat content, so memory use scales with how long peers stay
offline. The limits are constants at the top of `signaling_server.js`; lowering
`storedTtlMs` shortens how long an offline recipient's queue survives.

---

## 9. Monitoring

```bash
# PM2 logs (VPS)
pm2 logs ghostline-relay

# Railway logs
railway logs

# Render logs
# Available in Render Dashboard → Logs tab

# Fly.io logs
flyctl logs
```

---

## 10. Troubleshooting

| Issue | Fix |
|---|---|
| App shows "Relay unreachable" | Check TLS cert is valid, nginx is running, port is open |
| `wss://` not working | Ensure nginx `Upgrade` headers are forwarded (see nginx config above) |
| Relay refuses WebSocket | Check `ws` package is installed: `npm install` inside `server/` |
| High memory usage | Each connected peer uses ~1 KB. The in-memory Map is cleaned on disconnect automatically |
| Android rejects `ws://` (not `wss://`) | Android 9+ enforces cleartext traffic policy — always use `wss://` in production |

## 11. TURN and coordinated deployment

Set `TURN_URL`, `TURN_USER`, and `TURN_CRED` with `--dart-define` when building the app for restrictive NAT environments.
Example: `flutter build apk --dart-define=TURN_URL=turn:relay.example.com:3478 --dart-define=TURN_USER=user --dart-define=TURN_CRED=secret`.
The app retains public STUN fallback and adds TURN only when all three values are present.
Use `wss://` for production signaling and keep relay configuration outside source control.
Redeploy the server together with the new app build whenever signaling protocol or relay limits change.

## Release build signing and relay pinning

Release APKs are signed with the keystore described in `android/key.properties`
(git-ignored). Without that file the build falls back to the debug key, which
must not be shipped.

```properties
storeFile=/absolute/path/to/release.jks
storePassword=...
keyAlias=...
keyPassword=...
```

To pin the relay's TLS certificate, pass its SHA-256 DER fingerprint (hex) at
build time:

```bash
openssl s_client -connect <relay-host>:443 </dev/null 2>/dev/null \
  | openssl x509 -outform DER | sha256sum
flutter build apk --release --dart-define=RELAY_CERT_SHA256=<hex>
```

Rotate the build whenever the relay certificate changes.
