# Self-hosting SendBeam

SendBeam ships as a single container that serves the web app, the signaling
endpoint, and the encrypted relay from one process on one port. This guide
covers running it yourself, including TLS, reverse proxies, STUN/TURN, rate
limiting, and relay quotas.

## Quickstart

Requires Docker (or any OCI-compatible runtime) and nothing else:

```sh
docker run -d --name sendbeam -p 8443:8443 ghcr.io/akshay7273/sendbeam
```

Then open <http://localhost:8443> and send your first file. Plain HTTP on
`localhost` is a browser secure context, so WebRTC works; for anything
reachable from another machine, put TLS in front (see [TLS & Reverse Proxies](#tls--reverse-proxies)).

### Health & Readiness Endpoints

- **Liveness probe:** `GET /healthz` returns `{"status":"ok"}` (HTTP 200). The container image includes a `HEALTHCHECK` against this endpoint.
- **Readiness probe:** `GET /readyz` returns `{"status":"ready","rooms":N,"connections":M,"draining":false}` (HTTP 200) during normal operation. When the server begins graceful shutdown, it transitions to `{"status":"draining",...}` (HTTP 503 Service Unavailable) so load balancers stop sending new ingress traffic while active relay transfers drain.

### Prometheus Metrics

- **Metrics endpoint:** `GET /metrics` serves Prometheus text metrics:
  - `sendbeam_rooms`: Active signaling rooms (gauge)
  - `sendbeam_active_connections`: Active WebSocket connections (gauge)
  - `sendbeam_connections_total`: Total accepted WebSocket connections (counter)
  - `sendbeam_rooms_created_total`: Total rooms created since start (counter)
  - `sendbeam_rooms_paired_total`: Total rooms paired since start (counter)
  - `sendbeam_rooms_reaped_total`: Total idle rooms reaped (counter)
  - `sendbeam_relay_bytes_total`: Ciphertext bytes relayed (counter)
  - `sendbeam_errors_total{code="..."}`: Error and refusal counts by code (counter)
  - `sendbeam_messages_total{type="..."}`: Signaling and control messages by type (counter)

All metrics expose aggregate counters and byte totals only — **zero IP addresses, zero room codes, zero client IDs, and zero content metadata are ever exposed**.

## What the image contains

- The built web bundle (`apps/web`), served with SPA fallback by `sendbeamd`
- The blind signaling endpoint (`/ws`) and the encrypted relay
- CA certificates for outbound TLS
- Runs as an unprivileged user (`sendbeam`, uid 10001); no shell access

The web app defaults to the signaling endpoint at `/ws` on its own origin,
so web + signaling + relay all share the published port.

## Environment variables

| Variable                                  | Default       | Purpose                                                                                                                                                                       |
| ----------------------------------------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SENDBEAM_ADDR`                           | `:8443`       | Listen address.                                                                                                                                                               |
| `SENDBEAM_TLS_CERT` / `_TLS_KEY`          | unset         | PEM cert/key paths; when both are set `sendbeamd` terminates TLS itself.                                                                                                      |
| `SENDBEAM_WEB_DIR`                        | unset         | Directory of the built web bundle to serve; set to `/srv/web` in the image.                                                                                                   |
| `SENDBEAM_WEB_DEV_PROXY`                  | unset         | Vite dev-server URL to proxy to (development only; overrides `SENDBEAM_WEB_DIR`).                                                                                             |
| `SENDBEAM_ALLOWED_ORIGINS`                | empty         | Comma-separated WSS origin allowlist. Empty allows only same-origin browser sockets; native CLI clients (no `Origin` header) are always allowed.                              |
| `SENDBEAM_TRUSTED_PROXIES`                | empty         | Comma-separated CIDRs/IPs of trusted upstream reverse proxies (e.g. `127.0.0.1/32,10.0.0.0/8`). Enables secure `X-Forwarded-For` and `CF-Connecting-IP` client IP extraction. |
| `SENDBEAM_RATE_LIMIT_ENABLED`             | `true`        | Master toggle for token-bucket rate limiters and concurrency quotas. Set to `false` for private unconstrained LAN operation.                                                  |
| `SENDBEAM_MAX_CONNECTIONS`                | `10000`       | Global ceiling for concurrent active WebSocket connections.                                                                                                                   |
| `SENDBEAM_MAX_CONNS_PER_IP`               | `32`          | Maximum concurrent active WebSocket connections per client IP.                                                                                                                |
| `SENDBEAM_MAX_ROOMS`                      | `5000`        | Global ceiling for concurrent active signaling rooms.                                                                                                                         |
| `SENDBEAM_CONN_BURST` / `_PER_SEC`        | `16` / `8.0`  | Token-bucket connection rate limit per client IP at WebSocket upgrade.                                                                                                        |
| `SENDBEAM_ROOM_CREATE_BURST` / `_PER_SEC` | `8` / `2.0`   | Token-bucket room creation rate limit per client IP.                                                                                                                          |
| `SENDBEAM_JOIN_FAIL_BURST` / `_PER_SEC`   | `10` / `1.0`  | Token-bucket anti-brute-force rate limit for failed room join attempts per client IP.                                                                                         |
| `SENDBEAM_DRAIN_TIMEOUT`                  | `15s`         | Maximum duration to wait for active transfers to drain during graceful shutdown.                                                                                              |
| `SENDBEAM_SHUTDOWN_TIMEOUT`               | `15s`         | Maximum total duration for HTTP server shutdown.                                                                                                                              |
| `SENDBEAM_LOG_FORMAT`                     | `text`        | Structured log format: `text` or `json`.                                                                                                                                      |
| `SENDBEAM_LOG_LEVEL`                      | `info`        | Structured log level: `debug`, `info`, `warn`, `error`. Zero-PII policy applies at all levels.                                                                                |
| `SENDBEAM_ICE_SERVERS`                    | unset         | Comma-separated STUN (or TURN) URLs published to the web app via `/config.json`; unset keeps the bundled Google STUN default.                                                 |
| `SENDBEAM_SIGNAL_IDLE_TIMEOUT`            | `10m`         | Close a socket silent this long; also bounds how long an unpaired room lingers before being reaped.                                                                           |
| `SENDBEAM_SIGNAL_MAX_MESSAGE_BYTES`       | `65536`       | Cap on a single inbound signaling message (64 KiB).                                                                                                                           |
| `SENDBEAM_RELAY_MAX_FRAME_BYTES`          | `131072`      | Cap on a single relay frame (128 KiB).                                                                                                                                        |
| `SENDBEAM_RELAY_WINDOW_BYTES`             | `1048576`     | In-flight window per relay connection (1 MiB).                                                                                                                                |
| `SENDBEAM_RELAY_QUEUE_BYTES`              | `2097152`     | Bounded per-connection relay queue (2 MiB).                                                                                                                                   |
| `SENDBEAM_RELAY_BURST_BYTES`              | `8388608`     | Token-bucket burst for relay throughput (8 MiB).                                                                                                                              |
| `SENDBEAM_RELAY_BYTES_PER_SEC`            | `33554432`    | Relay throughput ceiling per session (32 MiB/s by default).                                                                                                                   |
| `SENDBEAM_RELAY_MAX_SESSION_BYTES`        | `17179869184` | Lifetime bytes relayed per session (16 GiB).                                                                                                                                  |

Durations use Go's `time.ParseDuration` syntax (`30s`, `5m`); sizes use
plain integers (bytes).

## TLS & Reverse Proxies

### Option 1: Reverse proxy (recommended)

Use Caddy, Nginx, Traefik, or Cloudflare to handle TLS certificate issuance and renewal, proxying plain HTTP to SendBeam:

#### Caddy

```caddy
send.example.com {
    reverse_proxy 127.0.0.1:8443 {
        header_up X-Forwarded-For {remote_host}
        header_up X-Forwarded-Proto {scheme}
    }
}
```

```sh
docker run -d --name sendbeam -p 127.0.0.1:8443:8443 \
  -e SENDBEAM_ALLOWED_ORIGINS=https://send.example.com \
  -e SENDBEAM_TRUSTED_PROXIES=127.0.0.1/32,::1/128 \
  ghcr.io/akshay7273/sendbeam
```

#### Nginx

```nginx
server {
    listen 443 ssl http2;
    server_name send.example.com;

    ssl_certificate /etc/letsencrypt/live/send.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/send.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8443;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 600s;
        proxy_send_timeout 600s;
    }
}
```

When behind a reverse proxy:

1. Set `SENDBEAM_ALLOWED_ORIGINS` to your public HTTPS origin (e.g. `https://send.example.com`).
2. Set `SENDBEAM_TRUSTED_PROXIES` to the proxy's IP/subnet (e.g. `127.0.0.1/32` or your private Docker network `172.16.0.0/12`) so client IP extraction safely parses `X-Forwarded-For` or `CF-Connecting-IP`.

### Option 2: Terminate TLS directly at `sendbeamd`

Mount your PEM certificate and private key into the container:

```sh
docker run -d --name sendbeam \
  -p 8443:8443 \
  -v /etc/letsencrypt/live/example.com/fullchain.pem:/certs/fullchain.pem:ro \
  -v /etc/letsencrypt/live/example.com/privkey.pem:/certs/privkey.pem:ro \
  -e SENDBEAM_TLS_CERT=/certs/fullchain.pem \
  -e SENDBEAM_TLS_KEY=/certs/privkey.pem \
  -e SENDBEAM_ALLOWED_ORIGINS=https://example.com \
  ghcr.io/akshay7273/sendbeam
```

Minimum TLS 1.2 is enforced server-side.

## STUN and TURN

- **STUN** — both clients use Google's STUN (`stun:stun.l.google.com:19302`)
  by default for external candidate discovery. The CLI points at your own
  STUN servers with the repeatable `--ice-server` flag. The web bundle's ICE
  config is configurable at runtime: the server publishes an operator-chosen
  STUN list via `/config.json` (from `SENDBEAM_ICE_SERVERS`), which the web
  app fetches on load, validates, and passes to `RTCPeerConnection`.
- **TURN** — optional. Operators who need better restrictive-network
  reachability publish TURN URLs (alongside STUN) in `SENDBEAM_ICE_SERVERS`;
  clients then gather a TURN relayed candidate and race it against direct
  candidates. TURN credentials are served with `Cache-Control: no-cache` and
  clients never reuse a fetched config past the 15-minute credential TTL, so
  operators may serve short-lived credentials without embedding them in the
  web bundle. **Default self-hosting requires no TURN service**: when no TURN is
  configured, restricted pairs fall back to the app-layer **encrypted relay**
  through this same server, which fills the TURN role without a second service.
  The relay (and a TURN server, when used) never sees plaintext: payloads are
  end-to-end encrypted and framed inside WebSocket messages, and a TURN server
  observes only encrypted WebRTC datagrams. See `docs/adr/0003-path-selection.md`.

## Relay & Rate Limits

Every layer of the public server is bounded:

| Protection             | Mechanism                  | Default                    |
| ---------------------- | -------------------------- | -------------------------- |
| Connection rate        | Token bucket per IP        | 16 burst, 8 / sec          |
| Connection concurrency | Active connection quota    | 32 per IP, 10,000 global   |
| Room creation rate     | Token bucket per IP        | 8 burst, 2.0 / sec         |
| Room capacity          | Global room ceiling        | 5,000 rooms                |
| Room code brute force  | Failed join penalty bucket | 10 burst, 1.0 / sec refill |
| Relay frame size       | Hard frame limit           | 128 KiB                    |
| Relay window           | In-flight credit window    | 1 MiB                      |
| Relay queue            | Buffer ceiling per socket  | 2 MiB                      |
| Relay throughput       | Token bucket per session   | 32 MiB/s                   |
| Session byte ceiling   | Lifetime relay bytes       | 16 GiB                     |

These bounds protect the instance from memory exhaustion, socket starvation, and code-guessing scans while providing full throughput for legitimate transfers.

## Security & Privacy Invariants

- Pairing is authenticated via SPAKE2; the server never sees the word code or plaintext payloads.
- Structured server logs contain room numbers, error codes, and message counts only — **zero client IPs, zero invite codes, zero filenames, and zero cryptographic keys**.
- `SENDBEAM_ALLOWED_ORIGINS` blocks cross-site WebSocket hijacking; always set it when operating publicly.
- Reverse proxy IP extraction ignores `X-Forwarded-For` from untrusted direct connections to prevent IP spoofing.

## Updating

```sh
docker pull ghcr.io/akshay7273/sendbeam
docker restart sendbeam
```

The container is stateless; nothing persists inside it, so restarts and rollouts are safe at any time.
