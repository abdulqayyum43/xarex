# Xarex — Launch Runbook

**Goal:** take the platform from "fully built on a laptop" to "live, charging real customers" in one focused day (≈8 hours including coffee breaks).

This is opinionated. Each step picks one path. If you want to deviate, the rationale for each pick is right above the step so you know what you're trading off.

**Total runtime spend:** ≈ **\$30 / month** to start (Fly.io shared-CPU instance + their managed Postgres). Scales linearly with traffic.

---

## Order of operations (DO NOT skip ahead)

These have hard dependencies:

```
1. Domain  ───►  2. Marketing site  ───►  3. Cloud-brain hosting  ───►
                                                  │
                                                  ▼
                                          4. Live Stripe cutover
                                                  │
                                                  ▼
                                          5. Email (Resend + DNS)
                                                  │
                                                  ▼
                                          6. End-to-end smoke
```

You cannot do step 4 without step 3 (Stripe webhook needs a public URL). You cannot do step 5 without step 1 (DKIM/SPF need DNS). Stick to the order.

---

## Step 1 — Register the domain ⏱ 15 min · 💰 ~$10/year

**Pick: Cloudflare Registrar.** At-cost pricing (~$9.15/yr for `.com`), no upsells, free DNS, free TLS, free DDoS protection, free WHOIS privacy. Anyone telling you to use GoDaddy or Namecheap is wrong in 2026.

1. Go to https://dash.cloudflare.com → Domain Registration → Register Domains.
2. Search `xarex.com`. If taken, the next-best are `xarex.io` ($30/yr) or `xarex.sec` ($150/yr). The marketing site already canonicalises to `xarex.com` (`website/index.html` line 10) — pick something you can live with for years.
3. Buy. Cloudflare auto-creates the zone in your dashboard and turns on free DNS.
4. Verify: `dig +short ns xarex.com` should return Cloudflare nameservers (e.g. `cory.ns.cloudflare.com`).

**Done when:** the domain is in your Cloudflare dashboard under DNS → Records.

---

## Step 2 — Marketing site → Cloudflare Pages ⏱ 30 min · 💰 free

**Pick: Cloudflare Pages.** The marketing site is pure static HTML (`website/index.html` + `website/sample-report.html`). Cloudflare Pages serves it from 300+ edge POPs with no config, zero cost, and you already own the DNS.

### 2a. One-time: put the marketing site in a git repo

If the marketing site isn't already in a git repo, do this once:

```bash
cd C:\Users\abdul\OneDrive\Desktop\projs\phantom\website
git init
git add -A
git commit -m "Initial marketing site"
gh repo create xarex-website --public --source=. --remote=origin --push
```

(Replace `xarex-website` with whatever name you want. Keep it public — easier; the contents are already public on the live site.)

### 2b. Connect to Cloudflare Pages

1. Cloudflare dashboard → Workers & Pages → Create → Pages → Connect to Git.
2. Authorize the GitHub app, pick `xarex-website`.
3. Build settings:
   - **Framework preset:** None
   - **Build command:** *(leave empty)*
   - **Build output directory:** `/`
4. Save and Deploy. First build is ~1 minute. You'll get a `xarex-website.pages.dev` URL.

### 2c. Point xarex.com at Pages

1. In the Pages project → Custom domains → Set up a custom domain → `xarex.com`. Confirm.
2. Cloudflare auto-creates the DNS records and TLS cert (1–3 min to provision).
3. Verify: `curl -sI https://xarex.com | head -3` should return `HTTP/2 200` with `server: cloudflare`.

**Done when:** https://xarex.com loads the marketing site over HTTPS.

---

## Step 3 — Cloud-brain → Fly.io ⏱ 2-3 hours · 💰 ~$25/month

**Pick: Fly.io.** Reasons over Railway / Render / DO App Platform:
- Native Docker (matches our existing setup, no rewrite)
- Managed Postgres on the same private network (no Neon round-trip cost)
- gRPC works out of the box on TCP services (probes need :50051)
- Free TLS via Let's Encrypt
- Pricing is predictable: ~$5/mo for a shared-CPU app + ~$20/mo for the smallest managed Postgres
- Can scale to multi-region later if you grow

You'll need: a credit card on Fly (no charges until you scale past free tier), and `flyctl` installed locally (`curl -L https://fly.io/install.sh | sh`).

### 3a. Provision Postgres first (cloud-brain depends on it)

```bash
flyctl auth login
flyctl postgres create --name xarex-db --region iad --vm-size shared-cpu-1x --volume-size 10
# Save the connection string it prints — looks like:
#   postgres://xarex_db:<password>@xarex-db.internal:5432
```

Stash the connection string in your password manager. You'll paste it in 3a-step-2.

### 3b. Create the cloud-brain Fly app

From the project root:

```bash
cd C:\Users\abdul\OneDrive\Desktop\projs\phantom\cloud-brain
flyctl launch --no-deploy --name xarex --region iad --dockerfile Dockerfile
```

When prompted:
- "Would you like to set up a Postgresql database?" → **No** (we already have one)
- "Would you like to set up an Upstash Redis database?" → **No**
- "Create .dockerignore?" → **Yes**

This creates `fly.toml`. Open it and edit the `[[services]]` block:

```toml
[[services]]
  internal_port = 8005
  protocol = "tcp"

  [[services.ports]]
    handlers = ["http"]
    port = 80
    force_https = true

  [[services.ports]]
    handlers = ["tls", "http"]
    port = 443

# Probe gRPC port
[[services]]
  internal_port = 50051
  protocol = "tcp"

  [[services.ports]]
    port = 50051
```

Then attach the Postgres:

```bash
flyctl postgres attach xarex-db --app xarex
# This sets DATABASE_URL secret on the xarex app automatically.
```

### 3c. Set the remaining secrets

These come from your local `.env` plus a few new prod-only ones. **Do this all in one command** (Fly restarts the app once per `secrets set` call, so batch them):

```bash
flyctl secrets set --app xarex \
  ENVIRONMENT=production \
  PUBLIC_URL=https://xarex.com \
  CORS_ORIGINS=https://xarex.com \
  ADMIN_SECRET="$(openssl rand -hex 32)" \
  SECRET_KEY="$(openssl rand -hex 32)" \
  ANTHROPIC_API_KEY=<your-key> \
  STRIPE_SECRET_KEY=<paste-in-step-4> \
  STRIPE_WEBHOOK_SECRET=<paste-in-step-4> \
  STRIPE_PRICE_STARTER_MONTHLY=<paste-in-step-4> \
  STRIPE_PRICE_STARTER_ANNUAL=<paste-in-step-4> \
  STRIPE_PRICE_PRO_MONTHLY=<paste-in-step-4> \
  STRIPE_PRICE_PRO_ANNUAL=<paste-in-step-4> \
  RESEND_API_KEY=<paste-in-step-5> \
  EMAIL_FROM=hello@xarex.com \
  EMAIL_FROM_NAME="Xarex Security" \
  HIBP_API_KEY=<optional-3.50usd/mo>
```

For now use placeholder values for the Stripe + Resend secrets; you'll re-run `flyctl secrets set` for those after steps 4 + 5. **Do NOT skip `ENVIRONMENT=production`** — it silences the "live Stripe key detected in dev" warning and tightens a few code paths.

### 3d. Deploy

```bash
flyctl deploy --app xarex
```

First deploy takes ~5 minutes (image push + boot). It will print the public URL — looks like `https://xarex.fly.dev`.

### 3e. Point api.xarex.com at the Fly app

In Cloudflare DNS:
- Add a CNAME: `api` → `xarex.fly.dev` → Proxy status **DNS only** (grey cloud).
  - Grey cloud is important for Stripe webhooks + gRPC — Cloudflare's HTTP proxy doesn't handle gRPC over :50051 and adds latency on webhook callbacks.

Then in Fly:

```bash
flyctl certs create api.xarex.com --app xarex
# Cert provisions in 30-60 seconds. Verify:
curl -sI https://api.xarex.com/health
# Expect: HTTP/2 200
```

### 3f. Update the marketing site to point at the new API

Edit `website/index.html` line by line — find every `localhost:8005` reference and replace with `api.xarex.com`. Or, faster:

```bash
cd C:\Users\abdul\OneDrive\Desktop\projs\phantom\website
sed -i 's|http://localhost:8005|https://api.xarex.com|g' index.html
git commit -am "Point marketing site at production API"
git push
```

Cloudflare Pages auto-deploys in ~30 seconds.

**Done when:** https://api.xarex.com/health returns 200, the marketing site at https://xarex.com loads, and clicking "Sign up" hits the live API (check Network tab in browser dev tools).

---

## Step 4 — Stripe live cutover ⏱ 1 hour · 💰 free (until you take payment, then 2.9% + 30¢)

⚠️ **Rotate the `sk_live_…` key** you had sitting in `.env` from the previous session **before** doing anything else. Go to Stripe Dashboard → Developers → API keys → "Roll" on the live key. Old one is dead the moment you click. Save the new one to your password manager.

### 4a. Toggle Stripe Dashboard to Live mode

Top-left toggle in the Stripe dashboard. Everything below is in Live mode.

### 4b. Recreate the 4 prices

The price IDs from test mode do not work in live mode. You must recreate each one and copy the new `price_…` IDs.

1. Products → + Add product.
2. **Starter** product:
   - Add price: $49.00 / month, recurring → save → copy the `price_xxx` ID into your password manager labelled `STRIPE_PRICE_STARTER_MONTHLY`.
   - Add another price: $470.00 / year, recurring → save → `STRIPE_PRICE_STARTER_ANNUAL`.
3. **Pro** product:
   - $199.00 / month → `STRIPE_PRICE_PRO_MONTHLY`.
   - $1910.00 / year → `STRIPE_PRICE_PRO_ANNUAL`.

(Math check: annual = 12 × monthly × 0.8 → 20% off, matches `website/index.html` "Save 20%" copy.)

### 4c. Register the live webhook

1. Stripe Dashboard → Developers → Webhooks → + Add endpoint.
2. Endpoint URL: `https://api.xarex.com/api/billing/webhook/stripe`
3. Listen to events:
   - `checkout.session.completed`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `invoice.payment_failed`
4. Save. Copy the `whsec_…` signing secret into your password manager as `STRIPE_WEBHOOK_SECRET`.

### 4d. Push the live values to Fly

```bash
flyctl secrets set --app xarex \
  STRIPE_SECRET_KEY=sk_live_xxx_new_one \
  STRIPE_WEBHOOK_SECRET=whsec_xxx \
  STRIPE_PRICE_STARTER_MONTHLY=price_xxx \
  STRIPE_PRICE_STARTER_ANNUAL=price_xxx \
  STRIPE_PRICE_PRO_MONTHLY=price_xxx \
  STRIPE_PRICE_PRO_ANNUAL=price_xxx
# Fly restarts the app automatically. ~30 seconds.
```

### 4e. Test the live flow with a real card

1. Open https://xarex.com → click "Start Free Trial" → Starter monthly → enter a real email + a real card.
2. Charge will succeed. You'll get a `cus_…` ID in Stripe.
3. **Immediately refund** in Stripe Dashboard → Payments → [the test charge] → Refund. The refund is free of charge to you (Stripe still keeps the 30¢ fixed fee — call it a launch cost).
4. Verify your provisioned org by querying the new API:
   ```bash
   curl -sH "X-API-Key: <api_key_from_welcome_email>" https://api.xarex.com/api/v1/me
   ```

**Done when:** A real card charge completes, the welcome email arrives (you've done step 5 by now if you're following the runbook order), the API key works against `/api/v1/me`, and you've refunded the test charge.

---

## Step 5 — Resend + DNS (DKIM/SPF/DMARC) ⏱ 1 hour · 💰 free up to 3K emails/mo

### 5a. Create the Resend account + verify the domain

1. Sign up at https://resend.com.
2. Domains → + Add Domain → `xarex.com`.
3. Resend gives you 3-5 DNS records to add (SPF TXT, DKIM TXT, optional DMARC, optional MX for replies).
4. In Cloudflare DNS for `xarex.com`, add every record verbatim. **All as DNS-only (grey cloud).** Wait 5 minutes for propagation.
5. Click "Verify" in Resend. Each record turns green. You're done when all are verified.

### 5b. Generate API key

Resend Dashboard → API Keys → Create → "Production" → Permissions: "Sending access" → `xarex.com` only.

Copy the `re_…` value.

### 5c. Push to Fly

```bash
flyctl secrets set --app xarex \
  RESEND_API_KEY=re_xxx \
  EMAIL_FROM=hello@xarex.com \
  EMAIL_FROM_NAME="Xarex Security"
```

### 5d. Test by triggering a welcome email

The simplest test: do step 4e (a real Stripe checkout) and confirm the welcome email arrives. Or trigger one manually:

```bash
curl -s -X POST -H "X-Admin-Secret: $YOUR_ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  https://api.xarex.com/api/v1/admin/orgs \
  -d '{"name":"DNS Test Org"}'
# Then provision a license to send the welcome email:
# (admin only — your dashboard signup flow does this automatically for real customers)
```

**Done when:** A welcome email arrives in your inbox with the org_id + api_key, **not in spam** (DKIM + SPF are working), and the sender is `Xarex Security <hello@xarex.com>`.

---

## Step 6 — End-to-end smoke ⏱ 30 min

This is the "would my mum be able to use this" test. Do it from a fresh browser profile (incognito) on your phone.

- [ ] Open https://xarex.com on phone. Marketing site loads, looks correct.
- [ ] Click "Start Free Trial" → Starter monthly. Stripe checkout opens.
- [ ] Pay with a real card (you'll refund after).
- [ ] Welcome email arrives within 30 seconds. Click the dashboard link in it.
- [ ] Dashboard loads at https://xarex.com (or wherever you've put it — note: if you want the dashboard at `app.xarex.com` instead of being baked into the marketing-site origin, add another Cloudflare Pages project or route the `/app/*` path. For v1, keeping the dashboard accessible from xarex.com via the sign-in modal is fine).
- [ ] Navigate to Deploy Probe. Org ID + API key are populated.
- [ ] On a second machine (or a Linode/EC2 for $5/month), follow the Linux probe install instructions and run the probe.
- [ ] Within 30 seconds the dashboard banner switches to "1 probe connected".
- [ ] Start a Quick Scan against `127.0.0.1` (just to confirm scan dispatch). Findings stream in.
- [ ] Subdomain Enumeration tab → type `your-test-domain.com` → see real results.
- [ ] Secrets Scanner tab → paste `https://github.com/Plazmaz/leaky-repo` → see ≥5 findings.
- [ ] Refund the test Stripe charge.

**You have launched.**

---

## Post-launch (week 1)

Things to set up the moment customers exist:

1. **Sentry** for error tracking. Free tier covers it. Add `SENTRY_DSN` env var + `pip install sentry-sdk[fastapi]` + one-line init in `main.py`.
2. **Uptime monitoring** — UptimeRobot (free) pinging `https://api.xarex.com/health` every 5 min. Email alert on failure.
3. **Fly metrics** — `flyctl dashboard metrics --app xarex` shows you CPU, memory, request rate. Pin it to a browser tab on launch day.
4. **Stripe email alerts** — Stripe Dashboard → Settings → Team & security → Notifications → enable "Successful payment" + "Failed payment" + "Refund". You want to know the moment money moves.
5. **Postgres backups** — Fly Postgres auto-backs up daily by default. Verify in `flyctl postgres list` → click the cluster → Backups.

---

## Rollback plan

If something is on fire and you need to roll back:

```bash
# Roll back the cloud-brain to the previous deployment:
flyctl releases --app xarex                  # find the release ID before this one
flyctl releases rollback <release-id> --app xarex

# Roll back the marketing site:
# Cloudflare Pages dashboard → xarex-website → Deployments → Rollback to the previous one.

# Take Stripe down without losing data:
# Stripe Dashboard → Developers → Webhooks → click the endpoint → Disable.
# (Charges still process; provisioning is paused until you re-enable.)
```

---

## Cost summary (your first month)

| Line item | Cost |
|---|---|
| Domain (Cloudflare) | ~$10/year ≈ $0.85/mo |
| Cloudflare Pages | $0 |
| Fly cloud-brain (shared-cpu-1x, 256 MB) | $1.94/mo |
| Fly Postgres (shared-cpu-1x, 10 GB) | $19.39/mo |
| Resend | $0 (under 3K emails/mo) |
| Stripe | 2.9% + 30¢ per successful charge only |
| **Total fixed monthly** | **~$22/month** |

Anthropic API for AI analysis is variable per scan (pay-as-you-go). Budget ~$5-20/mo to start; tighten via the `ANTHROPIC_API_KEY` rate limits if it surprises you.

You're cheaper than a single Nessus Pro seat ($332/mo per your own marketing copy) every month from day one. Even at 1 customer on Starter ($49/mo), you're net positive after Stripe fees and infra. **You have a business.**
