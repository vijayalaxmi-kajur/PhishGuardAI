# PhishGuardAI — Production Deployment & Cloud Architecture Guide

This guide details how to configure, containerize, and deploy the PhishGuardAI SaaS and Threat Intelligence platform to enterprise cloud environments.

---

## 1. Architecture Overview

```
                                    [ Internet Users / API Clients ]
                                                   │
                                                   ▼
                                      [ Cloudflare DDoS & CDN ]
                                                   │
                                                   ▼
                                 [ NGINX Reverse Proxy (SSL / TLS 1.3) ]
                                                   │
                                                   ▼
                                   [ Gunicorn WSGI Master Process ]
                                   (4-8 Gevent/Sync Worker Processes)
                                                   │
                                                   ▼
                                        [ PhishGuardAI App ]
                           ┌───────────────────────┼───────────────────────┐
                           ▼                       ▼                       ▼
                  [ PostgreSQL 16 ]           [ Redis 7 ]           [ Threat Feeds ]
                 (Multi-tenant DB)        (Reputation Cache)       (30-min Auto-Sync)
```

---

## 2. Docker & Docker Compose Deployment (Recommended)

PhishGuardAI is fully containerized with a production multi-stage `Dockerfile` and `docker-compose.yml`.

### Quickstart
1. Clone the repository and configure your environment:
   ```bash
   cp .env.production.example .env
   # Edit .env with your PostgreSQL credentials, Secret Key, and Stripe tokens
   ```

2. Build and launch the container cluster:
   ```bash
   docker-compose up -d --build
   ```

3. Verify service health:
   ```bash
   curl http://localhost:5000/api/health
   ```

---

## 3. Cloud Provider Deployment Guides

### Option A: Render (PaaS)
1. Fork or push this repository to GitHub.
2. In the Render Dashboard, click **New Web Service** and connect your repo.
3. Configure settings:
   - **Environment:** `Docker` (or `Python 3`)
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn wsgi:app -w 4 -b 0.0.0.0:$PORT`
4. Attach a **Render Managed PostgreSQL** and **Render Managed Redis** instance.
5. Add the environment variables from `.env.production.example`.

### Option B: AWS ECS / Fargate (Containerized Microservices)
1. Authenticate with AWS ECR:
   ```bash
   aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin <YOUR_ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com
   ```
2. Build and push image:
   ```bash
   docker build -t phishguard:latest .
   docker tag phishguard:latest <YOUR_ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/phishguard:latest
   docker push <YOUR_ACCOUNT_ID>.dkr.ecr.us-east-1.amazonaws.com/phishguard:latest
   ```
3. Provision an **Amazon Aurora PostgreSQL** cluster and **Amazon ElastiCache for Redis**.
4. Create an ECS Task Definition with 1 vCPU and 2GB RAM.
5. Attach an Application Load Balancer (ALB) with an AWS Certificate Manager (ACM) SSL certificate.

### Option C: DigitalOcean App Platform
1. Select **Deploy from GitHub**.
2. DigitalOcean automatically detects the `Dockerfile`.
3. Provision attached Managed PostgreSQL and Managed Redis components.
4. Scale CPU/RAM as traffic scales.

---

## 4. Production Security Checklist

- [ ] **HTTPS / TLS 1.3:** Enforce strict HTTPS using Let's Encrypt or Cloudflare Full SSL.
- [ ] **Environment Variables:** Set strong secrets for `SECRET_KEY` (64+ random hex bytes) and `STRIPE_WEBHOOK_SECRET`.
- [ ] **CORS Configuration:** Restrict allowed CORS origins in `app.py` from `*` to your exact front-end and browser extension domain.
- [ ] **Database Connection Pooling:** In high-concurrency production, use PgBouncer in front of PostgreSQL.
- [ ] **Automated Backups:** Schedule daily snapshots of PostgreSQL databases.
- [ ] **Health Monitoring:** Point Pingdom, Datadog, or UptimeRobot to `/api/health` with a 30-second interval.

---

## 5. Preflight Verification Script

Before switching live traffic to any deployment, run the automated preflight audit:
```bash
python scripts/preflight_check.py
```
Ensure all items report `[✓ PASS]` before directing production traffic.

