# AWS Scanner - Web UI Setup Guide

## Prerequisites

- Node.js 18+
- Docker Desktop (for PostgreSQL + Redis)
- AWS credentials with SecurityAudit permissions

---

## Step 1 — Start the Database and Redis

```bash
# From the aws-scanner root directory
docker-compose up -d

# Verify both are running
docker-compose ps
```

---

## Step 2 — Configure Environment

```bash
# Copy the example env file
cp .env.example api/.env

# Edit api/.env and set:
# 1. Generate JWT secrets:
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
# Paste output as JWT_ACCESS_SECRET and JWT_REFRESH_SECRET (use different values for each)

# 2. Generate encryption key:
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
# Paste as CREDENTIAL_ENCRYPTION_KEY (must be exactly 64 hex chars)

# 3. Set your admin credentials:
# ADMIN_EMAIL=admin@yourcompany.com
# ADMIN_PASSWORD=YourSecurePassword123!
```

---

## Step 3 — Install Dependencies

```bash
# Install root + workspace dependencies
npm install

# Install API dependencies
cd api && npm install && cd ..

# Install Web dependencies
cd web && npm install && cd ..
```

---

## Step 4 — Set Up the Database

```bash
cd api

# Run Prisma migrations (creates all tables)
npx prisma migrate dev --name init

# Generate Prisma client
npx prisma generate

cd ..
```

---

## Step 5 — Start the Application

### Option A: Two separate terminals

**Terminal 1 — API server:**
```bash
cd api
npm run dev
# API running at http://localhost:3001
```

**Terminal 2 — Web frontend:**
```bash
cd web
npm run dev
# Frontend running at http://localhost:5173
```

### Option B: Both at once (from root)
```bash
npm run ui:dev
```

---

## Step 6 — Login

1. Open http://localhost:5173 in your browser
2. Login with the admin credentials you set in `.env`:
   - Email: `admin@example.com` (or your ADMIN_EMAIL)
   - Password: `Admin@123456` (or your ADMIN_PASSWORD)

---

## Step 7 — Add an AWS Account

1. Go to **Accounts** → **Add Account**
2. Enter account name and 12-digit AWS Account ID
3. Go to the account → **Credentials** tab
4. Choose auth method:
   - **Access Key**: Enter AWS Access Key ID + Secret (needs SecurityAudit policy)
   - **Assume Role**: Enter IAM Role ARN (for cross-account access)
5. Click **Verify** to test connectivity

---

## Step 8 — Run Your First Scan

1. From Dashboard or Account detail, click **Run Scan**
2. Select services to scan (or leave all checked)
3. Select regions
4. Click **Start Scan**
5. Watch real-time progress on the scan detail page

---

## Required AWS Permissions

Attach this policy to the IAM user/role used by the scanner:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "sts:GetCallerIdentity",
        "cloudtrail:DescribeTrails",
        "cloudtrail:GetTrailStatus",
        "iam:ListUsers",
        "iam:ListAccessKeys",
        "iam:GetLoginProfile",
        "iam:ListAttachedUserPolicies",
        "iam:GetAccessKeyLastUsed",
        "s3:ListAllMyBuckets",
        "s3:GetEncryptionConfiguration",
        "s3:GetBucketVersioning",
        "s3:GetBucketPublicAccessBlock",
        "s3:GetBucketAcl",
        "s3:GetBucketLogging",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeInstances",
        "rds:DescribeDBInstances",
        "rds:DescribeDBClusters",
        "kms:ListKeys",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "secretsmanager:ListSecrets",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": "*"
    }
  ]
}
```

Or attach the AWS managed policy **SecurityAudit** for broader coverage.

---

## Troubleshooting

**Port already in use:**
```bash
# Kill process on port 3001
npx kill-port 3001
# Kill process on port 5173
npx kill-port 5173
```

**Database connection failed:**
```bash
# Check containers are running
docker-compose ps
# Restart if needed
docker-compose restart postgres
```

**Prisma client not found:**
```bash
cd api && npx prisma generate
```

**Redis connection failed:**
```bash
docker-compose restart redis
```

**View API logs:**
```bash
# Check api/logs/ directory
tail -f api/logs/combined.log
```

**Reset everything:**
```bash
docker-compose down -v   # removes volumes (deletes all data!)
docker-compose up -d
cd api && npx prisma migrate dev
```

---

## Architecture Overview

```
Browser (http://localhost:5173)
    ↓ Vite proxy /api →
API Server (http://localhost:3001)
    ↓ BullMQ jobs →
Scan Worker (same process)
    ↓ AWS SDK →
Your AWS Accounts

PostgreSQL (localhost:5432) — stores scan results, findings, accounts
Redis (localhost:6379) — BullMQ job queue + Socket.IO adapter
Socket.IO — real-time scan progress pushed to browser
```

---

## Default Credentials (change immediately in production!)

| Setting | Default Value |
|---|---|
| Admin Email | admin@example.com |
| Admin Password | Admin@123456 |
| DB User | scanner |
| DB Password | scanner_pass |
| DB Name | aws_scanner |
