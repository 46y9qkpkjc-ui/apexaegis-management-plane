# Windows Agent & Desktop Client Build Guide

## Overview

The enrollment PS1 script downloads and installs the ApexAegis agent MSI. The management plane serves the MSI via `/api/v1/agent/download`.

**Important:** The management plane runs on **ECS Fargate** (no persistent local disk). Agent files must be stored in **S3** and served from there.

---

## Step 1: Build the Agent Binary

The agent is a Go binary. Build it on Windows:

```powershell
# Clone the agent repo
git clone https://github.com/46y9qkpkjc-ui/apexaegis-agent.git
cd apexaegis-agent

# Build Windows agent
$env:GOOS = "windows"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
go build -ldflags="-s -w -H=windowsgui -X main.version=0.1.0" -o dist/apexaegis-agent-windows-amd64.exe ./cmd/agent
```

Output: `dist/apexaegis-agent-windows-amd64.exe`

---

## Step 2: Build the Desktop Client (Tauri + NSIS)

The desktop client wraps the agent in a Tauri app with an NSIS installer.

### Prerequisites

- Node.js 20+
- Rust (https://rustup.rs)
- Visual Studio Build Tools 2022 with "Desktop development with C++"
- nasm (https://nasm.us) — required by aws-lc-rs for PQ crypto

### Build Steps

```powershell
# Clone both repos as siblings
mkdir ApexAegis-Windows
cd ApexAegis-Windows
git clone https://github.com/46y9qkpkjc-ui/apexaegis-agent.git
git clone https://github.com/46y9qkpkjc-ui/apexaegis-desktop-client.git

# Build the agent binary first (see Step 1)
cd apexaegis-agent
# ... build agent ...
Copy-Item dist/apexaegis-agent-windows-amd64.exe ..\apexaegis-desktop-client\public\
cd ..

# Build the desktop client
cd apexaegis-desktop-client

# Install Rust target
rustup target add x86_64-pc-windows-msvc

# Install dependencies
npm ci

# Build Next.js frontend
npm run build

# Build Tauri app (produces NSIS installer)
npm run tauri build -- --target x86_64-pc-windows-msvc
```

### Output

The NSIS installer is at:
```
src-tauri/target/x86_64-pc-windows-msvc/release/bundle/nsis/ApexAegis_0.1.0_x64-setup.exe
```

---

## Step 3: Upload to S3

The management plane runs on ECS Fargate with no persistent disk. Upload the MSI to S3.

### AWS Account: `184353710603`
### Region: `ap-southeast-1`
### S3 Bucket: `apexaegis-agent-assets`

```powershell
# From Windows (AWS CLI v2 required)
aws configure  # Enter your AWS credentials if not already configured

# Upload the MSI
aws s3 cp ApexAegis-Setup.msi s3://apexaegis-agent-assets/v0.1.0/ApexAegis-Setup.msi --region ap-southeast-1

# Upload the EXE (optional)
aws s3 cp ApexAegis-Setup.exe s3://apexaegis-agent-assets/v0.1.0/ApexAegis-Setup.exe --region ap-southeast-1
```

### Create the S3 Bucket (if it doesn't exist)

```bash
aws s3 mb s3://apexaegis-agent-assets --region ap-southeast-1
```

### Set Public Read (for download access)

```bash
aws s3api put-bucket-policy --bucket apexaegis-agent-assets --region ap-southeast-1 --policy '{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PublicRead",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::apexaegis-agent-assets/*"
    }
  ]
}'
```

---

## Step 4: Verify Download

After uploading, verify the file is accessible:

```bash
# List available versions
curl -k https://drs.apexaegis.app/api/v1/agent/download/versions

# Get latest version info
curl -k https://drs.apexaegis.app/api/v1/agent/download/latest

# Download the MSI directly from S3 (bypassing API)
curl -k -O https://apexaegis-agent-assets.s3.ap-southeast-1.amazonaws.com/v0.1.0/ApexAegis-Setup.msi
```

---

## S3 File Structure

```
s3://apexaegis-agent-assets/
├── v0.1.0/
│   ├── ApexAegis-Setup.msi
│   └── ApexAegis-Setup.exe
├── v0.2.0/
│   ├── ApexAegis-Setup.msi
│   └── ApexAegis-Setup.exe
└── latest/ (symlink or copy, optional)
```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/agent/download/versions` | GET | List all versions and files |
| `/api/v1/agent/download/latest` | GET | Get latest version info |
| `/api/v1/agent/download/:version/:filename` | GET | Download a specific file |

### Example Response

```json
{
  "version": "v0.1.0",
  "files": [
    {
      "version": "v0.1.0",
      "filename": "ApexAegis-Setup.msi",
      "size": 15728640,
      "path": "/api/v1/agent/download/v0.1.0/ApexAegis-Setup.msi"
    }
  ]
}
```

---

## Environment Variable

The agent assets directory is configured via:
```
AGENT_ASSETS_DIR=/assets/agent
```

Default: `/assets/agent`

**Note:** On ECS Fargate, this directory is ephemeral. For persistent storage, use S3 and update the download URL in the PS1 script to point directly to S3.

---

## Quick Reference (AWS Credentials)

- **AWS Account:** `184353710603`
- **Region:** `ap-southeast-1`
- **S3 Bucket:** `apexaegis-agent-assets`
- **ECS Cluster:** `apexaegis-mgmt`
- **ECS Service:** `apexaegis-mgmt-plane`
