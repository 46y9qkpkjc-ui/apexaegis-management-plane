# Windows Agent & Desktop Client Build Guide

## Overview

The enrollment PS1 script downloads and installs the ApexAegis agent MSI. The management plane serves the MSI via `/api/v1/agent/download`.

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

## Step 3: Upload to Management Plane

Upload the MSI/EXE to the management plane server so the enrollment script can download it.

### Option A: Upload via SCP

```powershell
# From your Windows machine
scp dist/ApexAegis-Setup.msi ec2-user@<MGMT_PLANE_IP>:/assets/agent/v0.1.0/
```

### Option B: Upload via S3

```bash
# From any machine with AWS CLI
aws s3 cp ApexAegis-Setup.msi s3://apexaegis-assets/agent/v0.1.0/ApexAegis-Setup.msi
```

### Option C: Direct upload to the container

```bash
# Get the ECS task ID
TASK_ID=$(aws ecs list-tasks --cluster apexaegis-mgmt --service apexaegis-mgmt-plane --region ap-southeast-1 --query 'taskArns[0]' --output text | awk -F/ '{print $NF}')

# Copy file to the running container
docker cp ApexAegis-Setup.msi $(docker ps -q --filter "id=$TASK_ID"):/assets/agent/v0.1.0/
```

---

## Step 4: Verify Download

After uploading, verify the file is accessible:

```bash
# List available versions
curl -k https://drs.apexaegis.app/api/v1/agent/download/versions

# Get latest version info
curl -k https://drs.apexaegis.app/api/v1/agent/download/latest

# Download the MSI
curl -k -O https://drs.apexaegis.app/api/v1/agent/download/v0.1.0/ApexAegis-Setup.msi
```

---

## File Structure on Server

```
/assets/agent/
├── v0.1.0/
│   ├── ApexAegis-Setup.msi
│   └── ApexAegis-Setup.exe
├── v0.2.0/
│   ├── ApexAegis-Setup.msi
│   └── ApexAegis-Setup.exe
└── latest -> v0.2.0/ (symlink, optional)
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
