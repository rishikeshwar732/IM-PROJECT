# GuardRail AI – How to Execute the Project

Follow these steps in order. All commands assume you are in the project root: `d:\KLH\SEM 6\IM`.

---

## Step 1: Open terminal in project folder

```powershell
cd "d:\KLH\SEM 6\IM"
```

---

## Step 2: Create and activate a virtual environment (recommended)

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

You should see `(.venv)` in your prompt.

---

## Step 3: Install dependencies

```powershell
pip install -r requirements.txt
```

---

## Step 4 (recommended): Run the website – upload file, get danger message + safe result

1. **Start the backend** (serves the UI and the scan/remediate API):

   ```powershell
   python backend\app.py
   ```

2. **Open in browser:**  
   http://localhost:5000

3. **Upload a policy file:**
   - Click **Choose file** and select a cloud policy (e.g. from `samples/` – try `aws_s3_bad.json` or `azure_nsg_bad.json`).
   - Click **Scan & remediate**.

4. **You will see:**
   - A **backend result** message: either *"This file is dangerous: …"* (with a list of findings) or *"This file is safe"*.
   - If the file was dangerous, a **Safe result** section with the AI-remediated policy and a **Download safe file** link.

The backend scans the file for dangerous patterns (public S3, wildcard IAM, open SSH, etc.) and, when issues are found, uses AI (or rule-based fallback) to produce a safe version.

---

## Step 5: Run the Security Scanner (CLI)

Scans all sample policies in `samples/` and writes findings + metrics to JSON:

```powershell
python core\scanner.py --path samples --output scan_results.json
```

**What happens:** The scanner checks:
- AWS S3 policies (public bucket risk)
- AWS IAM policies (wildcard permissions)
- Azure NSG rules (open SSH from internet)

**Output:** `scan_results.json` in the project root. Open it to see findings, `time_saved_hours`, and `compliance_score` per file.

---

## Step 6: Run the AI Advisor (optional)

Takes the scan results and generates “innovation-friendly” remediation steps. Works **without** an API key (uses built-in fallback text).

```powershell
python ai_advisor\advisor.py --scan-results scan_results.json --output advisor_output.json
```

**With Gemini API** (optional, for real LLM advice):

```powershell
$env:GOOGLE_API_KEY = "your-api-key-here"
python ai_advisor\advisor.py --scan-results scan_results.json --output advisor_output.json
```

**Output:** `advisor_output.json` with `advice` text and `management_metrics`.

---

## Step 7: Database (optional – only if PostgreSQL is installed)

**6a. Set database environment variables** (if not using defaults):

```powershell
$env:DB_HOST = "localhost"
$env:DB_PORT = "5432"
$env:DB_NAME = "guardrail_ai"
$env:DB_USER = "guardrail_ai"
$env:DB_PASSWORD = "guardrail_ai"
```

**6b. Create the database** (e.g. in psql: `CREATE DATABASE guardrail_ai;`), then apply schema:

```powershell
python database\db_manager.py init --schema database\schema.sql
```

**6c. Save scan results into the database:**

```powershell
python database\db_manager.py save --project "GuardRail-AI-Demo" --scan-results scan_results.json
```

**6d. Get aggregated metrics for reporting:**

```powershell
python database\db_manager.py metrics
```

---

## Step 8: Open the Dashboard (if not using the website in Step 4)

Open the web UI in your browser:

- **Option A:** Double-click `ui\index.html`
- **Option B:** Right-click `ui\index.html` → Open with → your browser
- **Option C:** From terminal: `start ui\index.html`

The dashboard shows:
- **Innovation Velocity Score** (2880×)
- **Time Saved Calculator** – enter “policies per week” to see hours returned to innovation
- Shift-left governance narrative

---

## Quick Reference – Website flow (upload → danger message → safe result)

| Step | Command / action |
|------|------------------|
| 1 | `cd "d:\KLH\SEM 6\IM"` |
| 2 | `python -m venv .venv` then `.\.venv\Scripts\Activate.ps1` |
| 3 | `pip install -r requirements.txt` |
| 4 | `python backend\app.py` |
| 5 | Open http://localhost:5000 → upload a policy file → click **Scan & remediate** → see danger message and download safe result |

## Quick Reference – CLI only (no DB, no Gemini)

| Step | Command |
|------|---------|
| 1 | `cd "d:\KLH\SEM 6\IM"` |
| 2 | `python -m venv .venv` then `.\.venv\Scripts\Activate.ps1` |
| 3 | `pip install -r requirements.txt` |
| 4 | `python core\scanner.py --path samples --output scan_results.json` |
| 5 | `python ai_advisor\advisor.py --scan-results scan_results.json -o advisor_output.json` |
| 6 | Open `ui\index.html` in browser (or run `python backend\app.py` and open http://localhost:5000) |

---

## Troubleshooting

- **“python not found”** – Use `py -m venv .venv` and `py core\scanner.py ...` instead of `python`.
- **Activate.ps1 cannot be loaded** – Run `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` once, then try activating again.
- **Database errors** – Skip Step 6; the scanner, advisor, and UI work without PostgreSQL.
