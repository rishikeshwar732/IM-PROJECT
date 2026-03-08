## GuardRail AI – Self-Service Security Auditor

GuardRail AI is a lightweight prototype that demonstrates how **automated security governance can increase innovation velocity** for cloud teams. It does this by shifting cloud policy checks (AWS S3, IAM and Azure NSG) **left** into a self-service workflow that developers can run in seconds, instead of waiting hours for manual reviews.

The core idea: **every time a developer touches a cloud policy, the auditor runs automatically**, producing machine-readable findings, leadership-ready metrics and AI-generated remediation guidance that keeps experimentation fast but safe.

---

### 1. Architecture Overview

- **`core/scanner.py`**  
  Python engine that scans JSON/YAML policies for:
  - Public AWS S3 buckets.
  - Overly permissive AWS IAM policies (wildcards on `Action` and `Resource`).
  - Azure NSG rules that expose SSH (22) to the internet.
  It emits structured findings plus management metrics (time saved, compliance score).

- **`ai_advisor/advisor.py`**  
  Takes the scanner output and calls a **Gemini / LLM API** (via `google-generativeai`) to generate:
  - “Innovation-friendly” remediation steps.
  - Executive summaries framed around speed, safety and developer experience.
  A deterministic fallback is provided if no API key is configured.

- **`database/schema.sql` & `database/db_manager.py`**  
  PostgreSQL schema and helper script that log:
  - Per-scan metrics (time saved, compliance score, total findings).
  - Per-finding details (provider, service, severity, message).
  It also exposes an `innovation_velocity_metrics` view that aggregates data into leadership KPIs.

- **`samples/`**  
  Six sample policies:
  - 3 “bad” (public S3, wildcard IAM, open SSH NSG).
  - 3 “good” equivalents for contrast.

- **`ui/index.html`**  
  A Tailwind-based dashboard that visualises:
  - **Innovation Velocity Score** (automated vs manual scans per hour).
  - A time-saved calculator (hours per week returned to innovation).
  - Conceptual compliance trends linked to the database view.

---

### 2. Management Metrics – Time Saved & Innovation Velocity

To make the business case clear, the prototype bakes in explicit assumptions:

- **Manual audit duration**: \( 4.0 \) hours per policy review.  
- **Automated audit duration**: \( 5 \) seconds per policy scan.

From these, we derive:

- **Time Saved per Scan (hours)**  
  \[
  \text{time\_saved\_hours} = 4.0 - \frac{5}{3600}
  \]

- **Manual Scans per Hour**  
  \[
  \text{manual\_scans\_per\_hour} = \frac{1}{4.0} = 0.25
  \]

- **Automated Scans per Hour**  
  \[
  \text{automated\_scans\_per\_hour} = \frac{3600}{5} = 720
  \]

- **Innovation Velocity Score (Multiplier)**  
  \[
  \text{innovation\_velocity\_multiplier} =
  \frac{\text{automated\_scans\_per\_hour}}{\text{manual\_scans\_per\_hour}} = 2880\times
  \]

These metrics are:

- Calculated per scan in `core/scanner.py` as part of the `ScanMetrics` object.
- Persisted to PostgreSQL via `database/db_manager.py`.
- Aggregated in the `innovation_velocity_metrics` view for reporting.
- Surfaced visually in the `ui/index.html` dashboard.

**Key narrative for leadership:**  
> “For every manual policy review we replace with this self-service auditor, we free ~4 hours of expert time while enabling almost three thousand times more safe experiments per hour.”

---

### 3. Shift-Left Security – Management Theory

Traditional cloud governance relies on:

- Central security teams manually reviewing policies.
- Long approval queues.
- Late-stage feedback (after design and implementation).

This has two predictable outcomes:

- **Security fatigue** – reviewers are overwhelmed with low-level checks.  
- **Innovation drag** – developers wait days or weeks to get a “yes”.

GuardRail AI embodies a **shift-left, guardrail-based** model:

- **Self-Service Checks**  
  - Developers run the auditor locally or in CI on every policy change.
  - Feedback loops compress from days to seconds.

- **Guardrails Instead of Gates**  
  - Opinionated patterns are encoded as regex/logic in `core/scanner.py`.
  - “Secure by default” templates (e.g. private S3, scoped IAM, JIT SSH) become the easiest path.

- **Metrics, Not Anecdotes**  
  - Time saved is measured explicitly in hours.
  - Compliance scores trend over time for each team/project.
  - Innovation Velocity Score quantifies how much faster teams can safely iterate.

This moves security from being a **serial gate** to a **parallel enabler**:

- Security teams design and maintain the rules and templates.  
- Developers consume them automatically via the auditor.  
- Management monitors **outcomes** (time saved, compliance trend) instead of micro-managing every review.

---

### 4. Running the Prototype

1. **Install dependencies**

   ```bash
   pip install -r requirements.txt
   ```

2. **Run the scanner against the sample policies**

   ```bash
   python core/scanner.py --path samples --output scan_results.json
   ```

   This produces `scan_results.json` containing:

   - File-level findings.
   - Time-saved metrics.
   - Compliance scores.

3. **Generate AI-powered remediation guidance (optional)**

   - Set your Gemini API key:

     ```bash
     set GOOGLE_API_KEY=YOUR_KEY_HERE  # PowerShell / Windows
     ```

   - Run the advisor:

     ```bash
     python ai_advisor/advisor.py --scan-results scan_results.json --output advisor_output.json
     ```

   - If no API key is configured, a deterministic “innovation-friendly” fallback is used.

4. **Persist metrics to PostgreSQL (optional but recommended for demos)**

   - Ensure PostgreSQL is running and environment variables are set:

     - `DB_HOST`, `DB_PORT`, `DB_NAME`, `DB_USER`, `DB_PASSWORD`

   - Initialise the schema:

     ```bash
     python database/db_manager.py init --schema database/schema.sql
     ```

   - Save scan results:

     ```bash
     python database/db_manager.py save --project "GuardRail-AI-Demo" --scan-results scan_results.json
     ```

   - Query high-level metrics:

     ```bash
     python database/db_manager.py metrics
     ```

5. **Open the dashboard**

   - Open `ui/index.html` in a browser.
   - Use the built-in calculator to show:
     - Hours of manual review avoided per week.
     - The fixed Innovation Velocity Score (2880×) based on the 4h vs 5s assumption.

---

### 5. How This Prototype Proves the Thesis

From a management perspective, this prototype demonstrates that:

- **Security findings are machine-readable**, enabling full automation in CI/CD.
- **Time saved is explicitly quantified** in hours and surfaced as a KPI.
- **Innovation velocity is measurable**, not just a vague promise to “move faster”.

In a production setting, you would:

- Extend the scanner to additional services (RDS, Key Vault, KMS, etc.).
- Wire the database to a live BI tool or internal portal.
- Enforce policies via pull-request checks instead of only reporting.

But even in prototype form, GuardRail AI shows how **automated, self-service governance removes manual bottlenecks**, allowing cloud teams to **ship more experiments safely**, with metrics that executives and security leaders can both trust.  

