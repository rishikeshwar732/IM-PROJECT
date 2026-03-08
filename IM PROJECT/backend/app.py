"""
GuardRail AI – Web backend: upload policy file, get danger message + AI-remediated safe result.
Run from project root: python backend/app.py
"""

import logging
import os
import tempfile
from dataclasses import asdict
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

# Allow importing core and ai_advisor when running from project root or backend/
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in __import__("sys").path:
    __import__("sys").path.insert(0, str(_PROJECT_ROOT))

from core.scanner import scan_file, scan_code_content
from ai_advisor.remediate import generate_safe_policy, generate_safe_code

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
)
LOGGER = logging.getLogger("guardrail_ai.backend")

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB max upload

# Serve UI from project ui/ folder
UI_DIR = _PROJECT_ROOT / "ui"


@app.route("/")
def index():
    """Serve the main dashboard (upload + results)."""
    return send_from_directory(UI_DIR, "index.html")


@app.route("/<path:path>")
def ui_static(path):
    """Serve other UI assets (e.g. if you add CSS/JS files)."""
    return send_from_directory(UI_DIR, path)


@app.route("/api/scan", methods=["POST"])
def api_scan():
    """
    Accept a single file upload (cloud policy JSON/YAML).
    Scan for danger; if dangerous, run AI remediation and return safe policy.
    """
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded. Use form field 'file'."}), 400

    file = request.files["file"]
    if not file or not file.filename:
        return jsonify({"error": "No file selected."}), 400

    ext = (Path(file.filename).suffix or "").lower()
    POLICY_EXTS = (".json", ".yaml", ".yml")
    CODE_EXTS = (".py", ".java", ".cpp", ".c++", ".hpp", ".h", ".txt")
    if ext not in POLICY_EXTS and ext not in CODE_EXTS:
        return jsonify({
            "error": "Allowed formats: policy (.json, .yaml, .yml) or code/text (.py, .java, .cpp, .hpp, .h, .txt)."
        }), 400

    try:
        content = file.read().decode("utf-8")
    except Exception as e:
        return jsonify({"error": f"Could not read file: {e}"}), 400

    file_name = file.filename or "uploaded_file"

    if ext in POLICY_EXTS:
        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, encoding="utf-8") as tmp:
                tmp.write(content)
                tmp_path = tmp.name
            result = scan_file(tmp_path)
            findings = [asdict(f) for f in result.findings]
            compliance_score = result.metrics.compliance_score
            danger = len(findings) > 0
            message = (
                "This file is dangerous: it contains security issues (malicious or risky patterns detected by the backend). "
                "See findings below. A safe, remediated version is provided."
                if danger
                else "This file is safe: no dangerous patterns were detected."
            )
            safe_content = None
            safe_file_name = None
            if danger:
                safe_content = generate_safe_policy(content, findings, file_name)
                base, _ = os.path.splitext(file_name)
                safe_file_name = f"{base}_safe.json"
            return jsonify({
                "danger": danger,
                "message": message,
                "file_name": file_name,
                "findings": findings,
                "finding_count": len(findings),
                "compliance_score": round(compliance_score, 2),
                "safe_content": safe_content,
                "safe_file_name": safe_file_name,
            })
        except Exception as e:
            LOGGER.exception("Policy scan or remediate failed")
            return jsonify({"error": str(e)}), 500
        finally:
            if tmp_path and os.path.isfile(tmp_path):
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
    else:
        # Code or text file
        try:
            code_findings, compliance_score = scan_code_content(content, file_name)
            findings = [asdict(f) for f in code_findings]
            danger = len(findings) > 0
            message = (
                "This file is dangerous: it contains risky or malicious patterns (eval, exec, system calls, hardcoded secrets, etc.) detected by the backend. "
                "See findings below. A safe, remediated version is provided."
                if danger
                else "This file is safe: no dangerous patterns were detected."
            )
            safe_content = None
            safe_file_name = None
            if danger:
                safe_content = generate_safe_code(content, findings, file_name)
                base, _ = os.path.splitext(file_name)
                safe_file_name = f"{base}_safe{ext}"
            return jsonify({
                "danger": danger,
                "message": message,
                "file_name": file_name,
                "findings": findings,
                "finding_count": len(findings),
                "compliance_score": round(compliance_score, 2),
                "safe_content": safe_content,
                "safe_file_name": safe_file_name,
            })
        except Exception as e:
            LOGGER.exception("Code scan or remediate failed")
            return jsonify({"error": str(e)}), 500


def main():
    port = int(os.getenv("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=True)


if __name__ == "__main__":
    main()
