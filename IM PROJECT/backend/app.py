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

from core.scanner import scan_file, scan_code_content, scan_unknown_source_risk
from ai_advisor.advisor import assess_source_url_with_ai
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


@app.route("/api/status", methods=["GET"])
def api_status():
    """Expose whether AI-assisted remediation/intel is available."""
    ai_enabled = bool(os.getenv("GOOGLE_API_KEY"))
    return jsonify({
        "ai_enabled": ai_enabled,
        "ai_label": "ON" if ai_enabled else "OFF",
        "ai_mode": "Gemini-enabled" if ai_enabled else "Rule-based fallback",
    })


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
    source_url = (request.form.get("source_url") or "").strip()
    file = request.files.get("file")

    def _score_from_findings(all_findings):
        score = 100.0
        for f in all_findings:
            sev = str(f.get("severity", "")).upper()
            if sev == "HIGH":
                score -= 15.0
            elif sev == "MEDIUM":
                score -= 8.0
            else:
                score -= 5.0
        return max(0.0, score)

    def _split_findings(all_findings):
        url_findings = []
        file_findings = []
        for f in all_findings:
            service = str(f.get("service", "")).lower()
            if service == "source-url":
                url_findings.append(f)
            else:
                file_findings.append(f)
        return file_findings, url_findings

    def _build_message(file_count, url_count, is_code_file):
        if file_count > 0 and url_count > 0:
            return (
                "This upload is dangerous: file content has risky patterns and the source URL is also suspicious. "
                "See separate findings below."
            )
        if file_count > 0:
            if is_code_file:
                return (
                    "This file is dangerous: it contains risky or malicious code/text patterns. "
                    "See file findings below."
                )
            return (
                "This file is dangerous: it contains cloud policy security misconfigurations. "
                "See file findings below."
            )
        if url_count > 0:
            return (
                "File content appears safe, but the source URL is suspicious. "
                "Treat this source as untrusted and verify integrity before use."
            )
        return "This file and source URL look safe: no dangerous patterns were detected."

    if (not file or not file.filename) and not source_url:
        return jsonify({"error": "Provide at least one input: file upload or source URL."}), 400

    if not file or not file.filename:
        findings_objs, _ = scan_unknown_source_risk("source_only_input.txt", "", source_url)
        findings = [asdict(f) for f in findings_objs]
        findings.extend(assess_source_url_with_ai(source_url, "source_only_input.txt", ""))
        file_findings, url_findings = _split_findings(findings)
        file_risk_count = len(file_findings)
        url_risk_count = len(url_findings)
        compliance_score = _score_from_findings(findings)
        danger = len(findings) > 0
        message = _build_message(file_risk_count, url_risk_count, is_code_file=False)
        return jsonify({
            "danger": danger,
            "message": message,
            "file_name": None,
            "findings": findings,
            "finding_count": len(findings),
            "file_risk_count": file_risk_count,
            "url_risk_count": url_risk_count,
            "compliance_score": round(compliance_score, 2),
            "safe_content": None,
            "safe_file_name": None,
        })

    ext = (Path(file.filename).suffix or "").lower()
    POLICY_EXTS = (".json", ".yaml", ".yml")
    CODE_EXTS = (".py", ".java", ".cpp", ".c++", ".hpp", ".h", ".txt", ".ps1")
    if ext not in POLICY_EXTS and ext not in CODE_EXTS:
        return jsonify({
            "error": "Allowed formats: policy (.json, .yaml, .yml) or code/text (.py, .java, .cpp, .hpp, .h, .txt, .ps1)."
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
            unknown_source_findings, _ = scan_unknown_source_risk(file_name, content, source_url)
            findings.extend([asdict(f) for f in unknown_source_findings])
            findings.extend(assess_source_url_with_ai(source_url, file_name, content))
            compliance_score = _score_from_findings(findings)
            file_findings, url_findings = _split_findings(findings)
            file_risk_count = len(file_findings)
            url_risk_count = len(url_findings)
            danger = len(findings) > 0
            message = _build_message(file_risk_count, url_risk_count, is_code_file=False)
            safe_content = None
            safe_file_name = None
            if file_risk_count > 0:
                safe_content = generate_safe_policy(content, findings, file_name)
                base, _ = os.path.splitext(file_name)
                safe_file_name = f"{base}_safe.json"
            return jsonify({
                "danger": danger,
                "message": message,
                "file_name": file_name,
                "findings": findings,
                "finding_count": len(findings),
                "file_risk_count": file_risk_count,
                "url_risk_count": url_risk_count,
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
            unknown_source_findings, _ = scan_unknown_source_risk(file_name, content, source_url)
            findings.extend([asdict(f) for f in unknown_source_findings])
            findings.extend(assess_source_url_with_ai(source_url, file_name, content))
            compliance_score = _score_from_findings(findings)
            file_findings, url_findings = _split_findings(findings)
            file_risk_count = len(file_findings)
            url_risk_count = len(url_findings)
            danger = len(findings) > 0
            message = _build_message(file_risk_count, url_risk_count, is_code_file=True)
            safe_content = None
            safe_file_name = None
            if file_risk_count > 0:
                safe_content = generate_safe_code(content, findings, file_name)
                base, _ = os.path.splitext(file_name)
                safe_file_name = f"{base}_safe{ext}"
            return jsonify({
                "danger": danger,
                "message": message,
                "file_name": file_name,
                "findings": findings,
                "finding_count": len(findings),
                "file_risk_count": file_risk_count,
                "url_risk_count": url_risk_count,
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
