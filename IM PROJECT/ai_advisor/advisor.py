import json
import logging
import os
import re
from urllib.request import Request, urlopen
from typing import Any, Dict, List

LOGGER = logging.getLogger("guardrail_ai.advisor")


def _fetch_source_preview(source_url: str) -> str:
    """Fetch a small, safe text preview from the source URL for AI risk context."""
    if not source_url or not re.match(r"(?i)^https?://", source_url):
        return ""

    try:
        req = Request(
            source_url,
            headers={"User-Agent": "GuardRailAI/1.0 (URL risk pre-screen)"},
            method="GET",
        )
        with urlopen(req, timeout=5) as resp:  # nosec B310
            content_type = (resp.headers.get("Content-Type") or "").lower()
            if "text" not in content_type and "json" not in content_type and "html" not in content_type:
                return f"Non-text content-type observed: {content_type or 'unknown'}"
            raw = resp.read(4096)
            return raw.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def assess_source_url_with_ai(source_url: str, file_name: str, content: str = "") -> List[Dict[str, Any]]:
    """
    Optional AI-based URL risk assessment.
    Returns a list of finding-like dicts compatible with backend output.
    """
    api_key = os.getenv("GOOGLE_API_KEY")
    model_name = os.getenv("GEMINI_MODEL", "gemini-1.5-pro-latest")
    if not api_key or not source_url:
        return []

    preview = _fetch_source_preview(source_url)
    content_hint = (content or "")[:1000]

    prompt = f"""
You are a cybersecurity analyst. Assess supply-chain risk for this download source.

SOURCE_URL: {source_url}
FILE_NAME: {file_name}
FILE_CONTENT_SNIPPET:
{content_hint}

SOURCE_PREVIEW_TEXT:
{preview}

Return strict JSON object only with keys:
- severity: HIGH | MEDIUM | LOW
- message: short risk statement
- recommendation_hint: short actionable advice

If uncertain, choose MEDIUM and explain uncertainty.
""".strip()

    try:
        import google.generativeai as genai  # type: ignore

        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(model_name)
        response = model.generate_content(prompt)
        text = (response.text or "").strip()

        if "```" in text:
            match = re.search(r"```(?:json)?\s*\n?(.*?)```", text, re.DOTALL)
            if match:
                text = match.group(1).strip()

        payload = json.loads(text)
        severity = str(payload.get("severity", "MEDIUM")).upper()
        if severity not in {"HIGH", "MEDIUM", "LOW"}:
            severity = "MEDIUM"

        return [
            {
                "id": f"{file_name}-ai-source-risk-0",
                "provider": "ai-intel",
                "service": "source-url",
                "severity": severity,
                "message": str(payload.get("message", "AI flagged potential source risk.")).strip(),
                "recommendation_hint": str(
                    payload.get(
                        "recommendation_hint",
                        "Verify source reputation and artifact integrity before use.",
                    )
                ).strip(),
            }
        ]
    except Exception as exc:
        LOGGER.warning("AI source URL assessment failed: %s", exc)
        return []


def _load_scan_results(path: str) -> List[Dict[str, Any]]:
    if not os.path.isfile(path):
        raise FileNotFoundError(f"Scan results file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if not isinstance(data, list):
        raise ValueError("Expected scan results JSON to be a list of scan objects.")
    return data


def _format_prompt(findings: List[Dict[str, Any]]) -> str:
    """
    Build a compact prompt instructing the LLM to respond with
    innovation-friendly remediations rather than generic 'lock it down'
    responses.
    """
    summary_lines: List[str] = []
    for f in findings:
        summary_lines.append(
            f"- [{f.get('severity','UNKNOWN')}] {f.get('provider','?')}/{f.get('service','?')} "
            f"{f.get('message','')}"
        )

    summary = "\n".join(summary_lines) or "No findings."

    prompt = f"""
You are a Senior Cloud Security Architect and Innovation Coach.

The following automated scan findings were detected in a cloud environment:

{summary}

For each ISSUE, propose concrete remediation steps that:
- Reduce risk to an enterprise-ready level, and
- Preserve or increase developer innovation velocity (e.g., prefer guardrails, automation, and paved roads
  over heavy manual approvals).

Respond in concise bullet points grouped under:
- "Quick Wins" (can be implemented this week)
- "Medium-Term Guardrails" (automation, reference architectures, reusable templates)
- "Policy & Culture" (how leadership should message shift-left security).
"""
    return prompt.strip()


def _call_gemini(prompt: str) -> str:
    """
    Call Gemini / LLM if configured, otherwise fall back to
    deterministic rule-based text so the prototype works offline.
    """
    api_key = os.getenv("GOOGLE_API_KEY")
    model_name = os.getenv("GEMINI_MODEL", "gemini-1.5-pro-latest")

    if not api_key:
        LOGGER.warning(
            "GOOGLE_API_KEY not set; using local fallback advisor instead of Gemini."
        )
        return _fallback_advice()

    try:
        import google.generativeai as genai  # type: ignore
    except Exception as exc:  # pragma: no cover - external dependency
        LOGGER.error("Failed to import google.generativeai: %s", exc)
        return _fallback_advice()

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(model_name)
        response = model.generate_content(prompt)
        return response.text or _fallback_advice()
    except Exception as exc:  # pragma: no cover - runtime integration
        LOGGER.error("Gemini call failed: %s", exc)
        return _fallback_advice()


def _fallback_advice() -> str:
    """
    Minimal but opinionated, innovation-friendly guidance when LLM
    connectivity is unavailable.
    """
    return (
        "Quick Wins:\n"
        "- Replace public S3/NSG access with role-based or IP-scoped access while keeping non-prod sandboxes easy to reach.\n"
        "- Remove wildcard IAM permissions in production accounts; keep broader rights only in isolated experimentation accounts.\n\n"
        "Medium-Term Guardrails:\n"
        "- Publish Terraform/ARM templates that encode secure defaults (private buckets, JIT SSH, scoped IAM) and make them the easiest path.\n"
        "- Integrate this scanner into CI so new policies are checked automatically on every pull request.\n\n"
        'Policy & Culture:\n'
        "- Position security rules as enablers of faster approvals (\"if you use the golden path, you auto-approve\").\n"
        "- Track and report \"time saved via automated policy checks\" as a KPI for both security and engineering leadership."
    )


def generate_advice(scan_results_path: str) -> Dict[str, Any]:
    """
    High-level entry point: takes the JSON produced by core.scanner,
    calls Gemini (or fallback) and returns a structured response.
    """
    LOGGER.info("Loading scan results from %s", scan_results_path)
    scans = _load_scan_results(scan_results_path)

    all_findings: List[Dict[str, Any]] = []
    for scan in scans:
        findings = scan.get("findings", [])
        if isinstance(findings, list):
            all_findings.extend(findings)

    prompt = _format_prompt(all_findings)
    advice_text = _call_gemini(prompt)

    total_time_saved = sum(
        (scan.get("metrics", {}) or {}).get("time_saved_hours", 0.0) for scan in scans
    )
    avg_compliance = 0.0
    if scans:
        avg_compliance = sum(
            (scan.get("metrics", {}) or {}).get("compliance_score", 0.0)
            for scan in scans
        ) / len(scans)

    result: Dict[str, Any] = {
        "advice": advice_text,
        "management_metrics": {
            "total_scans": len(scans),
            "total_time_saved_hours": round(total_time_saved, 3),
            "average_compliance_score": round(avg_compliance, 2),
        },
    }

    LOGGER.info(
        "Generated advisory with %d scan(s), total_time_saved_hours=%.3f, avg_compliance=%.2f",
        len(scans),
        result["management_metrics"]["total_time_saved_hours"],
        result["management_metrics"]["average_compliance_score"],
    )
    return result


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "GuardRail AI Advisor - turns raw security findings into "
            "innovation-friendly remediation guidance using Gemini/LLM."
        )
    )
    parser.add_argument(
        "--scan-results",
        "-s",
        required=True,
        help="Path to JSON file produced by core/scanner.py.",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="advisor_output.json",
        help="Where to write the advisory JSON payload.",
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        help="Logging verbosity.",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    )

    try:
        advice = generate_advice(args.scan_results)
    except Exception as exc:
        LOGGER.error("Failed to generate advice: %s", exc)
        raise SystemExit(1) from exc

    try:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(advice, f, indent=2)
    except Exception as exc:
        LOGGER.error("Failed to write advisor output file %s: %s", args.output, exc)
        raise SystemExit(1) from exc

    LOGGER.info("Advisor output written to %s", args.output)


if __name__ == "__main__":
    main()

