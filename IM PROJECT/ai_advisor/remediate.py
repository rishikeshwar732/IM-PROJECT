"""
Generate a safe (remediated) version of a cloud policy from scan findings.
Uses Gemini when available; otherwise applies rule-based fixes.
"""

import json
import logging
import os
import re
from typing import Any, Dict, List

LOGGER = logging.getLogger("guardrail_ai.remediate")


def _call_gemini_for_safe_policy(original_content: str, findings: List[Dict[str, Any]], file_name: str) -> str:
    """Ask Gemini to return a corrected policy document (JSON or YAML only)."""
    api_key = os.getenv("GOOGLE_API_KEY")
    model_name = os.getenv("GEMINI_MODEL", "gemini-1.5-pro-latest")

    if not api_key:
        return ""

    summary = "\n".join(
        f"- {f.get('message', '')} (severity: {f.get('severity', '')})"
        for f in findings
    )

    prompt = f"""You are a cloud security expert. The following cloud policy file was flagged as dangerous.

FILENAME: {file_name}

SECURITY ISSUES FOUND:
{summary}

ORIGINAL POLICY:
```
{original_content}
```

Your task: Produce a SAFE, corrected version of this policy that fixes all the security issues above. Preserve the same structure (JSON or YAML). Do not add explanations—output ONLY the corrected policy document, valid JSON or YAML, nothing else."""

    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(model_name)
        response = model.generate_content(prompt)
        text = (response.text or "").strip()
        # Extract code block if Gemini wrapped it
        if "```" in text:
            match = re.search(r"```(?:json|yaml)?\s*\n?(.*?)```", text, re.DOTALL)
            if match:
                text = match.group(1).strip()
        return text
    except Exception as exc:
        LOGGER.warning("Gemini remediation failed: %s", exc)
        return ""


def _remediate_aws_s3(policy: Dict[str, Any]) -> Dict[str, Any]:
    """Replace public principal with a placeholder IAM role."""
    out = json.loads(json.dumps(policy))  # deep copy
    statements = out.get("Statement") or out.get("statement") or []
    if not isinstance(statements, list):
        statements = [statements]
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        principal = stmt.get("Principal") or stmt.get("principal")
        if principal == "*":
            stmt["Principal"] = {"AWS": "arn:aws:iam::123456789012:role/REPLACE_WITH_YOUR_TEAM_ROLE"}
            if "principal" in stmt:
                stmt["principal"] = stmt["Principal"]
    out["Statement"] = statements
    return out


def _remediate_aws_iam(policy: Dict[str, Any]) -> Dict[str, Any]:
    """Replace wildcard action/resource with minimal scoped permissions."""
    out = json.loads(json.dumps(policy))
    statements = out.get("Statement") or out.get("statement") or []
    if not isinstance(statements, list):
        statements = [statements]
    for stmt in statements:
        if not isinstance(stmt, dict):
            continue
        if (stmt.get("Action") or stmt.get("action")) == "*" or stmt.get("Resource") == "*":
            stmt["Action"] = ["iam:GetUser", "iam:ListAccountAliases"]
            stmt["Resource"] = ["arn:aws:iam::123456789012:user/*"]
            if "action" in stmt:
                del stmt["action"]
    out["Statement"] = statements
    return out


def _remediate_azure_nsg(nsg: Dict[str, Any]) -> Dict[str, Any]:
    """Restrict SSH rule to localhost / admin range instead of 0.0.0.0/0."""
    out = json.loads(json.dumps(nsg))
    rules = (out.get("properties") or {}).get("securityRules") or out.get("securityRules") or []
    if not isinstance(rules, list):
        rules = [rules]
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        props = rule.get("properties", rule)
        if props.get("destinationPortRange") == "22" and props.get("sourceAddressPrefix") in ("*", "0.0.0.0/0"):
            props["sourceAddressPrefix"] = "203.0.113.0/24"  # placeholder admin range
    if out.get("properties"):
        out["properties"]["securityRules"] = rules
    else:
        out["securityRules"] = rules
    return out


def _parse_policy(content: str) -> Dict[str, Any]:
    """Parse JSON or YAML policy content into a dict."""
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    try:
        import yaml
        data = yaml.safe_load(content)
        return data if isinstance(data, dict) else {}
    except Exception:
        pass
    return {}


def _fallback_remediate(original_content: str, findings: List[Dict[str, Any]], file_name: str) -> str:
    """Apply rule-based fixes to produce a safe policy string."""
    data = _parse_policy(original_content)
    if not data:
        return json.dumps({"error": "Could not parse policy for automatic remediation. Use AI (set GOOGLE_API_KEY) or fix manually."}, indent=2)

    provider = "unknown"
    for f in findings:
        p = f.get("provider", "")
        if p in ("aws", "azure"):
            provider = p
            break

    if provider == "aws":
        if any(f.get("service") == "s3" for f in findings):
            data = _remediate_aws_s3(data)
        if any(f.get("service") == "iam" for f in findings):
            data = _remediate_aws_iam(data)
    elif provider == "azure":
        if any(f.get("service") == "nsg" for f in findings):
            data = _remediate_azure_nsg(data)

    return json.dumps(data, indent=2)


def generate_safe_policy(
    original_content: str,
    findings: List[Dict[str, Any]],
    file_name: str,
) -> str:
    """
    Produce a safe (remediated) version of the policy.
    Uses Gemini if GOOGLE_API_KEY is set; otherwise uses rule-based fixes.
    """
    if not findings:
        return original_content

    safe = _call_gemini_for_safe_policy(original_content, findings, file_name)
    if safe and (safe.strip().startswith("{") or safe.strip().startswith("[")):
        try:
            json.loads(safe)
            return safe
        except json.JSONDecodeError:
            pass
    if safe:
        return safe

    return _fallback_remediate(original_content, findings, file_name)


def _call_gemini_for_safe_code(original_content: str, findings: List[Dict[str, Any]], file_name: str) -> str:
    """Ask Gemini to return a safer version of the code (or remediation advice)."""
    api_key = os.getenv("GOOGLE_API_KEY")
    model_name = os.getenv("GEMINI_MODEL", "gemini-1.5-pro-latest")
    if not api_key:
        return ""

    summary = "\n".join(f"- {f.get('message', '')} (severity: {f.get('severity', '')})" for f in findings)
    prompt = f"""You are a security-focused developer. The following source file was flagged for dangerous patterns.

FILENAME: {file_name}

SECURITY ISSUES FOUND:
{summary}

ORIGINAL CONTENT:
```
{original_content}
```

Your task: Produce a SAFER version of this code that fixes the security issues. Remove or replace dangerous constructs (eval, exec, system calls, hardcoded secrets) with safe alternatives. Output ONLY the corrected code, no explanation. If the file is not code, output a short secure replacement or instructions."""

    try:
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(model_name)
        response = model.generate_content(prompt)
        text = (response.text or "").strip()
        if "```" in text:
            match = re.search(r"```(?:\w+)?\s*\n?(.*?)```", text, re.DOTALL)
            if match:
                text = match.group(1).strip()
        return text
    except Exception as exc:
        LOGGER.warning("Gemini code remediation failed: %s", exc)
        return ""


def generate_safe_code(
    original_content: str,
    findings: List[Dict[str, Any]],
    file_name: str,
) -> str:
    """
    Produce a safer version of code/text given findings.
    Uses Gemini when available; otherwise returns a short fallback message.
    """
    if not findings:
        return original_content

    safe = _call_gemini_for_safe_code(original_content, findings, file_name)
    if safe:
        return safe

    fallback = (
        "# Safe version: remove or replace the following patterns.\n"
        + "\n".join(f"# - {f.get('message', '')}" for f in findings)
        + "\n# Use environment variables for secrets; avoid eval/exec/system with user input."
    )
    return fallback
