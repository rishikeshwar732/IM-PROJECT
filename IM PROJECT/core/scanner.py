import argparse
import json
import logging
import os
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover - optional dependency
    yaml = None  # type: ignore


LOGGER = logging.getLogger("guardrail_ai.scanner")


MANUAL_AUDIT_HOURS = 4.0
TOOL_AUDIT_SECONDS = 5.0


@dataclass
class Finding:
    id: str
    provider: str
    service: str
    severity: str
    message: str
    recommendation_hint: str
    path: Optional[str] = None


@dataclass
class ScanMetrics:
    manual_audit_hours: float = MANUAL_AUDIT_HOURS
    tool_audit_seconds: float = TOOL_AUDIT_SECONDS
    time_saved_hours: float = field(init=False)
    compliance_score: float = 100.0

    def __post_init__(self) -> None:
        self.time_saved_hours = max(
            0.0, self.manual_audit_hours - (self.tool_audit_seconds / 3600.0)
        )


@dataclass
class ScanResult:
    file_path: str
    provider: str
    service: str
    scanned_at_utc: str
    findings: List[Finding]
    metrics: ScanMetrics

    @property
    def is_compliant(self) -> bool:
        return not self.findings


def _load_policy(file_path: str) -> Dict[str, Any]:
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Heuristic: try JSON first, then YAML
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        if yaml is None:
            raise ValueError(
                f"File {file_path!r} is not valid JSON and PyYAML is not installed."
            )
        try:
            loaded = yaml.safe_load(content)
        except Exception as exc:
            raise ValueError(f"Unable to parse policy file {file_path!r}: {exc}") from exc

        if not isinstance(loaded, dict):
            raise ValueError(
                f"Expected a mapping (object) at root of {file_path!r}, "
                f"got {type(loaded).__name__} instead."
            )
        return loaded


def _detect_aws_s3_findings(policy: Dict[str, Any], file_path: str) -> List[Finding]:
    findings: List[Finding] = []
    statements = policy.get("Statement") or policy.get("statement") or []
    if not isinstance(statements, list):
        statements = [statements]

    for idx, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            continue

        effect = str(stmt.get("Effect") or stmt.get("effect") or "").lower()
        principal = stmt.get("Principal") or stmt.get("principal")
        resource = stmt.get("Resource") or stmt.get("resource")

        principal_is_public = principal == "*" or (
            isinstance(principal, dict)
            and any(
                v == "*" or (isinstance(v, list) and "*" in v)
                for v in principal.values()
            )
        )

        resource_is_bucket_or_objects = False
        if isinstance(resource, str):
            resource_is_bucket_or_objects = ":s3:::" in resource
        elif isinstance(resource, list):
            resource_is_bucket_or_objects = any(
                isinstance(r, str) and ":s3:::" in r for r in resource
            )

        if effect == "allow" and principal_is_public and resource_is_bucket_or_objects:
            findings.append(
                Finding(
                    id=f"{os.path.basename(file_path)}-s3-public-{idx}",
                    provider="aws",
                    service="s3",
                    severity="HIGH",
                    message="S3 bucket policy allows public access to bucket data.",
                    recommendation_hint=(
                        "Restrict bucket access to specific IAM roles or VPC endpoints, "
                        "and use bucket policies that explicitly deny public access. "
                        "This keeps data safe while still enabling rapid experimentation "
                        "through role-based access."
                    ),
                    path=f"Statement[{idx}]",
                )
            )

    return findings


def _detect_aws_iam_findings(policy: Dict[str, Any], file_path: str) -> List[Finding]:
    findings: List[Finding] = []
    statements = policy.get("Statement") or policy.get("statement") or []
    if not isinstance(statements, list):
        statements = [statements]

    for idx, stmt in enumerate(statements):
        if not isinstance(stmt, dict):
            continue

        effect = str(stmt.get("Effect") or stmt.get("effect") or "").lower()
        actions = stmt.get("Action") or stmt.get("action")
        resource = stmt.get("Resource") or stmt.get("resource")

        if isinstance(actions, str):
            actions_list = [actions]
        elif isinstance(actions, list):
            actions_list = [a for a in actions if isinstance(a, str)]
        else:
            actions_list = []

        wildcards = [a for a in actions_list if a == "*" or a.endswith(":*")]
        resource_is_all = resource == "*" or (
            isinstance(resource, list) and "*" in resource
        )

        if effect == "allow" and wildcards and resource_is_all:
            findings.append(
                Finding(
                    id=f"{os.path.basename(file_path)}-iam-star-{idx}",
                    provider="aws",
                    service="iam",
                    severity="HIGH",
                    message="IAM policy allows wildcard actions on all resources.",
                    recommendation_hint=(
                        "Scope IAM permissions to the minimal set of actions and "
                        "resources needed for the team or workload. Start broad in a "
                        "sandbox, then quickly tighten to named resources as patterns "
                        "stabilise to keep innovation velocity high without over-privilege."
                    ),
                    path=f"Statement[{idx}]",
                )
            )

    return findings


def _detect_azure_nsg_findings(nsg: Dict[str, Any], file_path: str) -> List[Finding]:
    findings: List[Finding] = []

    # Support ARM templates and simplified NSG exports
    rules = (
        nsg.get("properties", {})
        .get("securityRules")
        or nsg.get("securityRules")
        or []
    )
    if not isinstance(rules, list):
        rules = [rules]

    for idx, rule in enumerate(rules):
        if not isinstance(rule, dict):
            continue

        props = rule.get("properties", rule)
        direction = str(props.get("direction", "")).lower()
        access = str(props.get("access", "")).lower()
        source_prefix = props.get("sourceAddressPrefix")
        source_prefixes = props.get("sourceAddressPrefixes")
        if isinstance(source_prefixes, list):
            source_values = [str(v) for v in source_prefixes]
        elif source_prefixes is not None:
            source_values = [str(source_prefixes)]
        elif source_prefix is not None:
            source_values = [str(source_prefix)]
        else:
            source_values = []

        dest_port_range = props.get("destinationPortRange")
        dest_port_ranges = props.get("destinationPortRanges")
        if isinstance(dest_port_ranges, list):
            port_values = [str(v) for v in dest_port_ranges]
        elif dest_port_ranges is not None:
            port_values = [str(dest_port_ranges)]
        elif dest_port_range is not None:
            port_values = [str(dest_port_range)]
        else:
            port_values = []

        is_inbound_allow = direction == "inbound" and access == "allow"
        # Azure often uses "Internet" to denote public source; include common public aliases.
        is_open_source = any(
            s.strip().lower() in {"*", "0.0.0.0/0", "internet", "any"}
            for s in source_values
        )
        exposes_ssh = any(
            p.strip() == "22" or p.strip() == "22-22"
            for p in port_values
        )

        if is_inbound_allow and is_open_source and exposes_ssh:
            findings.append(
                Finding(
                    id=f"{os.path.basename(file_path)}-nsg-ssh-{idx}",
                    provider="azure",
                    service="nsg",
                    severity="HIGH",
                    message="NSG rule allows SSH (22) from the entire internet.",
                    recommendation_hint=(
                        "Limit SSH to just admin IP ranges or use a Just-In-Time "
                        "access pattern via Azure Security Center or Bastion. "
                        "This still lets engineers move fast while avoiding always-on "
                        "internet-exposed management ports."
                    ),
                    path=f"securityRules[{idx}]",
                )
            )

    return findings


def _infer_provider_and_service(file_path: str, policy: Dict[str, Any]) -> Tuple[str, str]:
    name = os.path.basename(file_path).lower()

    if "s3" in name:
        return "aws", "s3"
    if "iam" in name:
        return "aws", "iam"
    if "nsg" in name or "securitygroup" in name:
        return "azure", "nsg"

    # Fallback heuristics
    if "Statement" in policy or "statement" in policy:
        # Most likely an AWS-style policy
        if any("s3" in str(v).lower() for v in policy.values()):
            return "aws", "s3"
        return "aws", "iam"

    if "securityRules" in policy or (
        isinstance(policy.get("properties"), dict)
        and "securityRules" in (policy.get("properties") or {})
    ):
        return "azure", "nsg"

    return "unknown", "unknown"


def _calculate_compliance_score(findings: List[Finding]) -> float:
    """
    Simple management-friendly score:
    Start at 100 and subtract 15 points per high-severity finding,
    5 per anything else. Floor at 0.
    """
    if not findings:
        return 100.0

    score = 100.0
    for f in findings:
        if f.severity.upper() == "HIGH":
            score -= 15.0
        elif f.severity.upper() == "MEDIUM":
            score -= 8.0
        else:
            score -= 5.0
    return max(0.0, score)


# Dangerous patterns in code (Python, Java, C++, plain text)
_CODE_PATTERNS = [
    # Python
    (r"\beval\s*\(", "python", "HIGH", "Use of eval() can execute arbitrary code."),
    (r"\bexec\s*\(", "python", "HIGH", "Use of exec() can execute arbitrary code."),
    (r"__import__\s*\(", "python", "HIGH", "Dynamic __import__ can load arbitrary modules."),
    (r"os\.system\s*\(", "python", "HIGH", "os.system() executes shell commands; use subprocess with strict args."),
    (r"subprocess\.(call|run|Popen)\s*\b.*shell\s*=\s*True", "python", "HIGH", "subprocess with shell=True is dangerous; avoid shell=True."),
    # Java
    (r"Runtime\.getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(", "java", "HIGH", "Runtime.exec() can run arbitrary commands."),
    (r"ProcessBuilder\s*\(", "java", "MEDIUM", "ProcessBuilder executes external processes; validate inputs."),
    (r"ScriptEngineManager|eval\s*\(", "java", "HIGH", "Script engine or eval can execute arbitrary code."),
    # C++
    (r"\bsystem\s*\(", "c++", "HIGH", "system() executes shell commands; prefer secure APIs."),
    (r"\bexec[lv]\s*\(", "c++", "HIGH", "exec family can replace process with arbitrary program."),
    (r"\bpopen\s*\(", "c++", "MEDIUM", "popen() runs shell commands; use safer APIs."),
]
# Generic (any code/text)
_CODE_GENERIC = [
    (r"\beval\s*\(", "code", "HIGH", "eval() pattern can execute arbitrary code."),
    (r"\bexec\s*\(", "code", "HIGH", "exec() pattern can execute arbitrary code."),
]
# Generic / text
_SUSPICIOUS_PATTERNS = [
    (r"(?i)password\s*=\s*['\"]?[^'\"]+['\"]?", "txt", "MEDIUM", "Hardcoded password detected."),
    (r"(?i)api[_-]?key\s*=\s*['\"]?[^'\"]+['\"]?", "txt", "MEDIUM", "Hardcoded API key detected."),
]


_RISKY_FILE_EXTENSIONS = {
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".msi", ".scr", ".com", ".hta", ".docm", ".xlsm",
}

_SUSPICIOUS_DOMAIN_PATTERNS = [
    r"(?i)pastebin\.com",
    r"(?i)anonfiles\.com",
    r"(?i)mediafire\.com",
    r"(?i)bit\.ly|tinyurl\.com|t\.co",
    r"(?i)raw\.githubusercontent\.com",
]

_DANGEROUS_DOWNLOAD_SCRIPT_PATTERNS = [
    (r"(?i)invoke-webrequest\b.*\b-exec(utionpolicy)?\b", "HIGH", "PowerShell script includes risky remote execution flow."),
    (r"(?i)iwr\s+https?://", "MEDIUM", "Short-form iwr command downloads remote content."),
    (r"(?i)curl\s+https?://", "MEDIUM", "curl command pulls remote content; verify source integrity."),
    (r"(?i)wget\s+https?://", "MEDIUM", "wget command pulls remote content; verify source integrity."),
    (r"(?i)powershell\s+-enc\b", "HIGH", "Encoded PowerShell command detected."),
    (r"(?i)certutil\s+-urlcache\b", "HIGH", "certutil download pattern is often abused by malware."),
]


def scan_unknown_source_risk(
    file_name: str,
    content: str,
    source_url: str = "",
) -> Tuple[List[Finding], float]:
    """
    Scan potential downloaded artifacts for supply-chain or malware-like risk patterns.
    This is heuristic-based and intended for pre-screening, not antivirus replacement.
    """
    findings: List[Finding] = []
    lower_name = file_name.lower()
    ext = os.path.splitext(lower_name)[1]

    if ext in _RISKY_FILE_EXTENSIONS:
        findings.append(
            Finding(
                id=f"{file_name}-artifact-ext-0",
                provider="supply-chain",
                service="artifact",
                severity="HIGH",
                message=f"Downloaded artifact uses high-risk executable/script extension: {ext}",
                recommendation_hint=(
                    "Treat as untrusted. Verify checksum/signature, prefer sandbox execution, "
                    "and only run from approved internal repositories."
                ),
            )
        )

    if source_url:
        if re.match(r"(?i)^http://", source_url):
            findings.append(
                Finding(
                    id=f"{file_name}-source-url-http-0",
                    provider="supply-chain",
                    service="source-url",
                    severity="MEDIUM",
                    message="Source URL uses insecure HTTP (not HTTPS), so transport integrity is weaker.",
                    recommendation_hint=(
                        "Prefer HTTPS-only sources and verify checksums/signatures before use."
                    ),
                )
            )
        elif not re.match(r"(?i)^https?://", source_url):
            findings.append(
                Finding(
                    id=f"{file_name}-source-url-scheme-0",
                    provider="supply-chain",
                    service="source-url",
                    severity="MEDIUM",
                    message="Source URL is not HTTP/HTTPS and cannot be trusted by default.",
                    recommendation_hint="Use trusted HTTPS sources with domain allow-listing.",
                )
            )
        for idx, pattern in enumerate(_SUSPICIOUS_DOMAIN_PATTERNS):
            if re.search(pattern, source_url):
                findings.append(
                    Finding(
                        id=f"{file_name}-source-domain-{idx}",
                        provider="supply-chain",
                        service="source-url",
                        severity="HIGH",
                        message="Source URL matches a high-risk or short-link domain pattern.",
                        recommendation_hint=(
                            "Use approved vendor or internal artifact registries. "
                            "Avoid short links and anonymous hosting for corporate downloads."
                        ),
                    )
                )

    for idx, (pattern, severity, message) in enumerate(_DANGEROUS_DOWNLOAD_SCRIPT_PATTERNS):
        if re.search(pattern, content):
            findings.append(
                Finding(
                    id=f"{file_name}-script-risk-{idx}",
                    provider="supply-chain",
                    service="script",
                    severity=severity,
                    message=message,
                    recommendation_hint=(
                        "Avoid direct download-and-execute flows. Download to a temp path, "
                        "validate hash/signature, and run with least privilege."
                    ),
                )
            )

    if "MZ" in content[:8]:
        findings.append(
            Finding(
                id=f"{file_name}-binary-header-0",
                provider="supply-chain",
                service="artifact",
                severity="MEDIUM",
                message="Binary header signature detected in uploaded content.",
                recommendation_hint="Do not execute directly on developer machines; scan/sandbox first.",
            )
        )

    score = _calculate_compliance_score(findings)
    return findings, score


def scan_code_content(content: str, file_name: str) -> Tuple[List[Finding], float]:
    """
    Scan code or text content for dangerous patterns.
    Returns (list of Finding, compliance_score).
    """
    import re
    findings: List[Finding] = []
    ext = (os.path.splitext(file_name)[1] or "").lower().lstrip(".")
    if ext == "py":
        lang = "python"
    elif ext in ("java",):
        lang = "java"
    elif ext in ("cpp", "c++", "hpp", "h", "cc", "cxx"):
        lang = "c++"
    else:
        lang = "code"

    for pattern, service, severity, message in _CODE_PATTERNS:
        if service != lang and service != "code":
            continue
        try:
            for m in re.finditer(pattern, content, re.IGNORECASE):
                findings.append(
                    Finding(
                        id=f"{file_name}-{service}-{len(findings)}",
                        provider="code",
                        service=service,
                        severity=severity,
                        message=message,
                        recommendation_hint="Remove or replace with safe, input-validated alternatives.",
                        path=None,
                    )
                )
        except re.error:
            continue
    # Generic eval/exec for .txt or other non-code extensions
    if lang == "code":
        for pattern, service, severity, message in _CODE_GENERIC:
            try:
                for m in re.finditer(pattern, content, re.IGNORECASE):
                    findings.append(
                        Finding(
                            id=f"{file_name}-{service}-{len(findings)}",
                            provider="code",
                            service=service,
                            severity=severity,
                            message=message,
                            recommendation_hint="Remove or replace with safe, input-validated alternatives.",
                            path=None,
                        )
                    )
            except re.error:
                continue

    for pattern, service, severity, message in _SUSPICIOUS_PATTERNS:
        try:
            if re.search(pattern, content):
                findings.append(
                    Finding(
                        id=f"{file_name}-{service}-{len(findings)}",
                        provider="code",
                        service=service,
                        severity=severity,
                        message=message,
                        recommendation_hint="Use environment variables or a secrets manager.",
                        path=None,
                    )
                )
        except re.error:
            continue

    score = _calculate_compliance_score(findings)
    return findings, score


def scan_file(file_path: str) -> ScanResult:
    LOGGER.info("Scanning policy file %s", file_path)
    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"Policy file not found: {file_path}")

    try:
        policy = _load_policy(file_path)
    except Exception as exc:
        LOGGER.error("Failed to load policy file %s: %s", file_path, exc)
        raise

    provider, service = _infer_provider_and_service(file_path, policy)
    findings: List[Finding] = []

    if provider == "aws" and service == "s3":
        findings = _detect_aws_s3_findings(policy, file_path)
    elif provider == "aws" and service == "iam":
        findings = _detect_aws_iam_findings(policy, file_path)
    elif provider == "azure" and service == "nsg":
        findings = _detect_azure_nsg_findings(policy, file_path)
    else:
        LOGGER.warning(
            "Unknown provider/service for file %s; no specialised checks applied.",
            file_path,
        )

    metrics = ScanMetrics()
    metrics.compliance_score = _calculate_compliance_score(findings)

    result = ScanResult(
        file_path=os.path.abspath(file_path),
        provider=provider,
        service=service,
        scanned_at_utc=datetime.now(timezone.utc).isoformat(),
        findings=findings,
        metrics=metrics,
    )

    LOGGER.info(
        "Completed scan for %s with %d findings, compliance_score=%.2f, time_saved_hours=%.3f",
        file_path,
        len(findings),
        metrics.compliance_score,
        metrics.time_saved_hours,
    )
    return result


def scan_directory(directory: str) -> List[ScanResult]:
    LOGGER.info("Scanning directory %s for policy files", directory)
    if not os.path.isdir(directory):
        raise NotADirectoryError(f"Not a directory: {directory}")

    results: List[ScanResult] = []
    for root, _, files in os.walk(directory):
        for name in files:
            if not name.lower().endswith((".json", ".yaml", ".yml")):
                continue
            file_path = os.path.join(root, name)
            try:
                results.append(scan_file(file_path))
            except Exception as exc:
                LOGGER.error("Error scanning %s: %s", file_path, exc)
    LOGGER.info("Directory scan produced %d result(s)", len(results))
    return results


def _results_to_serialisable(results: List[ScanResult]) -> List[Dict[str, Any]]:
    serialised: List[Dict[str, Any]] = []
    for r in results:
        finding_count = len(r.findings)
        serialised.append(
            {
                "file_path": r.file_path,
                "file_name": os.path.basename(r.file_path),
                "provider": r.provider,
                "service": r.service,
                "scanned_at_utc": r.scanned_at_utc,
                "metrics": asdict(r.metrics),
                "is_compliant": r.is_compliant,
                "status": "danger" if finding_count > 0 else "ok",
                "finding_count": finding_count,
                "findings": [asdict(f) for f in r.findings],
            }
        )
    return serialised


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "GuardRail AI - Self-Service Security Auditor\n"
            "Scans JSON/YAML cloud policies (AWS S3, IAM, Azure NSG) "
            "and emits machine-readable findings plus management metrics."
        )
    )
    parser.add_argument(
        "--path",
        "-p",
        required=True,
        help="Path to a policy file or directory of policies to scan.",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="scan_results.json",
        help="Path to write aggregated scan results as JSON.",
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

    target_path = args.path
    try:
        if os.path.isdir(target_path):
            results = scan_directory(target_path)
        else:
            results = [scan_file(target_path)]
    except Exception as exc:
        LOGGER.error("Scan failed: %s", exc)
        raise SystemExit(1) from exc

    output_data = _results_to_serialisable(results)

    try:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(output_data, f, indent=2)
    except Exception as exc:
        LOGGER.error("Failed to write output file %s: %s", args.output, exc)
        raise SystemExit(1) from exc

    # Print which files have danger (for visibility in terminal and demos)
    danger_files = [r for r in output_data if r.get("status") == "danger"]
    ok_files = [r for r in output_data if r.get("status") == "ok"]
    if danger_files:
        LOGGER.warning(
            "DANGER: %d file(s) with findings: %s",
            len(danger_files),
            [r["file_name"] for r in danger_files],
        )
        for r in danger_files:
            LOGGER.warning(
                "  - %s: %d finding(s), compliance_score=%.1f",
                r["file_name"],
                r.get("finding_count", 0),
                (r.get("metrics") or {}).get("compliance_score", 0),
            )
    if ok_files:
        LOGGER.info("OK: %d file(s) with no findings: %s", len(ok_files), [r["file_name"] for r in ok_files])
    LOGGER.info("Scan complete. Results written to %s", args.output)


if __name__ == "__main__":
    main()

