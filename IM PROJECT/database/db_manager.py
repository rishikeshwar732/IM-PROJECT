import logging
import os
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
from psycopg2.extras import DictCursor


LOGGER = logging.getLogger("guardrail_ai.db")


def _get_connection():
    try:
        conn = psycopg2.connect(
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", "5432")),
            dbname=os.getenv("DB_NAME", "guardrail_ai"),
            user=os.getenv("DB_USER", "guardrail_ai"),
            password=os.getenv("DB_PASSWORD", "guardrail_ai"),
            cursor_factory=DictCursor,
        )
        return conn
    except Exception as exc:
        LOGGER.error("Failed to establish PostgreSQL connection: %s", exc)
        raise


def init_db(schema_path: str) -> None:
    """
    Initialise the database using the provided schema.sql path.
    Safe to run multiple times.
    """
    LOGGER.info("Initialising database with schema %s", schema_path)
    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    conn = _get_connection()
    try:
        with conn, conn.cursor() as cur:
            cur.execute(schema_sql)
        LOGGER.info("Database schema applied successfully.")
    finally:
        conn.close()


def save_scan_results(
    project_name: str, scans: List[Dict[str, Any]]
) -> List[int]:
    """
    Persist scan and finding data as produced by core/scanner.py.

    :param project_name: Logical project or application name.
    :param scans: List of scan dictionaries (already JSON-deserialised).
    :return: List of inserted scan IDs.
    """
    if not scans:
        LOGGER.warning("No scans provided to save_scan_results; nothing to persist.")
        return []

    conn = _get_connection()
    inserted_ids: List[int] = []
    try:
        with conn:
            with conn.cursor() as cur:
                for scan in scans:
                    metrics = scan.get("metrics", {}) or {}
                    findings = scan.get("findings", []) or []

                    cur.execute(
                        """
                        INSERT INTO scans (
                            project_name,
                            scanned_at_utc,
                            manual_audit_hours,
                            tool_audit_seconds,
                            time_saved_hours,
                            compliance_score,
                            total_findings,
                            is_compliant
                        )
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING id;
                        """,
                        (
                            project_name,
                            scan.get("scanned_at_utc"),
                            metrics.get("manual_audit_hours", 4.0),
                            metrics.get("tool_audit_seconds", 5.0),
                            metrics.get("time_saved_hours", 4.0 - (5.0 / 3600.0)),
                            metrics.get("compliance_score", 100.0),
                            len(findings),
                            bool(scan.get("is_compliant", not findings)),
                        ),
                    )
                    scan_id = cur.fetchone()[0]
                    inserted_ids.append(scan_id)

                    for f in findings:
                        cur.execute(
                            """
                            INSERT INTO findings (
                                scan_id,
                                provider,
                                service,
                                severity,
                                message,
                                path,
                                recommendation_hint
                            )
                            VALUES (%s, %s, %s, %s, %s, %s, %s);
                            """,
                            (
                                scan_id,
                                f.get("provider", "unknown"),
                                f.get("service", "unknown"),
                                f.get("severity", "UNKNOWN"),
                                f.get("message", ""),
                                f.get("path"),
                                f.get("recommendation_hint"),
                            ),
                        )
        LOGGER.info("Persisted %d scan(s) to the database.", len(inserted_ids))
    except Exception as exc:
        LOGGER.error("Failed to save scan results: %s", exc)
        raise
    finally:
        conn.close()

    return inserted_ids


def load_innovation_metrics() -> Optional[Dict[str, Any]]:
    """
    Fetch aggregated metrics for management reporting
    from the innovation_velocity_metrics view.
    """
    conn = _get_connection()
    try:
        with conn, conn.cursor() as cur:
            cur.execute("SELECT * FROM innovation_velocity_metrics;")
            row = cur.fetchone()

        if not row:
            LOGGER.warning("No data available in innovation_velocity_metrics view yet.")
            return None

        data = dict(row)
        # Normalise Decimal types to float for easy JSON serialisation.
        normalised: Dict[str, Any] = {}
        for k, v in data.items():
            if v is None:
                normalised[k] = None
            elif hasattr(v, "quantize"):
                normalised[k] = float(v)
            else:
                normalised[k] = v

        LOGGER.info(
            "Loaded innovation metrics: total_scans=%s, total_time_saved_hours=%s, "
            "avg_compliance_score=%s, innovation_velocity_multiplier=%s",
            normalised.get("total_scans"),
            normalised.get("total_time_saved_hours"),
            normalised.get("avg_compliance_score"),
            normalised.get("innovation_velocity_multiplier"),
        )
        return normalised
    except Exception as exc:
        LOGGER.error("Failed to load innovation metrics: %s", exc)
        raise
    finally:
        conn.close()


def save_scan_results_from_file(project_name: str, path: str) -> List[int]:
    """
    Helper to load scanner output from disk and persist it.
    """
    import json

    if not os.path.isfile(path):
        raise FileNotFoundError(f"Scan results file not found: {path}")

    with open(path, "r", encoding="utf-8") as f:
        scans = json.load(f)

    if not isinstance(scans, list):
        raise ValueError("Expected scan results JSON to be a list.")
    return save_scan_results(project_name, scans)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description=(
            "GuardRail AI DB Manager - persists scan results and "
            "exposes aggregated innovation velocity metrics."
        )
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init", help="Initialise the database schema.")
    init_parser.add_argument(
        "--schema",
        default=os.path.join(os.path.dirname(__file__), "schema.sql"),
        help="Path to schema.sql (defaults to bundled file).",
    )

    save_parser = subparsers.add_parser(
        "save", help="Persist scan results from a JSON file."
    )
    save_parser.add_argument(
        "--project",
        required=True,
        help="Logical project name (e.g., team or application).",
    )
    save_parser.add_argument(
        "--scan-results",
        required=True,
        help="Path to JSON produced by core/scanner.py.",
    )

    metrics_parser = subparsers.add_parser(
        "metrics", help="Print aggregated innovation velocity metrics as JSON."
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
        if args.command == "init":
            init_db(args.schema)
        elif args.command == "save":
            ids = save_scan_results_from_file(args.project, args.scan_results)
            print(f"Inserted scan IDs: {ids}")
        elif args.command == "metrics":
            metrics = load_innovation_metrics()
            import json

            print(json.dumps(metrics or {}, indent=2))
    except Exception as exc:
        LOGGER.error("DB manager command failed: %s", exc)
        raise SystemExit(1) from exc


if __name__ == "__main__":
    main()

