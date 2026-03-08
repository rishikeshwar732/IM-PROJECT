-- GuardRail AI - Management-Focused Reporting Schema
-- This schema is intentionally compact and focused on leadership KPIs:
-- - How many scans are we running?
-- - How much manual audit time have we avoided?
-- - Are our policies trending toward higher compliance over time?

CREATE TABLE IF NOT EXISTS scans (
    id                  BIGSERIAL PRIMARY KEY,
    project_name        TEXT NOT NULL,
    scanned_at_utc      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source_tool         TEXT NOT NULL DEFAULT 'guardrail-ai-scanner',

    -- Raw timing metrics
    manual_audit_hours  NUMERIC(10, 4) NOT NULL,
    tool_audit_seconds  NUMERIC(10, 4) NOT NULL,
    time_saved_hours    NUMERIC(10, 4) NOT NULL,

    -- Compliance as a management-friendly score (0-100)
    compliance_score    NUMERIC(5, 2) NOT NULL,

    -- Convenience aggregations
    total_findings      INTEGER NOT NULL DEFAULT 0,
    is_compliant        BOOLEAN NOT NULL DEFAULT FALSE
);


CREATE TABLE IF NOT EXISTS findings (
    id              BIGSERIAL PRIMARY KEY,
    scan_id         BIGINT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,

    provider        TEXT NOT NULL,
    service         TEXT NOT NULL,
    severity        TEXT NOT NULL,
    message         TEXT NOT NULL,
    path            TEXT,
    recommendation_hint TEXT,

    created_at_utc  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);


-- View to power the dashboard: innovation velocity KPIs.
CREATE OR REPLACE VIEW innovation_velocity_metrics AS
SELECT
    COUNT(*)                           AS total_scans,
    COALESCE(SUM(time_saved_hours),0)  AS total_time_saved_hours,
    COALESCE(AVG(compliance_score),0)  AS avg_compliance_score,
    COALESCE(SUM(total_findings),0)    AS total_findings,

    -- Scans per hour if teams relied solely on manual audits (4h per scan)
    1.0 / NULLIF(AVG(manual_audit_hours), 0) AS manual_scans_per_hour,

    -- Scans per hour with the automated tool (5s per scan by design)
    3600.0 / NULLIF(AVG(tool_audit_seconds), 0) AS automated_scans_per_hour,

    -- How many times faster the organisation can safely iterate on policies.
    CASE
        WHEN AVG(tool_audit_seconds) IS NULL OR AVG(tool_audit_seconds) = 0
            OR AVG(manual_audit_hours) IS NULL OR AVG(manual_audit_hours) = 0
        THEN NULL
        ELSE (3600.0 / AVG(tool_audit_seconds)) / (1.0 / AVG(manual_audit_hours))
    END AS innovation_velocity_multiplier
FROM scans;

