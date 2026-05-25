-- 90-day retention cleanup. Runs once per day via the receiver-side
-- scheduler (Cloudflare cron triggers, GitHub Actions on a schedule,
-- or ClickHouse's own TTL — whichever the operator prefers).
--
-- This script is idempotent: re-running deletes only rows older
-- than the cutoff, never rows still inside the window.

-- Table shape mirrors the validated payload from ingest.ts. Operators
-- create this once at deploy time; the cleanup script doesn't create
-- or alter it.
--
-- CREATE TABLE telemetry.pings (
--     ingested_at           DateTime64(3, 'UTC'),
--     install_id_hash       FixedString(64),
--     rts_version           LowCardinality(String),
--     os                    LowCardinality(String),
--     arch                  LowCardinality(String),
--     uptime_hours          UInt32,
--     languages_indexed     Array(LowCardinality(String)),
--     method_counts         Map(LowCardinality(String), UInt64),
--     method_latency_p50_ms Map(LowCardinality(String), UInt64),
--     method_latency_p99_ms Map(LowCardinality(String), UInt64),
--     error_counts          Map(LowCardinality(String), UInt64),
--     cache_hit_rate        Float32,
--     cold_walk_ms_p50      UInt32,
--     workspace_size_bucket LowCardinality(String)
-- )
-- ENGINE = MergeTree
-- PARTITION BY toYYYYMM(ingested_at)
-- ORDER BY ingested_at
-- TTL ingested_at + INTERVAL 90 DAY DELETE;
--
-- The TTL clause above is the load-bearing retention enforcement.
-- The DELETE below is a belt-and-braces extra in case a deployment
-- forgets the TTL.

ALTER TABLE telemetry.pings
    DELETE WHERE ingested_at < now() - INTERVAL 90 DAY;
