-- Audience visibility is read directly from body_json (`body.audience`)
-- by the visibility predicates. The dedicated table was write-only and
-- never read; remove it so the schema reflects actual usage.
DROP INDEX IF EXISTS idx_audience_agent;
DROP TABLE IF EXISTS context_audience;
