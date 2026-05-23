-- Postgres full-text search via tsvector + weighted ranking.

ALTER TABLE contexts ADD COLUMN IF NOT EXISTS search_vector tsvector;
CREATE INDEX IF NOT EXISTS idx_ctx_fts ON contexts USING gin(search_vector);

CREATE OR REPLACE FUNCTION update_search_vector() RETURNS trigger AS $$
BEGIN
  NEW.search_vector :=
    setweight(to_tsvector('english', coalesce(NEW.title, '')), 'A') ||
    setweight(to_tsvector('english', coalesce(NEW.summary, '')), 'B') ||
    setweight(to_tsvector('english', coalesce(NEW.description, '')), 'B') ||
    setweight(to_tsvector('english', coalesce(NEW.domain, '')), 'C') ||
    setweight(to_tsvector('english', coalesce(array_to_string(NEW.tags, ' '), '')), 'C') ||
    setweight(to_tsvector('english', NEW.agent_id), 'D');
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS contexts_fts_update ON contexts;
CREATE TRIGGER contexts_fts_update
  BEFORE INSERT OR UPDATE OF title, summary, description, domain, tags, agent_id
  ON contexts FOR EACH ROW
  EXECUTE FUNCTION update_search_vector();
