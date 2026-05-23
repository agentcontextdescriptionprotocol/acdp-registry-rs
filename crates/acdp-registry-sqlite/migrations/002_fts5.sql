-- FTS5 virtual table over the bounded search fields. Kept in sync with
-- `contexts` via triggers.

CREATE VIRTUAL TABLE IF NOT EXISTS contexts_fts USING fts5(
    ctx_id UNINDEXED,
    title,
    summary,
    description,
    domain,
    tags,
    agent_id
);

CREATE TRIGGER IF NOT EXISTS contexts_fts_insert AFTER INSERT ON contexts BEGIN
    INSERT INTO contexts_fts(ctx_id, title, summary, description, domain, tags, agent_id)
    VALUES (new.ctx_id,
            new.title,
            COALESCE(new.summary, ''),
            COALESCE(new.description, ''),
            COALESCE(new.domain, ''),
            new.tags,
            new.agent_id);
END;

CREATE TRIGGER IF NOT EXISTS contexts_fts_delete AFTER DELETE ON contexts BEGIN
    DELETE FROM contexts_fts WHERE ctx_id = old.ctx_id;
END;

CREATE TRIGGER IF NOT EXISTS contexts_fts_update AFTER UPDATE OF
    title, summary, description, domain, tags, agent_id
ON contexts BEGIN
    DELETE FROM contexts_fts WHERE ctx_id = old.ctx_id;
    INSERT INTO contexts_fts(ctx_id, title, summary, description, domain, tags, agent_id)
    VALUES (new.ctx_id,
            new.title,
            COALESCE(new.summary, ''),
            COALESCE(new.description, ''),
            COALESCE(new.domain, ''),
            new.tags,
            new.agent_id);
END;
