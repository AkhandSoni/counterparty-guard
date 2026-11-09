ALTER TABLE executions ADD COLUMN finalized_block_height TEXT;

-- Retain polling timestamps as observations; backfill execution order from the
-- first retained finalized receipt, which established each terminal state.
UPDATE executions
SET finalized_block_height = (
  SELECT json_extract(r.receipt_json, '$.block_height')
  FROM execution_receipts r
  WHERE r.execution_id = executions.id
    AND json_extract(r.receipt_json, '$.finalized') = 1
    AND json_extract(r.receipt_json, '$.state') = executions.stage
    AND r.observed_at = executions.finalized_at
  ORDER BY r.rowid
  LIMIT 1
)
WHERE finalized = 1;

CREATE INDEX executions_history_height ON executions(
  agent_id, network, vault_id, receiver_id, stage, finalized,
  length(finalized_block_height) DESC, finalized_block_height DESC
);
