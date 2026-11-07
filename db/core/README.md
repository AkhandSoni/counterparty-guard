# Core migrations

Owner: **A**.

`001_initial.sql` creates core identity/evidence/check/permit/execution/history tables. The API applies [the ordered manifest](../migrations.json), spanning core and future C report migrations, with applied IDs/positions/checksums. Append migrations; never rewrite applied SQL.

See [API persistence](../../docs/api.md) and [operations](../../docs/runbook.md).
