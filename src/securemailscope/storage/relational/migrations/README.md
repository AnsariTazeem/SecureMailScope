# SecureMailScope relational migrations

This Alembic environment owns only the relational schema. It never runs from
FastAPI startup or request handling, and application code must check the
revision without silently upgrading it.

For a new, disposable local SQLite database whose parent directory already
exists:

```bash
export SECUREMAILSCOPE_SQLITE_PATH=/absolute/path/to/local-securemailscope.sqlite3
uv run alembic -c alembic.ini upgrade head
uv run alembic -c alembic.ini current
```

Configuration validation and SQLAlchemy Engine construction create neither a
database file nor a directory. Every new database connection revalidates the
absolute target, existing parent, path components, file type, accessibility and
applicable permissions. `alembic.ini` contains no database URL, credential, or
production fallback.

On POSIX, a missing database is created relative to a securely traversed parent
directory with `os.open`, `O_CREAT|O_EXCL`, and `O_NOFOLLOW` when available.
The preparation descriptor is forced to owner read/write mode (`0600`) before
SQLite opens the verified file. Existing databases must be regular non-symlink
files owned by the application, readable and writable by it, and grant no group
or other permissions. The immediate persistent-storage parent must be owned by
the application, writable/searchable by it, and not group/world writable.
Symlinked target or parent/path components and target replacement detected at
connection time fail closed. Existing files are never silently chmodded and
parent directories are never created.

These POSIX mode-bit guarantees are not a claim of equivalent Windows ACL
enforcement. Non-POSIX deployments require a separately reviewed platform ACL
policy before persistent use.

The first durable-result revision is `9f3c2a1b7d4e`. The current projection
revision adds only `analysis_result_projections`, `analysis_result_protocols`,
their portable constraints and their bounded catalog indexes. During upgrade it
validates each existing canonical schema-1.0.0 Chain and backfills its complete
deterministic projection in the migration transaction; an unprojectable stored
result fails the upgrade instead of being skipped. A one-revision downgrade to
`9f3c2a1b7d4e` removes those projection structures and preserves
`analysis_results`, and re-upgrade derives them again from the preserved
canonical results. The full downgrade to `base` then drops
`analysis_results`; run that only on an intentionally disposable database:

```bash
uv run alembic -c alembic.ini downgrade base
```

SQLite foreign-key enforcement is enabled on every connection. Projection
membership cascades from its projection parent, which in turn cascades from the
authoritative `analysis_results` row. A 5-second DBAPI lock timeout bounds ordinary
lock contention. WAL is not enabled: this milestone has no measured concurrent
workload or durable queue, WAL adds checkpoint and sidecar-file operations, and
it is unsuitable for network-filesystem/multi-host use. SQLite remains a local,
single-instance development and test database; it is not a multi-instance job
queue.

Relational timestamps use one infrastructure-only UTC type. Bind values must be
`datetime` instances (or `None` for nullable `expires_at`), must be timezone
aware, and must have zero UTC offset. Naive and non-UTC values are rejected.
SQLite's timezone-naive `DATETIME` result is reconstructed as an aware UTC
`datetime`; PostgreSQL continues to compile relational timestamps as
`TIMESTAMP WITH TIME ZONE`. The historical `9f3c2a1b7d4e` revision remains
unchanged.
