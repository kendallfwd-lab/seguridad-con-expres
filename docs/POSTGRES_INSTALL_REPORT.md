# PostgreSQL local installation report

Installed at: 2026-11-25T10:16:26.9824410-06:00

- PostgreSQL command line tools: psql (PostgreSQL) 17.12
- Service readiness: successful on 127.0.0.1:5432.
- Development and test databases created with separate migrator and runtime roles.
- Versioned migration applied to both local databases.
- Runtime role was granted DML only in app_private; it has no database creation, role creation, schema creation, or DDL permissions.
- backend/.env was created locally and remains ignored by Git. No credential is recorded in this report.
