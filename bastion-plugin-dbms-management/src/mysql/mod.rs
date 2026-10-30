//! MySQL and MariaDB sessions (features/sql-browser.md Phase 6, T127): the
//! `mysql_async` connection, value mapping, the object browser, row edits
//! and the `SHOW GRANTS` ceiling probe. Sessions, runs, exports, audit and
//! the journal are the engine-neutral modules the PostgreSQL path uses.

pub mod browse;
pub mod conn;
pub mod values;
