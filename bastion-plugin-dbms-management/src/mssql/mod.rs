//! SQL Server sessions (features/sql-browser.md Phase 7, T128): the
//! `tiberius` connection over the plugin's own TLS negotiation, value
//! mapping, the object browser, row edits and the `fn_my_permissions`
//! ceiling probe. Sessions, runs, exports, audit and the journal are the
//! engine-neutral modules the other engines use.

pub mod browse;
pub mod conn;
pub mod tds_tls;
pub mod values;
