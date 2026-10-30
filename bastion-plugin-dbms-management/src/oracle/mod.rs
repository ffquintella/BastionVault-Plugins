//! Oracle Database sessions (T129, Phase 8): the session layer over the
//! Sans-I/O protocol crate (`tns`), the connection of one session (`conn`),
//! result values (`values`) and the browser, row edits and probe (`browse`).

pub mod browse;
pub mod conn;
pub mod tns;
pub mod values;
