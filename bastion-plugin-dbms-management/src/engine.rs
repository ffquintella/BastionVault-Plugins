//! The database engine of a session and its connection (T127). Sessions,
//! runs and the lifecycle hold a [`DbConn`]; what is engine-specific
//! (connecting, catalog reads, row edits, the probe) dispatches on it.

use std::sync::Arc;

use bv_sql_classify::{Dialect, NameContext, ObjectRef};

use serde_json::Value;
use tokio::sync::{mpsc, oneshot};

use crate::authz::{AuthorizedStatement, Resolutions};
use crate::driver::{DbError, PgConn, PluginSql};
use crate::mssql::conn::MsConn;
use crate::mysql::conn::MyConn;
use crate::oracle::conn::OraConn;
use crate::wire::TxStatus;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    PostgreSql,
    MySql,
    MariaDb,
    MsSql,
    Oracle,
}

impl Engine {
    /// The resource record's `engine`; `None` for one this plugin does not
    /// serve.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "postgresql" => Some(Self::PostgreSql),
            "mysql" => Some(Self::MySql),
            "mariadb" => Some(Self::MariaDb),
            "mssql" => Some(Self::MsSql),
            "oracle" => Some(Self::Oracle),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::PostgreSql => "postgresql",
            Self::MySql => "mysql",
            Self::MariaDb => "mariadb",
            Self::MsSql => "mssql",
            Self::Oracle => "oracle",
        }
    }

    pub fn dialect(self) -> Dialect {
        match self {
            Self::PostgreSql => Dialect::PostgreSql,
            Self::MySql => Dialect::MySql,
            Self::MariaDb => Dialect::MariaDb,
            Self::MsSql => Dialect::MsSql,
            Self::Oracle => Dialect::Oracle,
        }
    }
}

/// A session's live connection.
#[derive(Clone)]
pub enum DbConn {
    Pg(Arc<PgConn>),
    My(Arc<MyConn>),
    Ms(Arc<MsConn>),
    Ora(Arc<OraConn>),
}

impl DbConn {
    pub fn taint(&self) -> Option<String> {
        match self {
            Self::Pg(c) => c.wire().taint(),
            Self::My(c) => c.taint(),
            Self::Ms(c) => c.taint(),
            Self::Ora(c) => c.taint(),
        }
    }

    pub fn tx(&self) -> TxStatus {
        match self {
            Self::Pg(c) => c.wire().tx(),
            Self::My(c) => c.tx(),
            Self::Ms(c) => c.tx(),
            Self::Ora(c) => c.tx(),
        }
    }

    pub fn is_closed(&self) -> bool {
        match self {
            Self::Pg(c) => c.is_closed(),
            Self::My(c) => c.is_closed(),
            Self::Ms(c) => c.is_closed(),
            Self::Ora(c) => c.is_closed(),
        }
    }

    pub fn shutdown(&self) {
        match self {
            Self::Pg(c) => c.shutdown(),
            Self::My(c) => c.shutdown(),
            Self::Ms(c) => c.shutdown(),
            Self::Ora(c) => c.shutdown(),
        }
    }

    /// Stop the running statement: a `CancelRequest` (PostgreSQL), `KILL
    /// QUERY` on a side connection (MySQL / MariaDB), the TDS attention
    /// signal (SQL Server) or an in-band BREAK (Oracle).
    pub async fn cancel(&self) -> Result<(), DbError> {
        match self {
            Self::Pg(c) => c.cancel().await,
            Self::My(c) => c.cancel().await,
            Self::Ms(c) => c.cancel().await,
            Self::Ora(c) => c.cancel().await,
        }
    }

    /// Plugin-authored SQL without a result (`BEGIN`, `COMMIT`, `ROLLBACK`).
    pub async fn internal_execute(&self, sql: &PluginSql) -> Result<u64, DbError> {
        match self {
            Self::Pg(c) => c.internal_execute(sql).await,
            Self::My(c) => c.internal_execute(sql).await,
            Self::Ms(c) => c.internal_execute(sql).await,
            Self::Ora(c) => c.internal_execute(sql).await,
        }
    }

    /// The classifier's name context, re-read from the session.
    pub async fn read_context(&self, database_read_only: bool) -> Result<NameContext, DbError> {
        match self {
            Self::Pg(c) => crate::session::read_context(c, database_read_only).await,
            Self::My(c) => c.read_context(database_read_only).await,
            Self::Ms(c) => c.read_context(database_read_only).await,
            Self::Ora(c) => c.read_context(database_read_only).await,
        }
    }

    /// Resolve unqualified names (§4.4). MySQL names are always qualified
    /// by the classifier (the current database), so nothing is left; any
    /// reference that is stays unaddressable.
    pub async fn resolve(&self, refs: &[ObjectRef]) -> Result<Resolutions, DbError> {
        match self {
            Self::Pg(c) => crate::session::resolve(c, refs).await,
            Self::My(_) => Ok(refs.iter().map(|r| (r.clone(), None)).collect()),
            Self::Ms(c) => c.resolve(refs).await,
            Self::Ora(c) => c.resolve(refs).await,
        }
    }
}

/// A result column of a channel-streamed statement (MySQL / MariaDB, SQL
/// Server and Oracle): what the grid and the exporters need.
#[derive(Debug, Clone)]
pub struct ChanCol {
    pub name: String,
    pub json: Value,
    pub numeric: bool,
    pub binary: bool,
}

/// A statement whose rows a driver task streams through a bounded channel
/// (§6.3): its columns, its rows as JSON cells, then how it ended.
pub struct ChanQuery {
    pub columns: Vec<ChanCol>,
    pub rows: mpsc::Receiver<Result<Vec<Value>, DbError>>,
    pub end: oneshot::Receiver<Result<u64, DbError>>,
}

/// The connections whose statements stream through a channel; runs and
/// exports drive both the same way.
#[derive(Clone)]
pub enum Streamed {
    My(Arc<MyConn>),
    Ms(Arc<MsConn>),
    Ora(Arc<OraConn>),
}

impl Streamed {
    /// Send one authorized statement (the engine's only path for caller
    /// SQL).
    pub async fn send_authorized(&self, stmt: AuthorizedStatement) -> Result<ChanQuery, DbError> {
        match self {
            Self::My(c) => {
                let q = c.send_authorized(stmt).await?;
                let columns = q
                    .columns
                    .iter()
                    .map(|m| ChanCol { name: m.name.clone(), json: m.json(), numeric: m.numeric(), binary: m.binary() })
                    .collect();
                Ok(ChanQuery { columns, rows: q.rows, end: q.end })
            }
            Self::Ms(c) => {
                let q = c.send_authorized(stmt).await?;
                let columns = q
                    .columns
                    .iter()
                    .map(|m| ChanCol { name: m.name.clone(), json: m.json(), numeric: m.numeric(), binary: m.binary() })
                    .collect();
                Ok(ChanQuery { columns, rows: q.rows, end: q.end })
            }
            Self::Ora(c) => {
                let q = c.send_authorized(stmt).await?;
                let columns = q
                    .columns
                    .iter()
                    .map(|m| ChanCol { name: m.name.clone(), json: m.json(), numeric: m.numeric, binary: m.binary() })
                    .collect();
                Ok(ChanQuery { columns, rows: q.rows, end: q.end })
            }
        }
    }

    pub async fn cancel(&self) -> Result<(), DbError> {
        match self {
            Self::My(c) => c.cancel().await,
            Self::Ms(c) => c.cancel().await,
            Self::Ora(c) => c.cancel().await,
        }
    }
}
