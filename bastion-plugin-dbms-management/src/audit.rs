//! Audit events (features/sql-browser.md §11). The host stamps the actor;
//! payloads carry no statement text, value or credential. Host calls are
//! refused outside an invocation, so a background event (a run ending, an
//! idle close, a seal) waits in its owner's outbox and is emitted during that
//! owner's next invocation, never under another caller's identity.

use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

use serde_json::{json, Value};

use crate::api::Owner;
use crate::host::Host;

/// Most events kept per owner while waiting; older ones are dropped and
/// counted, and the count is itself reported.
pub const MAX_PENDING_PER_OWNER: usize = 1_000;

#[derive(Debug, Clone)]
pub enum Pending {
    Audit(Value),
    /// Write `record` at `key` (the session's journal record).
    Journal {
        key: String,
        record: Value,
    },
}

#[derive(Default)]
struct Queue {
    items: VecDeque<Pending>,
    dropped: u64,
}

/// Per-owner queues of events that happened outside the owner's invocation.
#[derive(Default)]
pub struct Outbox(Mutex<BTreeMap<Owner, Queue>>);

impl Outbox {
    pub fn push(&self, owner: &Owner, item: Pending) {
        let mut map = self.0.lock().unwrap_or_else(|p| p.into_inner());
        let q = map.entry(owner.clone()).or_default();
        if let Pending::Journal { key, .. } = &item {
            // Only the newest snapshot of a journal record matters.
            q.items.retain(|p| !matches!(p, Pending::Journal { key: k, .. } if k == key));
        }
        if q.items.len() >= MAX_PENDING_PER_OWNER {
            q.items.pop_front();
            q.dropped += 1;
        }
        q.items.push_back(item);
    }

    /// Emit everything queued for `owner` through `host`, which must be
    /// serving an invocation by that owner. A failed write is kept.
    pub fn flush(&self, owner: &Owner, host: &dyn Host) {
        let (items, dropped) = {
            let mut map = self.0.lock().unwrap_or_else(|p| p.into_inner());
            match map.remove(owner) {
                Some(q) => (q.items, q.dropped),
                None => return,
            }
        };
        if dropped > 0 {
            let _ = host.audit(json!({"event": "dbms.audit_overflow", "dropped": dropped}));
        }
        let mut keep = VecDeque::new();
        for item in items {
            let ok = match &item {
                Pending::Audit(v) => host.audit(v.clone()).is_ok(),
                Pending::Journal { key, record } => {
                    serde_json::to_vec(record).map(|b| host.storage_put(key, &b).is_ok()).unwrap_or(true)
                }
            };
            if !ok {
                keep.push_back(item);
            }
        }
        if !keep.is_empty() {
            let mut map = self.0.lock().unwrap_or_else(|p| p.into_inner());
            let q = map.entry(owner.clone()).or_default();
            for item in keep.into_iter().rev() {
                q.items.push_front(item);
            }
        }
    }

    pub fn pending(&self, owner: &Owner) -> usize {
        self.0.lock().unwrap_or_else(|p| p.into_inner()).get(owner).map(|q| q.items.len()).unwrap_or(0)
    }
}

/// The fields every event of a session carries (§11).
pub fn base(event: &str, session: &str, resource: &str, profile: &str, db_enforced: bool) -> Value {
    json!({"event": event, "session": session, "resource": resource, "profile": profile, "db_enforced": db_enforced})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner(e: &str) -> Owner {
        Owner {
            entity_id: e.into(),
            namespace: String::new(),
            principal_mount: "userpass/".into(),
            principal_name: e.into(),
        }
    }

    #[test]
    fn the_outbox_keeps_owners_apart_and_bounds_itself() {
        let ob = Outbox::default();
        for i in 0..(MAX_PENDING_PER_OWNER + 5) {
            ob.push(&owner("ana"), Pending::Audit(json!({"i": i})));
        }
        ob.push(&owner("bob"), Pending::Audit(json!({"i": 0})));
        assert_eq!(ob.pending(&owner("ana")), MAX_PENDING_PER_OWNER);
        assert_eq!(ob.pending(&owner("bob")), 1);
        ob.push(&owner("bob"), Pending::Journal { key: "k".into(), record: json!(1) });
        ob.push(&owner("bob"), Pending::Journal { key: "k".into(), record: json!(2) });
        assert_eq!(ob.pending(&owner("bob")), 2, "a newer journal snapshot replaces the older one");
    }
}
