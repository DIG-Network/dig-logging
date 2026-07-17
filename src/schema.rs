//! The JSONL record model (SPEC §2).
//!
//! One JSON object per line. This module builds that object PURELY from its inputs — the per-process
//! static fields, the event's level/target/timestamp, the flattened span fields, and the event's own
//! fields — so the exact wire shape is golden-testable without a live subscriber. The tracing
//! [`layer`](crate::layer) gathers the inputs; this module decides the shape.
//!
//! Ordering: `serde_json`'s `preserve_order` feature keeps insertion order, so lines read top-to-
//! bottom as the SPEC §2 table lists them. Field order is not significant to consumers.

use serde_json::{Map, Value};

/// The current schema version emitted in the `schema` field. Bumping is additive-only (SPEC §2).
pub const SCHEMA_VERSION: u64 = 1;

/// The reserved event field carrying the human message; lifted to the top-level `message` field.
pub const MESSAGE_FIELD: &str = "message";

/// The per-process fields stamped on every record (SPEC §2). Borrowed — cheap to build per event.
pub struct StaticFields<'a> {
    /// The caller's service name (`dig-node`, `dig-dns`, …).
    pub service: &'a str,
    /// The caller's service version (its `CARGO_PKG_VERSION`).
    pub service_version: &'a str,
    /// `service` or `cli` (SPEC §2).
    pub run_context: &'a str,
    /// The UUIDv4 minted at init (SPEC §6).
    pub run_id: &'a str,
    /// The propagated parent operation id from `DIG_OP_ID`, if any (SPEC §6).
    pub parent_op_id: Option<&'a str>,
}

/// Build one record as an ordered JSON map (SPEC §2).
///
/// `ts` is a pre-formatted RFC 3339 UTC string. `span_fields` is already merged root→leaf by the
/// layer (so a leaf shadows an ancestor). `event_fields` are the event's own fields; its `message`
/// (if any) is lifted to the top-level `message`, and event fields shadow span fields of the same
/// name. `op_id` — when present among the span fields — is ordered right after the correlation ids.
pub fn build_record(
    statics: &StaticFields<'_>,
    level: &str,
    target: &str,
    ts: &str,
    mut span_fields: Map<String, Value>,
    mut event_fields: Map<String, Value>,
) -> Map<String, Value> {
    let message = event_fields
        .remove(MESSAGE_FIELD)
        .and_then(|value| value.as_str().map(str::to_string))
        .unwrap_or_default();

    let mut record = Map::new();
    record.insert("schema".into(), Value::from(SCHEMA_VERSION));
    record.insert("ts".into(), Value::from(ts));
    record.insert("level".into(), Value::from(level));
    record.insert("target".into(), Value::from(target));
    record.insert(MESSAGE_FIELD.into(), Value::from(message));
    record.insert("service".into(), Value::from(statics.service));
    record.insert(
        "service_version".into(),
        Value::from(statics.service_version),
    );
    record.insert("run_context".into(), Value::from(statics.run_context));
    record.insert("run_id".into(), Value::from(statics.run_id));
    if let Some(parent) = statics.parent_op_id {
        record.insert("parent_op_id".into(), Value::from(parent));
    }
    // Order op_id right after the correlation ids (SPEC §2 table), then the remaining span fields.
    if let Some(op_id) = span_fields.remove(crate::correlation::OP_ID_FIELD) {
        record.insert(crate::correlation::OP_ID_FIELD.into(), op_id);
    }
    record.append(&mut span_fields);
    // Event fields land last and shadow same-named span fields (SPEC §2).
    for (key, value) in event_fields {
        record.insert(key, value);
    }
    record
}

/// Serialize a record to a single JSONL line (no trailing newline). The writer appends `\n`.
pub fn to_line(record: &Map<String, Value>) -> String {
    Value::Object(record.clone()).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn statics() -> StaticFields<'static> {
        StaticFields {
            service: "dig-node",
            service_version: "1.2.3",
            run_context: "service",
            run_id: "11111111-1111-4111-8111-111111111111",
            parent_op_id: None,
        }
    }

    #[test]
    fn golden_minimal_line() {
        let record = build_record(
            &statics(),
            "INFO",
            "dig_node::serve",
            "2026-07-16T00:00:00Z",
            Map::new(),
            {
                let mut m = Map::new();
                m.insert("message".into(), Value::from("listening"));
                m
            },
        );
        assert_eq!(
            to_line(&record),
            r#"{"schema":1,"ts":"2026-07-16T00:00:00Z","level":"INFO","target":"dig_node::serve","message":"listening","service":"dig-node","service_version":"1.2.3","run_context":"service","run_id":"11111111-1111-4111-8111-111111111111"}"#
        );
    }

    #[test]
    fn op_id_ordered_after_correlation_and_parent_included() {
        let mut statics = statics();
        statics.parent_op_id = Some("op-parent");
        let mut span = Map::new();
        span.insert("op_id".into(), Value::from("op-child"));
        span.insert("peer".into(), Value::from("1.2.3.4"));
        let record = build_record(
            &statics,
            "WARN",
            "t",
            "2026-07-16T00:00:00Z",
            span,
            Map::new(),
        );
        let line = to_line(&record);
        // parent_op_id then op_id then the remaining span field, in that order.
        let parent = line.find("parent_op_id").unwrap();
        let op = line.find("\"op_id\"").unwrap();
        let peer = line.find("peer").unwrap();
        assert!(parent < op && op < peer, "line: {line}");
    }

    #[test]
    fn event_field_shadows_span_field() {
        let mut span = Map::new();
        span.insert("stage".into(), Value::from("connect"));
        let mut event = Map::new();
        event.insert("stage".into(), Value::from("handshake"));
        let record = build_record(&statics(), "INFO", "t", "2026-07-16T00:00:00Z", span, event);
        assert_eq!(record.get("stage"), Some(&Value::from("handshake")));
    }

    #[test]
    fn missing_message_becomes_empty_string() {
        let record = build_record(
            &statics(),
            "INFO",
            "t",
            "2026-07-16T00:00:00Z",
            Map::new(),
            Map::new(),
        );
        assert_eq!(record.get("message"), Some(&Value::from("")));
    }
}
