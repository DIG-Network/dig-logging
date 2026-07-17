//! The `tracing` layer that renders each event to a JSONL line (SPEC §2).
//!
//! It stamps the per-process static fields, flattens every span field in the event's scope
//! (root→leaf), and writes the rendered line through a [`MakeWriter`]. All shape decisions live in
//! [`schema`](crate::schema); this layer only gathers inputs from the tracing runtime.

use serde_json::{Map, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::Layer;

use crate::schema::{self, StaticFields};

/// Per-process static fields, owned so the layer outlives any borrow (SPEC §2/§6).
pub struct OwnedStatics {
    pub service: String,
    pub service_version: String,
    pub run_context: String,
    pub run_id: String,
    pub parent_op_id: Option<String>,
}

/// A layer that writes one JSONL record per event through `make_writer`.
pub struct DigJsonLayer<W> {
    statics: OwnedStatics,
    make_writer: W,
}

impl<W> DigJsonLayer<W> {
    /// Build the layer over its static fields and a line writer.
    pub fn new(statics: OwnedStatics, make_writer: W) -> Self {
        Self {
            statics,
            make_writer,
        }
    }
}

/// Span-scoped storage of a span's own fields, kept in the span's extensions until an event in its
/// scope flattens them.
struct SpanFields(Map<String, Value>);

/// Collect `tracing` field values into a JSON map. `record_debug` is the catch-all (it captures the
/// event `message` and any `Debug`-only field) and is ordered last so typed setters take precedence.
struct JsonVisitor<'a>(&'a mut Map<String, Value>);

impl Visit for JsonVisitor<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().into(), Value::from(value));
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.0.insert(field.name().into(), Value::from(value));
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.0.insert(field.name().into(), Value::from(value));
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.0.insert(field.name().into(), Value::from(value));
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.0.insert(field.name().into(), Value::from(value));
    }
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        self.0
            .insert(field.name().into(), Value::from(format!("{value:?}")));
    }
}

impl<S, W> Layer<S> for DigJsonLayer<W>
where
    S: Subscriber + for<'a> LookupSpan<'a>,
    W: for<'w> MakeWriter<'w> + 'static,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: Context<'_, S>,
    ) {
        let mut fields = Map::new();
        attrs.record(&mut JsonVisitor(&mut fields));
        if let Some(span) = ctx.span(id) {
            span.extensions_mut().insert(SpanFields(fields));
        }
    }

    fn on_record(
        &self,
        id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        ctx: Context<'_, S>,
    ) {
        if let Some(span) = ctx.span(id) {
            let mut ext = span.extensions_mut();
            if let Some(SpanFields(fields)) = ext.get_mut() {
                values.record(&mut JsonVisitor(fields));
            }
        }
    }

    fn on_event(&self, event: &Event<'_>, ctx: Context<'_, S>) {
        // Flatten span fields root→leaf so a leaf span shadows an ancestor (SPEC §2).
        let mut span_fields = Map::new();
        if let Some(scope) = ctx.event_scope(event) {
            for span in scope.from_root() {
                if let Some(SpanFields(fields)) = span.extensions().get() {
                    for (key, value) in fields {
                        span_fields.insert(key.clone(), value.clone());
                    }
                }
            }
        }

        let mut event_fields = Map::new();
        event.record(&mut JsonVisitor(&mut event_fields));

        let ts = OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_default();
        let statics = StaticFields {
            service: &self.statics.service,
            service_version: &self.statics.service_version,
            run_context: &self.statics.run_context,
            run_id: &self.statics.run_id,
            parent_op_id: self.statics.parent_op_id.as_deref(),
        };
        let record = schema::build_record(
            &statics,
            &event.metadata().level().to_string(),
            event.metadata().target(),
            &ts,
            span_fields,
            event_fields,
        );

        let mut line = schema::to_line(&record);
        line.push('\n');
        let mut writer = self.make_writer.make_writer();
        use std::io::Write;
        let _ = writer.write_all(line.as_bytes());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::layer::SubscriberExt;

    /// A `MakeWriter` capturing all output into a shared buffer, for asserting rendered lines.
    #[derive(Clone)]
    struct BufMaker(Arc<Mutex<Vec<u8>>>);
    impl Write for BufMaker {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    impl<'a> MakeWriter<'a> for BufMaker {
        type Writer = BufMaker;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    fn statics() -> OwnedStatics {
        OwnedStatics {
            service: "dig-node".into(),
            service_version: "1.0.0".into(),
            run_context: "service".into(),
            run_id: "run-1".into(),
            parent_op_id: Some("op-parent".into()),
        }
    }

    #[test]
    fn renders_event_with_flattened_span_fields_and_typed_values() {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry()
            .with(DigJsonLayer::new(statics(), BufMaker(buf.clone())));

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!(
                "download",
                op_id = "op-child",
                count = 5i64,
                ok = true,
                ratio = 1.5f64,
                size = 10u64
            );
            let _entered = span.enter();
            tracing::info!(peer = "203.0.113.7", "capsule fetched");
        });

        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        let line = out
            .lines()
            .find(|l| l.contains("capsule fetched"))
            .expect("event line");
        let record: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(record["service"], "dig-node");
        assert_eq!(record["parent_op_id"], "op-parent");
        assert_eq!(record["op_id"], "op-child"); // span field flattened
        assert_eq!(record["count"], 5);
        assert_eq!(record["ok"], true);
        assert_eq!(record["ratio"], 1.5);
        assert_eq!(record["size"], 10);
        assert_eq!(record["peer"], "203.0.113.7"); // event field
        assert_eq!(record["message"], "capsule fetched");
    }

    #[test]
    fn on_record_merges_late_span_values() {
        let buf = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::registry()
            .with(DigJsonLayer::new(statics(), BufMaker(buf.clone())));
        tracing::subscriber::with_default(subscriber, || {
            // A field declared empty then recorded later exercises `on_record`.
            let span = tracing::info_span!("op", stage = tracing::field::Empty);
            span.record("stage", "connect");
            let _e = span.enter();
            tracing::info!("in stage");
        });
        let out = String::from_utf8(buf.lock().unwrap().clone()).unwrap();
        assert!(out.contains("\"stage\":\"connect\""), "{out}");
    }
}
