//! Correlation ids (SPEC §6).
//!
//! - `run_id` — a UUIDv4 minted once at [`init`](crate::init), stamped on every record, so one
//!   process run is groupable across rotated files and restarts are distinguishable.
//! - `op_id` — a span field a consumer attaches to a top-level operation; it flattens onto every
//!   event inside the span (handled by the JSON layer), so it is a convention, not code here.
//! - `parent_op_id` — read once from the `DIG_OP_ID` env var, tying this run to the operation in the
//!   parent process that spawned it (installer → service; updater broker → worker).

use uuid::Uuid;

/// The reserved span-field name a consumer uses to tag a top-level operation (SPEC §6).
pub const OP_ID_FIELD: &str = "op_id";

/// The env var a parent process sets in a child's environment to propagate its operation id.
pub const ENV_DIG_OP_ID: &str = "DIG_OP_ID";

/// Mint a fresh run id for this process run.
pub fn new_run_id() -> String {
    Uuid::new_v4().to_string()
}

/// Read the propagated parent operation id from an injected env-getter: the `DIG_OP_ID` value when
/// present + non-blank, else `None`. Pure, so the pickup is testable without the process environment.
pub fn parent_op_id<G: Fn(&str) -> Option<String>>(get: G) -> Option<String> {
    get(ENV_DIG_OP_ID)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

/// Read the parent operation id from the real environment. See [`parent_op_id`].
pub fn parent_op_id_from_env() -> Option<String> {
    parent_op_id(|key| std::env::var(key).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn run_ids_are_unique_uuids() {
        let a = new_run_id();
        let b = new_run_id();
        assert_ne!(a, b);
        assert!(Uuid::parse_str(&a).is_ok());
    }

    #[test]
    fn parent_op_id_reads_non_blank_env() {
        let get = |key: &str| (key == ENV_DIG_OP_ID).then(|| "op-abc123".to_string());
        assert_eq!(parent_op_id(get), Some("op-abc123".to_string()));
    }

    #[test]
    fn parent_op_id_absent_or_blank_is_none() {
        assert_eq!(parent_op_id(|_| None), None);
        assert_eq!(parent_op_id(|_| Some("   ".to_string())), None);
    }
}
