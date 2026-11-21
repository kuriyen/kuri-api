//! The surface this crate mirrors: every table, struct, enum, union and
//! constant whose definition lives elsewhere, with its members.
//!
//! `tests/surface.json` is generated from the types themselves, so it cannot
//! drift from them: a test fails if file and generator disagree. The check
//! that keeps this crate in step with the definition reads that file and
//! requires every member on both sides; this crate is not published until
//! that check has passed against the commit being published.

use std::collections::BTreeMap;
use std::path::Path;

use kuri_api::grant::{Grant, GrantError, GrantRequest, PrincipalId, MAX_GRANT_LIFETIME_NS};
use kuri_api::power::{
    PowerError, PowerHoldRequest, PowerHoldResponse, PowerReleaseRequest, PowerRenewRequest,
    PowerRenewResponse, PowerWakeRequest, HOLD_ID_LEN, MAX_HOLD_NS,
};
use kuri_api::registry::{
    Accelerator, AcceleratorKind, Announcement, Capability, CapabilityKind, Compute, Health, Link,
    LinkKind, NodeEvent, NodeId, NodeState, Rdma, RegistryError, RegistryReaderWatchResponse,
    Scope, MAX_ACCELERATORS, MAX_CAPABILITIES, MAX_COMPUTE_CAPABILITIES, MAX_LINKS, MAX_NODES,
    MAX_NODE_EVENTS, WATCH_TICK_NS,
};
use serde::Serialize;
use serde_json::{json, Value};

const PATH: &str = "tests/surface.json";

/// The field names `value` encodes, which for a value with every field
/// present are all its fields.
fn fields<T: Serialize>(value: &T) -> Vec<String> {
    match serde_json::to_value(value).unwrap() {
        Value::Object(map) => {
            // Sorted, as the keys of a `BTreeMap` are, whether or not
            // serde_json's `preserve_order` is on.
            let mut keys: Vec<String> = map.keys().cloned().collect();
            keys.sort();
            keys
        }
        other => panic!("not a map: {other}"),
    }
}

/// A Rust type's name without its paths: `core::option::Option<u64>` ->
/// `Option<u64>`.
fn short(name: &str) -> String {
    let mut out = String::new();
    let mut word = String::new();
    for c in name.chars().chain(std::iter::once(' ')) {
        if c.is_alphanumeric() || c == '_' || c == ':' {
            word.push(c);
        } else {
            out.push_str(word.rsplit("::").next().unwrap());
            word.clear();
            if c != ' ' || !out.is_empty() && !out.ends_with(';') {
                out.push(c);
            }
        }
    }
    out.trim_end().to_owned()
}

/// Each field of a struct value with its Rust type, by destructuring it: a
/// field left out does not compile, and the names must be the ones the value
/// encodes.
macro_rules! shape {
    ($value:expr, $t:ident { $($f:ident),* $(,)? }) => {{
        let value = $value;
        let keys = fields(&value);
        let $t { $($f),* } = value;
        let map: BTreeMap<String, String> = BTreeMap::from([
            $((stringify!($f).to_owned(), short(std::any::type_name_of_val(&$f)))),*
        ]);
        assert_eq!(
            map.keys().cloned().collect::<Vec<_>>(),
            keys,
            "{} encodes other field names than it has",
            stringify!($t)
        );
        map
    }};
}

fn node() -> NodeId {
    NodeId { bytes: vec![1] }
}

fn accelerator() -> Accelerator {
    Accelerator {
        kind: Some(AcceleratorKind::Gpu),
        model: Some(String::new()),
        memory_bytes: Some(0),
    }
}

fn compute() -> Compute {
    Compute {
        accelerators: Some(vec![]),
        memory_bytes: Some(0),
    }
}

fn capability() -> Capability {
    Capability {
        kind: Some(CapabilityKind::Compute),
        instance: Some(String::new()),
        scope: Some(Scope::OwnerPrivate),
        compute: Some(compute()),
    }
}

fn link() -> Link {
    Link {
        kind: Some(LinkKind::Ethernet),
        speed_bps: Some(0),
        rdma: Some(Rdma::None),
        peer: Some(node()),
        segment: Some(String::new()),
    }
}

fn announcement() -> Announcement {
    Announcement {
        node: Some(node()),
        label: Some(String::new()),
        capabilities: Some(vec![]),
        links: Some(vec![]),
    }
}

fn node_state() -> NodeState {
    NodeState {
        announcement: Some(announcement()),
        health: Some(Health::Online),
        last_seen_monotonic_ns: Some(0),
    }
}

fn members<E: Copy>(all: &[E], name: fn(E) -> &'static str, number: fn(E) -> Option<u32>) -> Value {
    let map: BTreeMap<&str, u32> = all.iter().map(|&e| (name(e), number(e).unwrap())).collect();
    json!(map)
}

macro_rules! enums {
    ($($t:ident),* $(,)?) => {{
        let mut map = BTreeMap::new();
        $(map.insert(stringify!($t), members($t::ALL, $t::name, $t::number));)*
        map
    }};
}

fn build() -> String {
    let id = [0u8; HOLD_ID_LEN];
    let full_grant = Grant {
        principal: Some(PrincipalId::default()),
        provider: Some(node()),
        kind: Some(CapabilityKind::Sensor),
        instance: Some(String::new()),
        scope: Some(Scope::OwnerPrivate),
        holder_key: Some(vec![]),
        grant_id: Some(vec![]),
        expires_utc_ns: Some(0),
        issued_epoch: Some(vec![]),
        max_lifetime_ns: Some(0),
        signature: Some(vec![]),
    };
    let full_request = GrantRequest {
        principal: Some(PrincipalId::default()),
        provider: Some(node()),
        kind: Some(CapabilityKind::Sensor),
        instance: Some(String::new()),
        holder_key: Some(vec![]),
    };
    let tables: BTreeMap<&str, BTreeMap<String, String>> = BTreeMap::from([
        (
            "Accelerator",
            shape!(
                accelerator(),
                Accelerator {
                    kind,
                    model,
                    memory_bytes
                }
            ),
        ),
        (
            "Announcement",
            shape!(
                announcement(),
                Announcement {
                    node,
                    label,
                    capabilities,
                    links
                }
            ),
        ),
        (
            "Capability",
            shape!(
                capability(),
                Capability {
                    kind,
                    instance,
                    scope,
                    compute
                }
            ),
        ),
        (
            "Compute",
            shape!(
                compute(),
                Compute {
                    accelerators,
                    memory_bytes
                }
            ),
        ),
        (
            "Grant",
            shape!(
                full_grant,
                Grant {
                    principal,
                    provider,
                    kind,
                    instance,
                    scope,
                    holder_key,
                    grant_id,
                    expires_utc_ns,
                    issued_epoch,
                    max_lifetime_ns,
                    signature,
                }
            ),
        ),
        (
            "GrantRequest",
            shape!(
                full_request,
                GrantRequest {
                    principal,
                    provider,
                    kind,
                    instance,
                    holder_key
                }
            ),
        ),
        (
            "Link",
            shape!(
                link(),
                Link {
                    kind,
                    speed_bps,
                    rdma,
                    peer,
                    segment
                }
            ),
        ),
        (
            "NodeState",
            shape!(
                node_state(),
                NodeState {
                    announcement,
                    health,
                    last_seen_monotonic_ns
                }
            ),
        ),
    ]);
    let structs: BTreeMap<&str, BTreeMap<String, String>> = BTreeMap::from([
        ("NodeId", shape!(node(), NodeId { bytes })),
        (
            "PrincipalId",
            shape!(PrincipalId::default(), PrincipalId { bytes }),
        ),
        (
            "PowerHoldRequest",
            shape!(
                PowerHoldRequest::default(),
                PowerHoldRequest { node, duration_ns }
            ),
        ),
        (
            "PowerHoldResponse",
            shape!(
                PowerHoldResponse {
                    hold_id: id,
                    until_ns: 0
                },
                PowerHoldResponse { hold_id, until_ns }
            ),
        ),
        (
            "PowerReleaseRequest",
            shape!(
                PowerReleaseRequest { hold_id: id },
                PowerReleaseRequest { hold_id }
            ),
        ),
        (
            "PowerRenewRequest",
            shape!(
                PowerRenewRequest {
                    hold_id: id,
                    duration_ns: 0
                },
                PowerRenewRequest {
                    hold_id,
                    duration_ns
                }
            ),
        ),
        (
            "PowerRenewResponse",
            shape!(
                PowerRenewResponse::default(),
                PowerRenewResponse { until_ns }
            ),
        ),
        (
            "PowerWakeRequest",
            shape!(PowerWakeRequest::default(), PowerWakeRequest { node }),
        ),
        (
            "RegistryReaderWatchResponse",
            shape!(
                RegistryReaderWatchResponse::default(),
                RegistryReaderWatchResponse { events }
            ),
        ),
    ]);
    let enums = enums!(
        AcceleratorKind,
        CapabilityKind,
        GrantError,
        Health,
        LinkKind,
        PowerError,
        Rdma,
        RegistryError,
        Scope,
    );
    let union_members = |events: Vec<NodeEvent>| -> Vec<String> {
        events
            .iter()
            .map(|e| match serde_json::to_value(e).unwrap() {
                Value::Object(map) => map["type"].as_str().unwrap().to_owned(),
                other => panic!("not a map: {other}"),
            })
            .collect()
    };
    let unions = BTreeMap::from([(
        "NodeEvent",
        union_members(vec![
            NodeEvent::Existing(node_state()),
            NodeEvent::Idle,
            NodeEvent::Added(node_state()),
            NodeEvent::Changed(node_state()),
            NodeEvent::Removed(node()),
        ]),
    )]);
    let consts: BTreeMap<&str, i64> = BTreeMap::from([
        ("HOLD_ID_LEN", HOLD_ID_LEN as i64),
        ("MAX_ACCELERATORS", MAX_ACCELERATORS as i64),
        ("MAX_CAPABILITIES", MAX_CAPABILITIES as i64),
        ("MAX_COMPUTE_CAPABILITIES", MAX_COMPUTE_CAPABILITIES as i64),
        ("MAX_GRANT_LIFETIME_NS", MAX_GRANT_LIFETIME_NS),
        ("MAX_HOLD_NS", MAX_HOLD_NS),
        ("MAX_LINKS", MAX_LINKS as i64),
        ("MAX_NODES", MAX_NODES as i64),
        ("MAX_NODE_EVENTS", MAX_NODE_EVENTS as i64),
        ("WATCH_TICK_NS", WATCH_TICK_NS),
    ]);
    let mut file = json!({
        "about": "What this crate mirrors of the contracts' definition, generated from its types: tables and structs with their fields and each field's Rust type, enums with their members' names and numbers, unions with their members' names, constants with their values. Names are this crate's; enum members are in their wire form.",
        "tables": tables,
        "structs": structs,
        "enums": enums,
        "unions": unions,
        "consts": consts,
    });
    // Keys in sorted order, whether or not serde_json's `preserve_order` is
    // on, as it is wherever a crate in the same build enables it.
    file.sort_all_objects();
    serde_json::to_string_pretty(&file).unwrap() + "\n"
}

#[test]
fn the_surface_file_is_the_generated_one() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(PATH);
    let built = build();
    if std::env::var_os("KURI_API_WRITE_VECTORS").is_some() {
        std::fs::write(&path, &built).unwrap();
    }
    let on_disk = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        on_disk == built,
        "{PATH} differs from what the generator builds; rerun with KURI_API_WRITE_VECTORS=1 if the change is deliberate"
    );
}
