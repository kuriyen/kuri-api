use ciborium::Value;

use super::*;
use crate::{from_cbor, to_cbor};

fn node(byte: u8) -> NodeId {
    NodeId {
        bytes: vec![byte; 32],
    }
}

fn state(byte: u8, health: Health) -> NodeState {
    NodeState {
        announcement: Some(Announcement {
            node: Some(node(byte)),
            label: Some("laptop".into()),
            capabilities: Some(vec![Capability {
                kind: Some(CapabilityKind::Compute),
                instance: Some("gpu".into()),
                scope: Some(Scope::OwnerPrivate),
                compute: Some(Compute {
                    accelerators: Some(vec![Accelerator {
                        kind: Some(AcceleratorKind::Gpu),
                        model: Some("M3 Max".into()),
                        memory_bytes: None,
                    }]),
                    memory_bytes: Some(64 << 30),
                }),
            }]),
            links: Some(vec![Link {
                kind: Some(LinkKind::Thunderbolt),
                speed_bps: Some(40_000_000_000),
                rdma: Some(Rdma::Thunderbolt),
                peer: Some(node(9)),
                segment: None,
            }]),
        }),
        health: Some(health),
        last_seen_monotonic_ns: Some(1_000),
    }
}

/// The CBOR of `value`, read back as a generic value to look at its shape.
fn shape<T: Serialize>(value: &T) -> Value {
    from_cbor(&to_cbor(value).unwrap()).unwrap()
}

fn text(s: &str) -> Value {
    Value::Text(s.into())
}

#[test]
fn every_event_survives_the_wire() {
    for event in [
        NodeEvent::Existing(state(1, Health::Online)),
        NodeEvent::Idle,
        NodeEvent::Added(state(2, Health::Online)),
        NodeEvent::Changed(state(1, Health::Asleep)),
        NodeEvent::Removed(node(2)),
    ] {
        let back: NodeEvent = from_cbor(&to_cbor(&event).unwrap()).unwrap();
        assert_eq!(back, event);
    }
}

#[test]
fn an_event_is_a_map_of_type_and_value() {
    assert_eq!(
        shape(&NodeEvent::Idle),
        Value::Map(vec![(text("type"), text("idle"))])
    );
    let removed = shape(&NodeEvent::Removed(node(2)));
    assert_eq!(
        removed,
        Value::Map(vec![
            (text("type"), text("removed")),
            (
                text("value"),
                Value::Map(vec![(text("bytes"), Value::Bytes(vec![2; 32]))])
            ),
        ])
    );
}

#[test]
fn an_event_this_version_does_not_know_reads_as_unknown() {
    let newer = Value::Map(vec![
        (text("type"), text("merged")),
        (
            text("value"),
            Value::Map(vec![(text("into"), Value::Bytes(vec![1; 4]))]),
        ),
    ]);
    let bytes = to_cbor(&newer).unwrap();
    assert_eq!(from_cbor::<NodeEvent>(&bytes).unwrap(), NodeEvent::Unknown);
    assert!(
        to_cbor(&NodeEvent::Unknown).is_err(),
        "an unknown event has nothing to encode"
    );
}

#[test]
fn a_known_event_without_its_value_is_refused() {
    let bytes = to_cbor(&Value::Map(vec![(text("type"), text("added"))])).unwrap();
    assert!(from_cbor::<NodeEvent>(&bytes).is_err());
}

#[test]
fn a_reader_ignores_keys_it_does_not_know() {
    let mut newer = match shape(&state(1, Health::Online)) {
        Value::Map(entries) => entries,
        other => panic!("{other:?}"),
    };
    newer.push((text("battery"), Value::Integer(80.into())));
    let read: NodeState = from_cbor(&to_cbor(&Value::Map(newer)).unwrap()).unwrap();
    assert_eq!(read, state(1, Health::Online));
}

#[test]
fn members_keep_their_numbers_and_names() {
    assert_eq!(CapabilityKind::Compute.number(), Some(4));
    assert_eq!(Health::Asleep.number(), Some(3));
    assert_eq!(Health::from_name("asleep"), Health::Asleep);
    assert_eq!(Rdma::RoceV2.name(), "roce_v2");
    assert_eq!(RegistryError::GraphFull.number(), Some(3));
    assert_eq!(Health::from_name("hibernating"), Health::Unknown);
}

#[test]
fn a_watch_answer_survives_the_wire() {
    let answer = RegistryReaderWatchResponse {
        events: vec![
            NodeEvent::Existing(state(1, Health::Stale)),
            NodeEvent::Idle,
        ],
    };
    let back: RegistryReaderWatchResponse = from_cbor(&to_cbor(&answer).unwrap()).unwrap();
    assert_eq!(back, answer);
}
