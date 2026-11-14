use ciborium::Value;

use super::*;
use crate::{from_cbor, to_cbor};

#[test]
fn a_hold_survives_the_wire_with_its_id_as_bytes() {
    let answer = PowerHoldResponse {
        hold_id: [7; HOLD_ID_LEN],
        until_ns: 42,
    };
    let bytes = to_cbor(&answer).unwrap();
    assert_eq!(from_cbor::<PowerHoldResponse>(&bytes).unwrap(), answer);
    let shape: Value = from_cbor(&bytes).unwrap();
    let id = shape
        .as_map()
        .unwrap()
        .iter()
        .find(|(k, _)| k.as_text() == Some("hold_id"));
    assert_eq!(
        id.map(|(_, v)| v.clone()),
        Some(Value::Bytes(vec![7; HOLD_ID_LEN]))
    );
}

#[test]
fn requests_survive_the_wire() {
    let hold = PowerHoldRequest {
        node: NodeId { bytes: vec![1; 32] },
        duration_ns: MAX_HOLD_NS,
    };
    assert_eq!(
        from_cbor::<PowerHoldRequest>(&to_cbor(&hold).unwrap()).unwrap(),
        hold
    );
    let renew = PowerRenewRequest {
        hold_id: [3; HOLD_ID_LEN],
        duration_ns: 1,
    };
    assert_eq!(
        from_cbor::<PowerRenewRequest>(&to_cbor(&renew).unwrap()).unwrap(),
        renew
    );
}

#[test]
fn a_hold_id_of_another_length_is_refused() {
    let short = Value::Map(vec![(
        Value::Text("hold_id".into()),
        Value::Bytes(vec![1; 15]),
    )]);
    assert!(from_cbor::<PowerReleaseRequest>(&to_cbor(&short).unwrap()).is_err());
}

#[test]
fn errors_keep_their_numbers() {
    assert_eq!(PowerError::InvalidDuration.number(), Some(4));
    assert_eq!(PowerError::from_name("cannot_wake"), PowerError::CannotWake);
}
