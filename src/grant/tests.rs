use ed25519_dalek::{Signer, SigningKey};

use super::*;
use crate::{from_cbor, to_cbor};

/// A field, and a change to a grant that touches it.
type Change = (&'static str, fn(&mut Grant));

const NOW: i64 = 1_800_000_000_000_000_000;

fn issuer() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn issuer_key() -> IssuerKey {
    IssuerKey::from_bytes(&issuer().verifying_key().to_bytes()).unwrap()
}

fn node() -> NodeId {
    NodeId {
        bytes: b"camera-node".to_vec(),
    }
}

fn target(node: &NodeId) -> Target<'_> {
    Target {
        node,
        kind: CapabilityKind::Sensor,
        instance: "front-door",
    }
}

fn unsigned() -> Grant {
    Grant {
        principal: Some(PrincipalId {
            bytes: b"owner".to_vec(),
        }),
        provider: Some(node()),
        kind: Some(CapabilityKind::Sensor),
        instance: Some("front-door".into()),
        scope: Some(Scope::OwnerPrivate),
        holder_key: Some(
            SigningKey::from_bytes(&[9; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        ),
        grant_id: Some(vec![1; 16]),
        expires_utc_ns: Some(NOW + 60_000_000_000),
        issued_epoch: Some(vec![2; 8]),
        max_lifetime_ns: Some(60_000_000_000),
        signature: None,
    }
}

fn sign(mut grant: Grant) -> Grant {
    grant.signature = Some(
        issuer()
            .sign(&grant.signed_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    );
    grant
}

fn signed() -> Grant {
    sign(unsigned())
}

#[test]
fn a_genuine_grant_passes() {
    let node = node();
    let verified = signed().check(&issuer_key(), &target(&node), NOW).unwrap();
    assert_eq!(verified.principal.bytes, b"owner");
    assert_eq!(verified.grant_id, vec![1; 16]);
    assert_eq!(verified.scope, Scope::OwnerPrivate);
    assert_eq!(verified.expires_ns, NOW + 60_000_000_000);
    assert_eq!(
        verified.holder_key,
        SigningKey::from_bytes(&[9; 32]).verifying_key().to_bytes()
    );
}

#[test]
fn the_signed_layout_is_the_documented_one() {
    let grant = unsigned();
    let mut expected = b"kuri-api.Grant/v1\0".to_vec();
    let field = |out: &mut Vec<u8>, bytes: &[u8]| {
        out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(bytes);
    };
    field(&mut expected, b"owner");
    field(&mut expected, b"camera-node");
    expected.extend_from_slice(&1u32.to_le_bytes());
    field(&mut expected, b"front-door");
    expected.extend_from_slice(&1u32.to_le_bytes());
    field(&mut expected, grant.holder_key.as_deref().unwrap());
    field(&mut expected, &[1; 16]);
    expected.push(1);
    expected.extend_from_slice(&(NOW + 60_000_000_000).to_le_bytes());
    field(&mut expected, &[2; 8]);
    expected.extend_from_slice(&60_000_000_000i64.to_le_bytes());
    assert_eq!(grant.signed_bytes().unwrap(), expected);

    let mut without_deadline = grant;
    without_deadline.expires_utc_ns = None;
    let bytes = without_deadline.signed_bytes().unwrap();
    let deadline_at = expected.len() - 8 - (4 + 8) - 8 - 1;
    assert_eq!(bytes[deadline_at], 0, "an absent deadline is one zero byte");
    assert_eq!(bytes.len(), expected.len() - 8);
}

#[test]
fn every_signed_field_is_covered() {
    let node = node();
    let changes: [Change; 10] = [
        ("principal", |g| g.principal.as_mut().unwrap().bytes.push(0)),
        ("provider", |g| g.provider.as_mut().unwrap().bytes.push(0)),
        ("kind", |g| g.kind = Some(CapabilityKind::Actuator)),
        ("instance", |g| g.instance.as_mut().unwrap().push('x')),
        ("scope", |g| g.scope = Some(Scope::BroodShared)),
        ("holder_key", |g| g.holder_key.as_mut().unwrap()[0] ^= 1),
        ("grant_id", |g| g.grant_id.as_mut().unwrap()[0] ^= 1),
        ("expires_utc_ns", |g| g.expires_utc_ns = Some(NOW + 1)),
        ("issued_epoch", |g| g.issued_epoch.as_mut().unwrap()[0] ^= 1),
        ("max_lifetime_ns", |g| g.max_lifetime_ns = Some(1)),
    ];
    for (name, change) in changes {
        let mut grant = signed();
        change(&mut grant);
        assert_eq!(
            grant.check(&issuer_key(), &target(&node), NOW),
            Err(Rejection::BadSignature),
            "{name} changed after signing"
        );
    }
}

#[test]
fn another_issuers_grant_does_not_verify() {
    let node = node();
    let other = IssuerKey::from_bytes(&SigningKey::from_bytes(&[8; 32]).verifying_key().to_bytes())
        .unwrap();
    assert_eq!(
        signed().check(&other, &target(&node), NOW),
        Err(Rejection::BadSignature)
    );
}

#[test]
fn a_grant_reaches_only_its_own_tuple() {
    let grant = signed();
    let other_node = NodeId {
        bytes: b"another-node".to_vec(),
    };
    let node = node();
    for target in [
        Target {
            node: &other_node,
            ..target(&node)
        },
        Target {
            kind: CapabilityKind::Inference,
            ..target(&node)
        },
        Target {
            instance: "back-door",
            ..target(&node)
        },
    ] {
        assert_eq!(
            grant.check(&issuer_key(), &target, NOW),
            Err(Rejection::WrongTarget),
            "{target:?}"
        );
    }
}

#[test]
fn the_deadline_is_exclusive() {
    let node = node();
    let deadline = NOW + 60_000_000_000;
    let grant = signed();
    assert!(grant
        .check(&issuer_key(), &target(&node), deadline - 1)
        .is_ok());
    assert_eq!(
        grant.check(&issuer_key(), &target(&node), deadline),
        Err(Rejection::Expired)
    );
}

#[test]
fn a_malformed_grant_names_its_field() {
    let node = node();
    let cases: [Change; 16] = [
        ("principal", |g| g.principal = None),
        ("principal", |g| g.principal.as_mut().unwrap().bytes.clear()),
        ("principal", |g| {
            g.principal.as_mut().unwrap().bytes = vec![0; 65]
        }),
        ("provider", |g| g.provider = None),
        ("kind", |g| g.kind = None),
        ("kind", |g| g.kind = Some(CapabilityKind::Unknown)),
        ("instance", |g| g.instance = Some("x".repeat(65))),
        ("scope", |g| g.scope = Some(Scope::Unknown)),
        ("holder_key", |g| {
            g.holder_key.as_mut().unwrap().pop().map(drop).unwrap()
        }),
        ("grant_id", |g| g.grant_id = Some(vec![0; 33])),
        ("issued_epoch", |g| g.issued_epoch = None),
        ("max_lifetime_ns", |g| g.max_lifetime_ns = Some(0)),
        ("max_lifetime_ns", |g| {
            g.max_lifetime_ns = Some(MAX_GRANT_LIFETIME_NS + 1)
        }),
        ("expires_utc_ns", |g| g.expires_utc_ns = None),
        ("signature", |g| g.signature = None),
        ("signature", |g| g.signature.as_mut().unwrap().push(0)),
    ];
    for (field, change) in cases {
        let mut grant = signed();
        change(&mut grant);
        assert_eq!(
            grant.check(&issuer_key(), &target(&node), NOW),
            Err(Rejection::Malformed(Malformed(field))),
            "{field}"
        );
    }
}

#[test]
fn the_longest_fields_the_contract_allows_are_well_formed() {
    let node = NodeId {
        bytes: vec![3; MAX_NODE_ID_LEN],
    };
    let grant = sign(Grant {
        principal: Some(PrincipalId {
            bytes: vec![4; MAX_PRINCIPAL_LEN],
        }),
        provider: Some(node.clone()),
        instance: Some("i".repeat(MAX_INSTANCE_LEN)),
        grant_id: Some(vec![5; MAX_GRANT_ID_LEN]),
        issued_epoch: Some(vec![6; MAX_ISSUED_EPOCH_LEN]),
        max_lifetime_ns: Some(MAX_GRANT_LIFETIME_NS),
        ..unsigned()
    });
    let target = Target {
        node: &node,
        kind: CapabilityKind::Sensor,
        instance: &"i".repeat(MAX_INSTANCE_LEN),
    };
    assert!(grant.check(&issuer_key(), &target, NOW).is_ok());
}

#[test]
fn a_grant_survives_the_wire_and_still_verifies() {
    let node = node();
    let bytes = to_cbor(&signed()).unwrap();
    let decoded: Grant = from_cbor(&bytes).unwrap();
    assert_eq!(decoded, signed());
    assert!(decoded.check(&issuer_key(), &target(&node), NOW).is_ok());
}

#[test]
fn keys_from_a_newer_contract_are_ignored() {
    #[derive(Serialize)]
    struct Newer {
        #[serde(flatten)]
        grant: Grant,
        a_field_from_later: u32,
    }
    let node = node();
    let bytes = to_cbor(&Newer {
        grant: signed(),
        a_field_from_later: 7,
    })
    .unwrap();
    let decoded: Grant = from_cbor(&bytes).unwrap();
    assert!(decoded.check(&issuer_key(), &target(&node), NOW).is_ok());
}

#[test]
fn an_enum_member_from_a_newer_contract_reads_as_unknown() {
    #[derive(Serialize)]
    struct Newer {
        kind: &'static str,
    }
    let decoded: Grant = from_cbor(&to_cbor(&Newer { kind: "printer" }).unwrap()).unwrap();
    assert_eq!(decoded.kind, Some(CapabilityKind::Unknown));
}

#[test]
fn a_missing_key_reads_as_none() {
    let decoded: Grant = from_cbor(&to_cbor(&Grant::default()).unwrap()).unwrap();
    assert_eq!(decoded, Grant::default());
    assert_eq!(to_cbor(&Grant::default()).unwrap(), [0xa0], "an empty map");
}

#[test]
fn enum_numbers_and_names_are_the_contracts() {
    for (kind, number, name) in [
        (CapabilityKind::Sensor, 1, "sensor"),
        (CapabilityKind::Inference, 2, "inference"),
        (CapabilityKind::Actuator, 3, "actuator"),
    ] {
        assert_eq!(kind.number(), Some(number));
        assert_eq!(CapabilityKind::from_number(number), kind);
        assert_eq!(kind.name(), name);
    }
    assert_eq!(CapabilityKind::from_number(99), CapabilityKind::Unknown);
    assert_eq!(GrantError::UnknownService.number(), Some(12));
    assert_eq!(
        GrantError::from(Rejection::BadSignature),
        GrantError::UntrustedSignature
    );
}
