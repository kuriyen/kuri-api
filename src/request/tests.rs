use ed25519_dalek::{Signer, SigningKey};

use super::*;
use crate::grant::{PrincipalId, MAX_GRANT_LIFETIME_NS};
use crate::registry::{CapabilityKind, NodeId, Scope};
use crate::{from_cbor, to_cbor};

const STARTED: i64 = 1_800_000_000_000_000_000;
const NOW: i64 = STARTED + 100_000_000_000;
const SECOND: i64 = 1_000_000_000;

fn issuer() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn holder() -> HolderKey {
    HolderKey::from_seed(&[9; 32])
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

fn grant() -> Grant {
    let mut grant = Grant {
        principal: Some(PrincipalId {
            bytes: b"owner".to_vec(),
        }),
        provider: Some(node()),
        kind: Some(CapabilityKind::Sensor),
        instance: Some("front-door".into()),
        scope: Some(Scope::OwnerPrivate),
        holder_key: Some(holder().public().to_vec()),
        grant_id: Some(vec![1; 16]),
        expires_utc_ns: Some(NOW + 120 * SECOND),
        issued_epoch: Some(vec![2; 8]),
        max_lifetime_ns: Some(MAX_GRANT_LIFETIME_NS),
        signature: None,
    };
    grant.signature = Some(
        issuer()
            .sign(&grant.signed_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    );
    grant
}

fn requests() -> Requests {
    Requests::new(
        IssuerKey::from_bytes(&issuer().verifying_key().to_bytes()).unwrap(),
        STARTED,
    )
}

fn digest() -> RequestDigest {
    RequestDigest::of("registry/1.WatchNodes", &[0xa0])
}

fn signed(time_ns: i64, nonce: u8) -> HolderSignature {
    holder().sign(&[1; 16], &digest(), time_ns, [nonce; REQUEST_NONCE_LEN])
}

#[test]
fn a_signed_request_passes_once() {
    let node = node();
    let mut requests = requests();
    let signature = signed(NOW, 1);
    let verified = requests
        .check(&grant(), &target(&node), &digest(), &signature, NOW)
        .unwrap();
    assert_eq!(verified.grant_id, vec![1; 16]);
    assert_eq!(
        requests.check(
            &grant(),
            &target(&node),
            &digest(),
            &signature,
            NOW + SECOND
        ),
        Err(Refusal::Replayed)
    );
}

#[test]
fn another_nonce_is_another_request() {
    let node = node();
    let mut requests = requests();
    for nonce in 0..5 {
        assert!(requests
            .check(
                &grant(),
                &target(&node),
                &digest(),
                &signed(NOW, nonce),
                NOW
            )
            .is_ok());
    }
    assert_eq!(requests.remembered(), 5);
}

#[test]
fn the_signed_layout_is_the_documented_one() {
    let mut expected = b"kuri-api.HolderRequest/v1\0".to_vec();
    expected.extend_from_slice(&16u32.to_le_bytes());
    expected.extend_from_slice(&[1; 16]);
    expected.extend_from_slice(&digest().0);
    expected.extend_from_slice(&NOW.to_le_bytes());
    expected.extend_from_slice(&[3; 16]);
    let signature = signed(NOW, 3);
    SigningKey::from_bytes(&[9; 32])
        .verifying_key()
        .verify_strict(&expected, &Signature::from_bytes(&signature.signature))
        .expect("the holder signs the documented bytes");

    let mut body = 21u32.to_le_bytes().to_vec();
    body.extend_from_slice(b"registry/1.WatchNodes");
    body.push(0xa0);
    let expected_digest: [u8; 32] = Sha256::digest(&body).into();
    assert_eq!(digest().0, expected_digest);
}

#[test]
fn the_window_is_thirty_seconds_either_way() {
    let node = node();
    for (signed_at, passes) in [
        (NOW - 30 * SECOND, true),
        (NOW + 30 * SECOND, true),
        (NOW - 30 * SECOND - 1, false),
        (NOW + 30 * SECOND + 1, false),
    ] {
        let result = requests().check(
            &grant(),
            &target(&node),
            &digest(),
            &signed(signed_at, 1),
            NOW,
        );
        if passes {
            assert!(result.is_ok(), "{}", signed_at - NOW);
        } else {
            assert_eq!(result, Err(Refusal::OutsideWindow), "{}", signed_at - NOW);
        }
    }
}

#[test]
fn a_request_signed_before_the_peer_started_is_refused() {
    let node = node();
    let mut requests = requests();
    assert_eq!(
        requests.check(
            &grant(),
            &target(&node),
            &digest(),
            &signed(STARTED - 1, 1),
            STARTED + SECOND
        ),
        Err(Refusal::BeforeStart)
    );
    assert!(requests
        .check(
            &grant(),
            &target(&node),
            &digest(),
            &signed(STARTED, 1),
            STARTED + SECOND
        )
        .is_ok());
}

#[test]
fn a_changed_request_does_not_verify() {
    let node = node();
    let signature = signed(NOW, 1);
    for other in [
        RequestDigest::of("registry/1.WatchNodes", &[0xa1]),
        RequestDigest::of("power/1.Wake", &[0xa0]),
    ] {
        assert_eq!(
            requests().check(&grant(), &target(&node), &other, &signature, NOW),
            Err(Refusal::HolderSignature)
        );
    }
}

#[test]
fn a_request_signed_by_another_key_is_refused() {
    let node = node();
    let thief = HolderKey::from_seed(&[10; 32]);
    let signature = thief.sign(&[1; 16], &digest(), NOW, [1; REQUEST_NONCE_LEN]);
    assert_eq!(
        requests().check(&grant(), &target(&node), &digest(), &signature, NOW),
        Err(Refusal::HolderSignature)
    );
}

#[test]
fn the_signature_is_bound_to_its_time_and_nonce() {
    let node = node();
    let mut moved = signed(NOW, 1);
    moved.time_ns += 1;
    assert_eq!(
        requests().check(&grant(), &target(&node), &digest(), &moved, NOW),
        Err(Refusal::HolderSignature)
    );
    let mut renonced = signed(NOW, 1);
    renonced.nonce[0] ^= 1;
    assert_eq!(
        requests().check(&grant(), &target(&node), &digest(), &renonced, NOW),
        Err(Refusal::HolderSignature)
    );
}

#[test]
fn a_failed_request_uses_up_no_nonce() {
    let node = node();
    let mut requests = requests();
    let thief = HolderKey::from_seed(&[10; 32]);
    let forged = thief.sign(&[1; 16], &digest(), NOW, [1; REQUEST_NONCE_LEN]);
    assert!(requests
        .check(&grant(), &target(&node), &digest(), &forged, NOW)
        .is_err());
    assert_eq!(requests.remembered(), 0);
    assert!(requests
        .check(&grant(), &target(&node), &digest(), &signed(NOW, 1), NOW)
        .is_ok());
}

#[test]
fn the_grant_is_checked_first() {
    let node = node();
    let mut expired = grant();
    expired.expires_utc_ns = Some(NOW);
    expired.signature = Some(
        issuer()
            .sign(&expired.signed_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    );
    assert_eq!(
        requests().check(&expired, &target(&node), &digest(), &signed(NOW, 1), NOW),
        Err(Refusal::Grant(Rejection::Expired))
    );
    let other = NodeId {
        bytes: b"another-node".to_vec(),
    };
    assert_eq!(
        requests().check(&grant(), &target(&other), &digest(), &signed(NOW, 1), NOW),
        Err(Refusal::Grant(Rejection::WrongTarget))
    );
}

#[test]
fn nonces_are_kept_only_while_their_requests_could_pass() {
    let node = node();
    let mut requests = requests();
    let signature = signed(NOW, 1);
    requests
        .check(&grant(), &target(&node), &digest(), &signature, NOW)
        .unwrap();
    // The last moment the same request could pass the window: still refused.
    let last = NOW + 30 * SECOND;
    assert_eq!(
        requests.check(&grant(), &target(&node), &digest(), &signature, last),
        Err(Refusal::Replayed)
    );
    requests.prune(last);
    assert_eq!(requests.remembered(), 1);
    // After it, the nonce goes, and the request fails the window instead.
    requests.prune(last + 1);
    assert_eq!(requests.remembered(), 0);
    assert_eq!(
        requests.check(&grant(), &target(&node), &digest(), &signature, last + 1),
        Err(Refusal::OutsideWindow)
    );
}

#[test]
fn a_holder_signature_survives_the_wire() {
    let signature = signed(NOW, 4);
    let decoded: HolderSignature = from_cbor(&to_cbor(&signature).unwrap()).unwrap();
    assert_eq!(decoded, signature);
}

#[test]
fn refusals_read_as_the_contracts_errors() {
    assert_eq!(
        GrantError::from(Refusal::HolderSignature),
        GrantError::HolderProofFailed
    );
    assert_eq!(GrantError::from(Refusal::Replayed), GrantError::Spent);
    assert_eq!(
        GrantError::from(Refusal::OutsideWindow),
        GrantError::Expired
    );
    assert_eq!(GrantError::from(Refusal::BeforeStart), GrantError::Expired);
    assert_eq!(
        GrantError::from(Refusal::Grant(Rejection::BadSignature)),
        GrantError::UntrustedSignature
    );
}
