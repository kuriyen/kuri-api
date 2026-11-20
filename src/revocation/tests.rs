use ed25519_dalek::{Signer, SigningKey};

use super::*;
use crate::{from_cbor, to_cbor};

const T: i64 = 1_800_000_000_000_000_000;
const SECOND: i64 = 1_000_000_000;

fn issuer() -> SigningKey {
    SigningKey::from_bytes(&[7; 32])
}

fn revocations() -> Revocations {
    Revocations::new(IssuerKey::from_bytes(&issuer().verifying_key().to_bytes()).unwrap())
}

fn principal(name: &str) -> PrincipalId {
    PrincipalId {
        bytes: name.as_bytes().to_vec(),
    }
}

fn revocation(name: &str, revoked_ns: i64) -> Revocation {
    let principal = principal(name);
    let until_ns = revoked_ns + MAX_GRANT_LIFETIME_NS;
    let signature = issuer()
        .sign(&Revocation::signed_bytes(&principal, revoked_ns, until_ns))
        .to_bytes();
    Revocation {
        principal,
        revoked_ns,
        until_ns,
        signature,
    }
}

fn heartbeat(revoked_ns: i64) -> RevokeHeartbeat {
    RevokeHeartbeat {
        revoked_ns,
        signature: issuer()
            .sign(&RevokeHeartbeat::signed_bytes(revoked_ns))
            .to_bytes(),
    }
}

fn list(revocations: Vec<Revocation>, newest: i64) -> RevocationList {
    RevocationList {
        revocations,
        newest: heartbeat(newest),
    }
}

#[test]
fn a_provider_is_not_ready_until_it_has_an_answer() {
    let mut revocations = revocations();
    assert!(!revocations.ready());
    assert_eq!(revocations.heartbeat(&heartbeat(0)), Ok(Heard::AskAgain));
    revocations.revoked(&revocation("guest", T)).unwrap();
    assert!(!revocations.ready(), "a revocation alone is not an answer");
    revocations.answer(&list(vec![], 0)).unwrap();
    assert!(revocations.ready());
    assert_eq!(revocations.heartbeat(&heartbeat(0)), Ok(Heard::UpToDate));
}

#[test]
fn a_revoked_principal_stays_revoked_until_its_grants_have_expired() {
    let mut revocations = revocations();
    revocations
        .answer(&list(vec![revocation("guest", T)], T))
        .unwrap();
    // A grant's deadline may overshoot the lifetime by the slack and still
    // pass its check, so the revocation lasts that much longer than its
    // `until_ns`.
    let end = T + MAX_GRANT_LIFETIME_NS + DEADLINE_SLACK_NS;
    assert!(revocations.is_revoked(&principal("guest"), T));
    assert!(revocations.is_revoked(&principal("guest"), end - 1));
    assert!(!revocations.is_revoked(&principal("guest"), end));
    assert!(!revocations.is_revoked(&principal("owner"), T));
    revocations.prune(end - 1);
    assert_eq!(revocations.len(), 1);
    revocations.prune(end);
    assert!(revocations.is_empty());
}

#[test]
fn a_published_revocation_takes_effect_but_sets_nothing() {
    let mut revocations = revocations();
    revocations.answer(&list(vec![], 0)).unwrap();
    revocations.revoked(&revocation("guest", T)).unwrap();
    assert!(revocations.is_revoked(&principal("guest"), T + SECOND));
    // The heartbeat names it, and the provider has not had it from a list:
    // it may have missed an earlier one, so it asks.
    assert_eq!(revocations.heartbeat(&heartbeat(T)), Ok(Heard::AskAgain));
    revocations
        .answer(&list(vec![revocation("guest", T)], T))
        .unwrap();
    assert_eq!(revocations.heartbeat(&heartbeat(T)), Ok(Heard::UpToDate));
}

#[test]
fn a_missed_revocation_is_found_by_the_heartbeat() {
    let mut revocations = revocations();
    revocations.answer(&list(vec![], 0)).unwrap();
    // "guest" was revoked while this provider was not listening.
    assert_eq!(revocations.heartbeat(&heartbeat(T)), Ok(Heard::AskAgain));
    // The query fails: the next heartbeat sends it back again.
    assert_eq!(revocations.heartbeat(&heartbeat(T)), Ok(Heard::AskAgain));
    revocations
        .answer(&list(vec![revocation("guest", T)], T))
        .unwrap();
    assert!(revocations.is_revoked(&principal("guest"), T + SECOND));
    assert_eq!(revocations.heartbeat(&heartbeat(T)), Ok(Heard::UpToDate));
}

#[test]
fn a_provider_started_after_the_newest_expired_does_not_ask_at_each_heartbeat() {
    let mut revocations = revocations();
    let later = T + MAX_GRANT_LIFETIME_NS + SECOND;
    // The newest revocation has expired: the list holds none, but names it.
    revocations.answer(&list(vec![], T)).unwrap();
    assert!(!revocations.is_revoked(&principal("guest"), later));
    for _ in 0..3 {
        assert_eq!(revocations.heartbeat(&heartbeat(T)), Ok(Heard::UpToDate));
    }
}

#[test]
fn a_list_with_one_forged_part_changes_nothing() {
    let mut revocations = revocations();
    let mut forged = revocation("owner", T);
    forged.signature[0] ^= 1;
    assert_eq!(
        revocations.answer(&list(vec![revocation("guest", T), forged], T)),
        Err(RevocationError::BadSignature)
    );
    assert!(!revocations.ready());
    assert!(!revocations.is_revoked(&principal("guest"), T));

    let mut list = list(vec![revocation("guest", T)], T);
    list.newest.revoked_ns += 1;
    assert_eq!(
        revocations.answer(&list),
        Err(RevocationError::BadSignature)
    );
    assert!(!revocations.ready());
}

#[test]
fn nothing_unsigned_by_the_issuer_is_taken() {
    let mut revocations = revocations();
    let other = SigningKey::from_bytes(&[8; 32]);
    let principal = principal("owner");
    let forged = Revocation {
        signature: other
            .sign(&Revocation::signed_bytes(
                &principal,
                T,
                T + MAX_GRANT_LIFETIME_NS,
            ))
            .to_bytes(),
        ..revocation("owner", T)
    };
    assert_eq!(
        revocations.revoked(&forged),
        Err(RevocationError::BadSignature)
    );
    let mut moved = revocation("owner", T);
    moved.until_ns += 1;
    assert_eq!(
        revocations.revoked(&moved),
        Err(RevocationError::BadSignature)
    );
    let fake_heartbeat = RevokeHeartbeat {
        revoked_ns: T,
        signature: other.sign(&RevokeHeartbeat::signed_bytes(T)).to_bytes(),
    };
    assert_eq!(
        revocations.heartbeat(&fake_heartbeat),
        Err(RevocationError::BadSignature)
    );
    assert!(revocations.is_empty());
}

#[test]
fn a_short_until_is_kept_for_the_whole_lifetime() {
    let mut revocations = revocations();
    let principal = principal("guest");
    let until_ns = T + SECOND;
    let short = Revocation {
        signature: issuer()
            .sign(&Revocation::signed_bytes(&principal, T, until_ns))
            .to_bytes(),
        principal: principal.clone(),
        revoked_ns: T,
        until_ns,
    };
    revocations.revoked(&short).unwrap();
    assert!(revocations.is_revoked(
        &principal,
        T + MAX_GRANT_LIFETIME_NS + DEADLINE_SLACK_NS - 1
    ));
}

#[test]
fn an_empty_principal_is_malformed() {
    let mut revocations = revocations();
    assert_eq!(
        revocations.revoked(&revocation("", T)),
        Err(RevocationError::Malformed)
    );
}

#[test]
fn the_signed_layouts_are_the_documented_ones() {
    let mut expected = b"kuri-api.Revoke/v1\0".to_vec();
    expected.extend_from_slice(&5u32.to_le_bytes());
    expected.extend_from_slice(b"guest");
    expected.extend_from_slice(&T.to_le_bytes());
    expected.extend_from_slice(&(T + 1).to_le_bytes());
    assert_eq!(
        Revocation::signed_bytes(&principal("guest"), T, T + 1),
        expected
    );
    let mut expected = b"kuri-api.RevokeHeartbeat/v1\0".to_vec();
    expected.extend_from_slice(&T.to_le_bytes());
    assert_eq!(RevokeHeartbeat::signed_bytes(T), expected);
}

#[test]
fn a_list_survives_the_wire() {
    let list = list(vec![revocation("guest", T)], T);
    assert_eq!(
        from_cbor::<RevocationList>(&to_cbor(&list).unwrap()).unwrap(),
        list
    );
}
