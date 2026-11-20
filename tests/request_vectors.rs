//! The holder-signed request check's test vectors: requests as they travel,
//! each with the result a peer must reach.
//!
//! `tests/vectors/requests.json` is generated here from fixed keys, as the
//! grant vectors are; `KURI_API_WRITE_VECTORS=1` rewrites it. Each case is
//! checked by a peer of its own, which started at `started_ns` and was given
//! the case's `revocations` as the answer to its query for the list (none if
//! null); a case with `twice` set is checked twice, and its result is the
//! second check's.

use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use kuri_api::grant::{Grant, GrantError, IssuerKey, PrincipalId, Target};
use kuri_api::registry::{CapabilityKind, NodeId, Scope};
use kuri_api::request::{HolderKey, HolderSignature, RequestDigest, Requests};
use kuri_api::revocation::{Revocation, RevocationList, RevokeHeartbeat};
use kuri_api::{from_cbor, to_cbor};
use serde_json::{json, Value};

const STARTED: i64 = 1_800_000_000_000_000_000;
const NOW: i64 = STARTED + 100_000_000_000;
const SECOND: i64 = 1_000_000_000;
const PATH: &str = "tests/vectors/requests.json";
const METHOD: &str = "registry/1.Watch";
const BODY: &[u8] = &[0xa0];

fn issuer() -> SigningKey {
    SigningKey::from_bytes(&[0x11; 32])
}

fn holder() -> HolderKey {
    HolderKey::from_seed(&[0x22; 32])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn grant() -> Grant {
    let mut grant = Grant {
        principal: Some(PrincipalId {
            bytes: b"owner".to_vec(),
        }),
        provider: Some(NodeId {
            bytes: b"brain-node".to_vec(),
        }),
        kind: Some(CapabilityKind::Inference),
        instance: Some("registry".into()),
        scope: Some(Scope::BroodPrivate),
        holder_key: Some(holder().public().to_vec()),
        grant_id: Some((0..16).collect()),
        expires_utc_ns: Some(NOW + 120 * SECOND),
        issued_epoch: Some(b"epoch-1".to_vec()),
        max_lifetime_ns: Some(300 * SECOND),
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

fn list(revocations: Vec<Revocation>, newest: i64) -> RevocationList {
    RevocationList {
        revocations,
        newest: RevokeHeartbeat {
            revoked_ns: newest,
            signature: issuer()
                .sign(&RevokeHeartbeat::signed_bytes(newest))
                .to_bytes(),
        },
    }
}

fn revoked_owner() -> RevocationList {
    let principal = PrincipalId {
        bytes: b"owner".to_vec(),
    };
    let revoked_ns = NOW - SECOND;
    let until_ns = revoked_ns + 300 * SECOND;
    let revocation = Revocation {
        signature: issuer()
            .sign(&Revocation::signed_bytes(&principal, revoked_ns, until_ns))
            .to_bytes(),
        principal,
        revoked_ns,
        until_ns,
    };
    list(vec![revocation], revoked_ns)
}

struct Case {
    name: &'static str,
    revocations: Option<RevocationList>,
    method: &'static str,
    body: &'static [u8],
    holder: HolderSignature,
    now_ns: i64,
    twice: bool,
}

fn signed(time_ns: i64) -> HolderSignature {
    holder().sign(
        &grant().grant_id.unwrap(),
        &RequestDigest::of(METHOD, BODY),
        time_ns,
        [0x55; 16],
    )
}

fn case(name: &'static str, holder: HolderSignature) -> Case {
    Case {
        name,
        revocations: Some(list(vec![], 0)),
        method: METHOD,
        body: BODY,
        holder,
        now_ns: NOW,
        twice: false,
    }
}

fn cases() -> Vec<Case> {
    let thief = HolderKey::from_seed(&[0x33; 32]).sign(
        &grant().grant_id.unwrap(),
        &RequestDigest::of(METHOD, BODY),
        NOW,
        [0x55; 16],
    );
    vec![
        case("genuine", signed(NOW)),
        Case {
            twice: true,
            ..case("the same request again", signed(NOW))
        },
        case("signed 30 seconds ago", signed(NOW - 30 * SECOND)),
        case(
            "signed 30 seconds and a nanosecond ago",
            signed(NOW - 30 * SECOND - 1),
        ),
        case("signed 2 seconds ahead", signed(NOW + 2 * SECOND)),
        case(
            "signed 2 seconds and a nanosecond ahead",
            signed(NOW + 2 * SECOND + 1),
        ),
        Case {
            now_ns: STARTED + 10 * SECOND,
            ..case("signed before the peer started", signed(STARTED - SECOND))
        },
        Case {
            now_ns: STARTED + 10 * SECOND,
            ..case(
                "signed 4 seconds after the peer started",
                signed(STARTED + 4 * SECOND),
            )
        },
        Case {
            now_ns: STARTED + 10 * SECOND,
            ..case(
                "signed 4 seconds and a nanosecond after the peer started",
                signed(STARTED + 4 * SECOND + 1),
            )
        },
        Case {
            body: &[0xa1, 0x61, 0x78, 0x01],
            ..case("another body under the signature", signed(NOW))
        },
        Case {
            method: "power/1.Wake",
            ..case("another method under the signature", signed(NOW))
        },
        case("signed by another key", thief),
        Case {
            revocations: Some(revoked_owner()),
            ..case("its principal revoked", signed(NOW))
        },
        Case {
            revocations: None,
            ..case("before the peer knows the revocations", signed(NOW))
        },
    ]
}

fn check(case: &Case, issuer: &IssuerKey, started_ns: i64) -> Value {
    let node = NodeId {
        bytes: b"brain-node".to_vec(),
    };
    let target = Target {
        node: &node,
        kind: CapabilityKind::Inference,
        instance: "registry",
    };
    let digest = RequestDigest::of(case.method, case.body);
    let mut peer = Requests::new(issuer.clone(), started_ns);
    if let Some(list) = &case.revocations {
        peer.revocations().answer(list).unwrap();
    }
    let mut result = peer.check(&grant(), &target, &digest, &case.holder, case.now_ns);
    if case.twice {
        result = peer.check(&grant(), &target, &digest, &case.holder, case.now_ns);
    }
    match result {
        Ok(_) => json!("ok"),
        Err(refusal) => {
            json!({ "err": GrantError::from(refusal).name(), "why": refusal.to_string() })
        }
    }
}

fn build() -> String {
    let issuer_key = IssuerKey::from_bytes(&issuer().verifying_key().to_bytes()).unwrap();
    let cases: Vec<Value> = cases()
        .iter()
        .map(|case| {
            json!({
                "name": case.name,
                "method": case.method,
                "body": hex(case.body),
                "digest": hex(&RequestDigest::of(case.method, case.body).0),
                "holder_signature": hex(&to_cbor(&case.holder).unwrap()),
                "revocations": case.revocations.as_ref().map(|list| hex(&to_cbor(list).unwrap())),
                "now_ns": case.now_ns,
                "twice": case.twice,
                "result": check(case, &issuer_key, STARTED),
            })
        })
        .collect();
    let file = json!({
        "about": "Requests signed by a grant's holder (the holder signature as CBOR, hex), each checked by a fresh peer that started at started_ns, with the result it must reach. With twice set, the result is the second check of the same request.",
        "issuer_key": hex(&issuer_key.to_bytes()),
        "grant": hex(&to_cbor(&grant()).unwrap()),
        "target": { "node": hex(b"brain-node"), "kind": "inference", "instance": "registry" },
        "started_ns": STARTED,
        "cases": cases,
    });
    serde_json::to_string_pretty(&file).unwrap() + "\n"
}

#[test]
fn the_vector_file_is_the_generated_one() {
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

#[test]
fn every_vector_holds() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(PATH);
    let Ok(text) = std::fs::read_to_string(path) else {
        panic!("{PATH} is missing; generate it with KURI_API_WRITE_VECTORS=1");
    };
    let file: Value = serde_json::from_str(&text).unwrap();
    let key: [u8; 32] = unhex(file["issuer_key"].as_str().unwrap())
        .try_into()
        .unwrap();
    let issuer = IssuerKey::from_bytes(&key).unwrap();
    let grant: Grant = from_cbor(&unhex(file["grant"].as_str().unwrap())).unwrap();
    let node = NodeId {
        bytes: unhex(file["target"]["node"].as_str().unwrap()),
    };
    let target = Target {
        node: &node,
        kind: CapabilityKind::from_name(file["target"]["kind"].as_str().unwrap()),
        instance: file["target"]["instance"].as_str().unwrap(),
    };
    let cases = file["cases"].as_array().unwrap();
    assert!(cases.len() >= 14);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let body = unhex(case["body"].as_str().unwrap());
        let digest = RequestDigest::of(case["method"].as_str().unwrap(), &body);
        assert_eq!(hex(&digest.0), case["digest"].as_str().unwrap(), "{name}");
        let holder: HolderSignature =
            from_cbor(&unhex(case["holder_signature"].as_str().unwrap())).unwrap();
        let now = case["now_ns"].as_i64().unwrap();
        let mut peer = Requests::new(issuer.clone(), file["started_ns"].as_i64().unwrap());
        if let Some(list) = case["revocations"].as_str() {
            let list: RevocationList = from_cbor(&unhex(list)).unwrap();
            peer.revocations().answer(&list).unwrap();
        }
        let mut result = peer.check(&grant, &target, &digest, &holder, now);
        if case["twice"].as_bool().unwrap() {
            result = peer.check(&grant, &target, &digest, &holder, now);
        }
        let got = match result {
            Ok(_) => "ok".to_owned(),
            Err(refusal) => GrantError::from(refusal).name().to_owned(),
        };
        let want = match case["result"].get("err") {
            Some(err) => err.as_str().unwrap().to_owned(),
            None => "ok".to_owned(),
        };
        assert_eq!(got, want, "{name}");
    }
}
