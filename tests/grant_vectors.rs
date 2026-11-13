//! The grant check's test vectors: grants as they travel, each with the
//! result a provider must reach.
//!
//! `tests/vectors/grants.json` is the file other implementations run too. It
//! is generated here from fixed keys, so the test fails if the file and the
//! generator ever disagree; `KURI_API_WRITE_VECTORS=1` rewrites it after a
//! deliberate change. Every case is then checked against this crate.

use std::path::Path;

use ed25519_dalek::{Signer, SigningKey};
use kuri_api::grant::{Grant, GrantError, IssuerKey, PrincipalId, Target};
use kuri_api::registry::{CapabilityKind, NodeId, Scope};
use kuri_api::{from_cbor, to_cbor};
use serde_json::{json, Value};

const NOW: i64 = 1_800_000_000_000_000_000;
const MINUTE: i64 = 60_000_000_000;
const PATH: &str = "tests/vectors/grants.json";

fn issuer() -> SigningKey {
    SigningKey::from_bytes(&[0x11; 32])
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

fn base() -> Grant {
    Grant {
        principal: Some(PrincipalId {
            bytes: b"owner".to_vec(),
        }),
        provider: Some(NodeId {
            bytes: b"camera-node".to_vec(),
        }),
        kind: Some(CapabilityKind::Sensor),
        instance: Some("front-door".into()),
        scope: Some(Scope::BroodPrivate),
        holder_key: Some(
            SigningKey::from_bytes(&[0x22; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
        ),
        grant_id: Some((0..16).collect()),
        expires_utc_ns: Some(NOW + MINUTE),
        issued_epoch: Some(b"epoch-1".to_vec()),
        max_lifetime_ns: Some(MINUTE),
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

struct Case {
    name: &'static str,
    grant: Grant,
    node: &'static [u8],
    kind: CapabilityKind,
    instance: &'static str,
    now_ns: i64,
}

fn case(name: &'static str, grant: Grant) -> Case {
    Case {
        name,
        grant,
        node: b"camera-node",
        kind: CapabilityKind::Sensor,
        instance: "front-door",
        now_ns: NOW,
    }
}

fn cases() -> Vec<Case> {
    let mut tampered = sign(base());
    tampered.scope = Some(Scope::BroodShared);
    let mut foreign = base();
    foreign.signature = Some(
        SigningKey::from_bytes(&[0x33; 32])
            .sign(&foreign.signed_bytes().unwrap())
            .to_bytes()
            .to_vec(),
    );
    vec![
        case("genuine", sign(base())),
        Case {
            now_ns: NOW + MINUTE - 1,
            ..case("genuine, a nanosecond before its deadline", sign(base()))
        },
        Case {
            now_ns: NOW + MINUTE,
            ..case("at its deadline", sign(base()))
        },
        case("scope changed after signing", tampered),
        case("signed by another key", foreign),
        Case {
            node: b"another-node",
            ..case("presented to another node", sign(base()))
        },
        Case {
            kind: CapabilityKind::Actuator,
            ..case("presented for another kind", sign(base()))
        },
        Case {
            instance: "back-door",
            ..case("presented for another instance", sign(base()))
        },
        case(
            "no deadline on the home's clock",
            sign(Grant {
                expires_utc_ns: None,
                ..base()
            }),
        ),
        case(
            "a holder key of 31 bytes",
            Grant {
                holder_key: Some(vec![0x44; 31]),
                signature: sign(base()).signature,
                ..base()
            },
        ),
        case(
            "a lifetime past five minutes",
            Grant {
                max_lifetime_ns: Some(5 * MINUTE + 1),
                signature: sign(base()).signature,
                ..base()
            },
        ),
        case(
            "no signature",
            Grant {
                signature: None,
                ..base()
            },
        ),
    ]
}

fn result(case: &Case, issuer: &IssuerKey) -> Value {
    let node = NodeId {
        bytes: case.node.to_vec(),
    };
    let target = Target {
        node: &node,
        kind: case.kind,
        instance: case.instance,
    };
    match case.grant.check(issuer, &target, case.now_ns) {
        Ok(verified) => json!({
            "ok": {
                "principal": hex(&verified.principal.bytes),
                "grant_id": hex(&verified.grant_id),
                "holder_key": hex(&verified.holder_key),
                "scope": verified.scope.name(),
                "expires_ns": verified.expires_ns,
            }
        }),
        Err(rejection) => json!({ "err": GrantError::from(rejection).name() }),
    }
}

fn build() -> String {
    let issuer_key = IssuerKey::from_bytes(&issuer().verifying_key().to_bytes()).unwrap();
    let cases: Vec<Value> = cases()
        .iter()
        .map(|case| {
            json!({
                "name": case.name,
                "grant": hex(&to_cbor(&case.grant).unwrap()),
                "signed_bytes": case.grant.signed_bytes().map(|b| hex(&b)).ok(),
                "target": {
                    "node": hex(case.node),
                    "kind": case.kind.name(),
                    "instance": case.instance,
                },
                "now_ns": case.now_ns,
                "result": result(case, &issuer_key),
            })
        })
        .collect();
    let file = json!({
        "about": "Grants as they travel (CBOR, hex), each with the result a provider's offline check must reach. `signed_bytes` is null where the grant is malformed.",
        "issuer_key": hex(&issuer_key.to_bytes()),
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
    let file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let key: [u8; 32] = unhex(file["issuer_key"].as_str().unwrap())
        .try_into()
        .unwrap();
    let issuer = IssuerKey::from_bytes(&key).unwrap();
    let cases = file["cases"].as_array().unwrap();
    assert!(cases.len() >= 12);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let grant: Grant = from_cbor(&unhex(case["grant"].as_str().unwrap())).unwrap();
        let signed = grant.signed_bytes().map(|b| hex(&b)).ok();
        assert_eq!(signed.as_deref(), case["signed_bytes"].as_str(), "{name}");
        let node = NodeId {
            bytes: unhex(case["target"]["node"].as_str().unwrap()),
        };
        let target = Target {
            node: &node,
            kind: CapabilityKind::from_name(case["target"]["kind"].as_str().unwrap()),
            instance: case["target"]["instance"].as_str().unwrap(),
        };
        let got = match grant.check(&issuer, &target, case["now_ns"].as_i64().unwrap()) {
            Ok(_) => "ok".to_owned(),
            Err(rejection) => GrantError::from(rejection).name().to_owned(),
        };
        let want = match case["result"].get("err") {
            Some(err) => err.as_str().unwrap().to_owned(),
            None => "ok".to_owned(),
        };
        assert_eq!(got, want, "{name}");
    }
}
