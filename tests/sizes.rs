//! Every message this crate defines fits in [`MAX_MESSAGE_BYTES`] with every
//! field at its bound: each string, byte string and list at its `MAX_`
//! constant, each number at its longest encoding, and each enum at its
//! longest member name. A bound raised past the limit fails here.

use kuri_api::clock::TimeAnswer;
use kuri_api::grant::{
    Grant, GrantRequest, PrincipalId, MAX_GRANT_ID_LEN, MAX_HOLDER_KEY_LEN, MAX_ISSUED_EPOCH_LEN,
    MAX_PRINCIPAL_LEN, MAX_SIGNATURE_LEN,
};
use kuri_api::power::{
    PowerHoldRequest, PowerHoldResponse, PowerReleaseRequest, PowerRenewRequest,
    PowerRenewResponse, PowerWakeRequest, HOLD_ID_LEN,
};
use kuri_api::registry::{
    Accelerator, AcceleratorKind, Announcement, Capability, CapabilityKind, Compute, Health, Link,
    LinkKind, NodeEvent, NodeId, NodeState, Rdma, RegistryReaderWatchResponse, Scope,
    MAX_ACCELERATORS, MAX_CAPABILITIES, MAX_COMPUTE_CAPABILITIES, MAX_INSTANCE_LEN, MAX_LINKS,
    MAX_NAME_LEN, MAX_NODE_EVENTS, MAX_NODE_ID_LEN,
};
use kuri_api::request::{HolderSignature, REQUEST_NONCE_LEN};
use kuri_api::revocation::{Revocation, RevocationList, RevokeHeartbeat, MAX_REVOCATIONS};
use kuri_api::{to_cbor, MAX_MESSAGE_BYTES};
use serde::Serialize;

/// The member whose name is longest, which encodes longest.
fn longest<E: Copy>(all: &[E], name: fn(E) -> &'static str) -> E {
    *all.iter().max_by_key(|&&e| name(e).len()).unwrap()
}

fn text(len: usize) -> String {
    "x".repeat(len)
}

fn bytes(len: usize) -> Vec<u8> {
    vec![0xff; len]
}

fn node() -> NodeId {
    NodeId {
        bytes: bytes(MAX_NODE_ID_LEN),
    }
}

fn principal() -> PrincipalId {
    PrincipalId {
        bytes: bytes(MAX_PRINCIPAL_LEN),
    }
}

fn accelerator() -> Accelerator {
    Accelerator {
        kind: Some(longest(AcceleratorKind::ALL, AcceleratorKind::name)),
        model: Some(text(MAX_NAME_LEN)),
        memory_bytes: Some(u64::MAX),
    }
}

/// Only `MAX_COMPUTE_CAPABILITIES` of a node's capabilities may carry
/// `compute`.
fn capability(compute: bool) -> Capability {
    Capability {
        kind: Some(longest(CapabilityKind::ALL, CapabilityKind::name)),
        instance: Some(text(MAX_INSTANCE_LEN)),
        scope: Some(longest(Scope::ALL, Scope::name)),
        compute: compute.then(|| Compute {
            accelerators: Some(vec![accelerator(); MAX_ACCELERATORS]),
            memory_bytes: Some(u64::MAX),
        }),
    }
}

fn link() -> Link {
    Link {
        kind: Some(longest(LinkKind::ALL, LinkKind::name)),
        speed_bps: Some(u64::MAX),
        rdma: Some(longest(Rdma::ALL, Rdma::name)),
        peer: Some(node()),
        segment: Some(text(MAX_NAME_LEN)),
    }
}

fn state() -> NodeState {
    NodeState {
        announcement: Some(Announcement {
            node: Some(node()),
            label: Some(text(MAX_NAME_LEN)),
            capabilities: Some(
                (0..MAX_CAPABILITIES)
                    .map(|i| capability(i < MAX_COMPUTE_CAPABILITIES))
                    .collect(),
            ),
            links: Some(vec![link(); MAX_LINKS]),
        }),
        health: Some(longest(Health::ALL, Health::name)),
        last_seen_monotonic_ns: Some(i64::MIN),
    }
}

fn grant() -> Grant {
    Grant {
        principal: Some(principal()),
        provider: Some(node()),
        kind: Some(longest(CapabilityKind::ALL, CapabilityKind::name)),
        instance: Some(text(MAX_INSTANCE_LEN)),
        scope: Some(longest(Scope::ALL, Scope::name)),
        holder_key: Some(bytes(MAX_HOLDER_KEY_LEN)),
        grant_id: Some(bytes(MAX_GRANT_ID_LEN)),
        expires_utc_ns: Some(i64::MIN),
        issued_epoch: Some(bytes(MAX_ISSUED_EPOCH_LEN)),
        max_lifetime_ns: Some(i64::MIN),
        signature: Some(bytes(MAX_SIGNATURE_LEN)),
    }
}

fn revocation() -> Revocation {
    Revocation {
        principal: principal(),
        revoked_ns: i64::MIN,
        until_ns: i64::MIN,
        signature: [0xff; 64],
    }
}

fn fits<T: Serialize>(what: &str, value: &T) -> usize {
    let len = to_cbor(value).unwrap().len();
    assert!(
        len <= MAX_MESSAGE_BYTES,
        "{what} is {len} bytes at its bounds, over MAX_MESSAGE_BYTES ({MAX_MESSAGE_BYTES})"
    );
    len
}

#[test]
fn a_watch_answer_fits_with_every_kind_of_event() {
    let answer = |event: fn() -> NodeEvent| RegistryReaderWatchResponse {
        events: (0..MAX_NODE_EVENTS).map(|_| event()).collect(),
    };
    let existing = fits(
        "a watch answer of Existing",
        &answer(|| NodeEvent::Existing(state())),
    );
    fits(
        "a watch answer of Added",
        &answer(|| NodeEvent::Added(state())),
    );
    fits(
        "a watch answer of Changed",
        &answer(|| NodeEvent::Changed(state())),
    );
    fits(
        "a watch answer of Removed",
        &answer(|| NodeEvent::Removed(node())),
    );
    fits("a watch answer of Idle", &answer(|| NodeEvent::Idle));
    // The largest message: it keeps a margin under the limit.
    assert!(existing < MAX_MESSAGE_BYTES * 3 / 4, "{existing} bytes");
}

#[test]
fn grants_and_requests_fit() {
    fits("a grant", &grant());
    fits(
        "a grant request",
        &GrantRequest {
            principal: Some(principal()),
            provider: Some(node()),
            kind: Some(longest(CapabilityKind::ALL, CapabilityKind::name)),
            instance: Some(text(MAX_INSTANCE_LEN)),
            holder_key: Some(bytes(MAX_HOLDER_KEY_LEN)),
        },
    );
    fits(
        "a holder's signature",
        &HolderSignature {
            time_ns: i64::MIN,
            nonce: [0xff; REQUEST_NONCE_LEN],
            signature: [0xff; 64],
        },
    );
}

#[test]
fn the_time_and_revocations_fit() {
    fits(
        "a time answer",
        &TimeAnswer {
            utc_ns: i64::MIN,
            signature: [0xff; 64],
        },
    );
    fits(
        "a revocation list",
        &RevocationList {
            revocations: vec![revocation(); MAX_REVOCATIONS],
            newest: RevokeHeartbeat {
                revoked_ns: i64::MIN,
                signature: [0xff; 64],
            },
        },
    );
}

#[test]
fn power_messages_fit() {
    let id = [0xff; HOLD_ID_LEN];
    fits("a wake request", &PowerWakeRequest { node: node() });
    fits(
        "a hold request",
        &PowerHoldRequest {
            node: node(),
            duration_ns: i64::MIN,
        },
    );
    fits(
        "a hold response",
        &PowerHoldResponse {
            hold_id: id,
            until_ns: i64::MIN,
        },
    );
    fits(
        "a renew request",
        &PowerRenewRequest {
            hold_id: id,
            duration_ns: i64::MIN,
        },
    );
    fits(
        "a renew response",
        &PowerRenewResponse { until_ns: i64::MIN },
    );
    fits("a release request", &PowerReleaseRequest { hold_id: id });
}
