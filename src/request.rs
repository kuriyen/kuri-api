//! Requests signed by a grant's holder, and the check a peer runs on them
//! offline.
//!
//! On a mesh of messages there is no channel to challenge a holder on, and a
//! node that forwards a request sees the grant in it. So the holder signs each
//! request in band, with the private half of the grant's holder key, and the
//! peer checks the signature against that key. No round trip comes first.
//!
//! The holder signs:
//!
//! ```text
//! "kuri-api.HolderRequest/v1\0"
//! || u32le(len(grant_id)) || grant_id
//! || request_digest
//! || i64le(time_ns)
//! || nonce
//! ```
//!
//! - `request_digest` is SHA-256 over `u32le(len(method)) || method || body`:
//!   `method` is the versioned name and method (`registry/1.WatchNodes`), and
//!   `body` is the request's CBOR as sent. A forwarder can neither change the
//!   request nor attach the signature to another ([`RequestDigest`]).
//! - `time_ns` is the home's clock at signing, and `nonce` is 16 fresh random
//!   bytes.
//!
//! The peer ([`Requests::check`]), in order:
//!
//! 1. checks the grant itself ([`Grant::check`]);
//! 2. takes `time_ns` only within [`REQUEST_WINDOW_NS`] of its own reading of
//!    the home's clock, either way, and not earlier than the moment it
//!    started;
//! 3. verifies the signature against the grant's holder key;
//! 4. refuses a `(grant_id, nonce)` it has seen, and keeps each pair until
//!    `time_ns` plus the window has passed.
//!
//! The rule about the start time is what makes the record of nonces safe to
//! lose: after a restart, a request signed before it is refused outright, so
//! nothing recorded before the restart can come back.
//!
//! Whether the grant's principal is revoked is checked apart from this.
//!
//! How the signature travels with the request, say as an attachment, is the
//! transport's. This crate draws no randomness and reads no clock: the caller
//! passes the nonce and the time.

use std::collections::HashMap;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::grant::{Grant, GrantError, IssuerKey, Rejection, Target, Verified};

/// Prefixes the bytes a holder signs for a request, so the signature can
/// never pass for anything else.
pub const REQUEST_CONTEXT: &[u8] = b"kuri-api.HolderRequest/v1\0";

/// How far a request's time may be from the peer's reading of the home's
/// clock, either way: 30 seconds.
///
/// The home's clock is off by about half a round trip on a home network, well
/// under a second; the rest is room for delivery through a router and for the
/// time between two readings of the clock. The window bounds the record of
/// nonces at 60 seconds of traffic.
pub const REQUEST_WINDOW_NS: i64 = 30_000_000_000;

/// The length of a request's nonce.
pub const REQUEST_NONCE_LEN: usize = 16;

/// A request's digest: SHA-256 over its method and its body as sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestDigest(pub [u8; 32]);

impl RequestDigest {
    /// The digest of a request for `method` (the versioned name and method,
    /// such as `registry/1.WatchNodes`) whose CBOR body is `body`.
    pub fn of(method: &str, body: &[u8]) -> Self {
        let mut hash = Sha256::new();
        hash.update((method.len() as u32).to_le_bytes());
        hash.update(method.as_bytes());
        hash.update(body);
        RequestDigest(hash.finalize().into())
    }
}

/// What travels with a request beside its grant: when the holder signed it,
/// its nonce, and the signature.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HolderSignature {
    /// The home's clock at signing, in nanoseconds.
    pub time_ns: i64,
    /// Fresh random bytes, one set per request.
    #[serde(with = "serde_bytes")]
    pub nonce: [u8; REQUEST_NONCE_LEN],
    /// The holder's Ed25519 signature.
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

fn signed_bytes(
    grant_id: &[u8],
    digest: &RequestDigest,
    time_ns: i64,
    nonce: &[u8; REQUEST_NONCE_LEN],
) -> Vec<u8> {
    let mut out = REQUEST_CONTEXT.to_vec();
    out.extend_from_slice(&(grant_id.len() as u32).to_le_bytes());
    out.extend_from_slice(grant_id);
    out.extend_from_slice(&digest.0);
    out.extend_from_slice(&time_ns.to_le_bytes());
    out.extend_from_slice(nonce);
    out
}

/// A holder's key: the private half of the key a grant names.
pub struct HolderKey(SigningKey);

impl HolderKey {
    /// The key from its 32-byte Ed25519 seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        HolderKey(SigningKey::from_bytes(seed))
    }

    /// The public half, which a grant request names as its holder key.
    pub fn public(&self) -> [u8; 32] {
        self.0.verifying_key().to_bytes()
    }

    /// Signs a request made under the grant `grant_id`. `time_ns` is the home's
    /// clock now, and `nonce` must be fresh random bytes.
    pub fn sign(
        &self,
        grant_id: &[u8],
        digest: &RequestDigest,
        time_ns: i64,
        nonce: [u8; REQUEST_NONCE_LEN],
    ) -> HolderSignature {
        let bytes = signed_bytes(grant_id, digest, time_ns, &nonce);
        HolderSignature {
            time_ns,
            nonce,
            signature: self.0.sign(&bytes).to_bytes(),
        }
    }
}

impl std::fmt::Debug for HolderKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("HolderKey").field(&self.public()).finish()
    }
}

/// Why a peer refuses a request signed by a holder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Refusal {
    /// The grant itself does not pass.
    #[error(transparent)]
    Grant(#[from] Rejection),
    /// The request's time is more than the window away from the peer's
    /// reading of the home's clock.
    #[error("the request was signed too far from now")]
    OutsideWindow,
    /// The request was signed before the peer started, so the peer cannot
    /// tell whether it saw its nonce before.
    #[error("the request was signed before this peer started")]
    BeforeStart,
    /// The signature does not verify against the grant's holder key: the
    /// grant is genuine, its presenter is not, or the request was changed.
    #[error("the request is not signed by the grant's holder")]
    HolderSignature,
    /// The peer has seen this nonce under this grant before.
    #[error("the request was seen before")]
    Replayed,
}

/// What a refused request tells its sender. The contract has no codes of its
/// own for a request's time, so a request out of its window, or signed
/// before the peer started, reads as expired.
impl From<Refusal> for GrantError {
    fn from(refusal: Refusal) -> Self {
        match refusal {
            Refusal::Grant(rejection) => rejection.into(),
            Refusal::OutsideWindow | Refusal::BeforeStart => GrantError::Expired,
            Refusal::HolderSignature => GrantError::HolderProofFailed,
            Refusal::Replayed => GrantError::Spent,
        }
    }
}

/// One peer's check of holder-signed requests: the issuer it trusts, when it
/// started, and the nonces it has seen within the window.
#[derive(Debug)]
pub struct Requests {
    issuer: IssuerKey,
    started_ns: i64,
    /// Each `(grant_id, nonce)` seen, with the time after which it is
    /// forgotten.
    seen: HashMap<(Vec<u8>, [u8; REQUEST_NONCE_LEN]), i64>,
}

impl Requests {
    /// A check that trusts grants signed by `issuer`, for a peer that first
    /// read the home's clock at `started_ns`. A request signed before then is
    /// refused.
    pub fn new(issuer: IssuerKey, started_ns: i64) -> Self {
        Requests {
            issuer,
            started_ns,
            seen: HashMap::new(),
        }
    }

    /// Checks a request to `target`, whose digest is `digest`, made under
    /// `grant` and signed with `holder`, at `now_ns` on the home's clock. On
    /// success the nonce is recorded, so the same request is refused if it
    /// comes again.
    ///
    /// Nothing is recorded for a request that fails, so a request without
    /// the holder's signature cannot use up a nonce for the holder.
    pub fn check(
        &mut self,
        grant: &Grant,
        target: &Target<'_>,
        digest: &RequestDigest,
        holder: &HolderSignature,
        now_ns: i64,
    ) -> Result<Verified, Refusal> {
        let verified = grant.check(&self.issuer, target, now_ns)?;
        if holder.time_ns.abs_diff(now_ns) > REQUEST_WINDOW_NS as u64 {
            return Err(Refusal::OutsideWindow);
        }
        if holder.time_ns < self.started_ns {
            return Err(Refusal::BeforeStart);
        }
        let key =
            VerifyingKey::from_bytes(&verified.holder_key).map_err(|_| Refusal::HolderSignature)?;
        let bytes = signed_bytes(&verified.grant_id, digest, holder.time_ns, &holder.nonce);
        key.verify_strict(&bytes, &Signature::from_bytes(&holder.signature))
            .map_err(|_| Refusal::HolderSignature)?;

        self.prune(now_ns);
        let forget_at = holder.time_ns.saturating_add(REQUEST_WINDOW_NS);
        match self.seen.entry((verified.grant_id.clone(), holder.nonce)) {
            std::collections::hash_map::Entry::Occupied(_) => Err(Refusal::Replayed),
            std::collections::hash_map::Entry::Vacant(entry) => {
                entry.insert(forget_at);
                Ok(verified)
            }
        }
    }

    /// Forgets nonces whose requests can no longer pass the window. [`check`]
    /// does this as it goes; a peer may also call it when idle.
    ///
    /// [`check`]: Requests::check
    pub fn prune(&mut self, now_ns: i64) {
        self.seen.retain(|_, forget_at| now_ns <= *forget_at);
    }

    /// How many nonces are kept.
    pub fn remembered(&self) -> usize {
        self.seen.len()
    }
}

#[cfg(test)]
mod tests;
