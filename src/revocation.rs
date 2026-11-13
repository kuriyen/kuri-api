//! Revocations: ending a principal's grants before their deadlines.
//!
//! A grant serves request after request until its deadline, and a mesh has
//! no channel to tear down, so when a principal is revoked the issuer tells
//! the providers. A revocation names the principal, its time on the home's
//! clock, and `until_ns`, that time plus the longest grant lifetime, after
//! which no grant issued before it is valid. It is signed by the key that
//! signs grants:
//!
//! ```text
//! "kuri-api.Revoke/v1\0"
//! || u32le(len(principal)) || principal
//! || i64le(revoked_ns)
//! || i64le(until_ns)
//! ```
//!
//! A provider keeps each revoked principal until `until_ns`, and until then
//! refuses every request whose grant names it ([`Revocations`]).
//!
//! # Finding one that was missed
//!
//! Each revocation's `revoked_ns` is later than the one before. Every 10
//! seconds the issuer publishes a heartbeat with no payload, naming the
//! newest revocation's `revoked_ns` (0 if none), signed by the same key:
//!
//! ```text
//! "kuri-api.RevokeHeartbeat/v1\0" || i64le(revoked_ns)
//! ```
//!
//! The answer to a query for the list names the same value: beside the
//! revocations in force, it carries the newest `revoked_ns`, expired or not,
//! with that signature ([`RevocationList`]).
//!
//! A provider keeps the value the last answer named, and only an answer sets
//! it. A heartbeat that names a newer one sends the provider back to the list
//! ([`Heard::AskAgain`]); if that query fails, the next heartbeat sends it
//! back again. A revocation that arrives takes effect but does not set the
//! value either: revocations have no consecutive sequence, so the one
//! received does not show whether an earlier one was missed. Each revocation
//! thus costs every provider one more query, and revocations are rare. A
//! provider started after the newest revocation expired learns its
//! `revoked_ns` from the answer, and the heartbeats that follow do not send
//! it back.
//!
//! A heartbeat is not checked against a window: replaying an old one can at
//! most send a provider that is behind anyway to the list once more.
//!
//! If a revocation is missed anyway, the grant's deadline still bounds it.

use std::collections::HashMap;

use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

use crate::grant::{IssuerKey, PrincipalId, MAX_GRANT_LIFETIME_NS, MAX_PRINCIPAL_LEN};

/// Prefixes the bytes the issuer signs for a revocation.
pub const REVOKE_CONTEXT: &[u8] = b"kuri-api.Revoke/v1\0";

/// Prefixes the bytes the issuer signs for a heartbeat, or for the newest
/// `revoked_ns` in an answer.
pub const REVOKE_HEARTBEAT_CONTEXT: &[u8] = b"kuri-api.RevokeHeartbeat/v1\0";

/// How often the issuer publishes its heartbeat: every 10 seconds.
pub const REVOKE_HEARTBEAT_EVERY_NS: i64 = 10_000_000_000;

/// A principal revoked: until `until_ns`, no grant naming it is honoured.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    /// Who is revoked.
    pub principal: PrincipalId,
    /// When, on the home's clock.
    pub revoked_ns: i64,
    /// `revoked_ns` plus the longest grant lifetime: when every grant issued
    /// before the revocation has expired anyway.
    pub until_ns: i64,
    /// The issuer's signature over [`Revocation::signed_bytes`].
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

impl Revocation {
    /// The bytes the issuer signs for a revocation.
    pub fn signed_bytes(principal: &PrincipalId, revoked_ns: i64, until_ns: i64) -> Vec<u8> {
        let mut out = REVOKE_CONTEXT.to_vec();
        out.extend_from_slice(&(principal.bytes.len() as u32).to_le_bytes());
        out.extend_from_slice(&principal.bytes);
        out.extend_from_slice(&revoked_ns.to_le_bytes());
        out.extend_from_slice(&until_ns.to_le_bytes());
        out
    }
}

/// The newest revocation's `revoked_ns`, signed: the issuer's heartbeat, and
/// the part of a list's answer that says how new the list is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevokeHeartbeat {
    /// The newest revocation's `revoked_ns`, expired or not; 0 if there has
    /// been none.
    pub revoked_ns: i64,
    /// The issuer's signature over [`RevokeHeartbeat::signed_bytes`].
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

impl RevokeHeartbeat {
    /// The bytes the issuer signs for a heartbeat.
    pub fn signed_bytes(revoked_ns: i64) -> Vec<u8> {
        let mut out = REVOKE_HEARTBEAT_CONTEXT.to_vec();
        out.extend_from_slice(&revoked_ns.to_le_bytes());
        out
    }
}

/// The answer to a query for the revocations in force.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RevocationList {
    /// Every revocation still in force.
    pub revocations: Vec<Revocation>,
    /// The newest revocation's `revoked_ns`, expired or not.
    pub newest: RevokeHeartbeat,
}

/// A revocation, heartbeat or list that is not the issuer's.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RevocationError {
    /// The signature does not verify against the issuer's key.
    #[error("not signed by the issuer")]
    BadSignature,
    /// The revocation's principal is empty or too long.
    #[error("the revocation's principal is empty or too long")]
    Malformed,
}

/// What a heartbeat means for the provider that heard it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Heard {
    /// The provider's list is as new as the issuer's.
    UpToDate,
    /// A revocation is newer than the provider's last answer, or it has had
    /// none: query the list.
    AskAgain,
}

/// The revocations one provider holds, and how new its last answer was.
#[derive(Debug)]
pub struct Revocations {
    issuer: IssuerKey,
    /// Each revoked principal, with the time until which it stays revoked.
    revoked: HashMap<Vec<u8>, i64>,
    /// The newest `revoked_ns` the last answer named; `None` before the
    /// first answer.
    answered: Option<i64>,
}

impl Revocations {
    /// A provider's revocations before it has asked for the list. Until an
    /// answer arrives it is not [`ready`](Revocations::ready).
    pub fn new(issuer: IssuerKey) -> Self {
        Revocations {
            issuer,
            revoked: HashMap::new(),
            answered: None,
        }
    }

    /// Whether the provider has had an answer to its query for the list. A
    /// provider refuses requests signed by a holder until it has.
    pub fn ready(&self) -> bool {
        self.answered.is_some()
    }

    fn verified(&self, revocation: &Revocation) -> Result<(), RevocationError> {
        let principal = &revocation.principal.bytes;
        if principal.is_empty() || principal.len() > MAX_PRINCIPAL_LEN {
            return Err(RevocationError::Malformed);
        }
        let bytes = Revocation::signed_bytes(
            &revocation.principal,
            revocation.revoked_ns,
            revocation.until_ns,
        );
        self.issuer
            .verify(&bytes, &Signature::from_bytes(&revocation.signature))
            .map_err(|_| RevocationError::BadSignature)
    }

    fn verified_newest(&self, heartbeat: &RevokeHeartbeat) -> Result<i64, RevocationError> {
        self.issuer
            .verify(
                &RevokeHeartbeat::signed_bytes(heartbeat.revoked_ns),
                &Signature::from_bytes(&heartbeat.signature),
            )
            .map_err(|_| RevocationError::BadSignature)?;
        Ok(heartbeat.revoked_ns)
    }

    /// Keeps a verified revocation. It lasts until `until_ns`, and at least
    /// until every grant issued before it has expired: a signed revocation
    /// whose `until_ns` is short of that is kept the longer time rather than
    /// refused, since refusing it would leave the principal unrevoked.
    fn keep(&mut self, revocation: &Revocation) {
        let lasts = revocation
            .until_ns
            .max(revocation.revoked_ns.saturating_add(MAX_GRANT_LIFETIME_NS));
        let until = self
            .revoked
            .entry(revocation.principal.bytes.clone())
            .or_insert(lasts);
        *until = (*until).max(lasts);
    }

    /// Takes the answer to a query for the list. Every part of it is verified
    /// before any takes effect, so a list with one forged entry changes
    /// nothing.
    pub fn answer(&mut self, list: &RevocationList) -> Result<(), RevocationError> {
        let newest = self.verified_newest(&list.newest)?;
        for revocation in &list.revocations {
            self.verified(revocation)?;
        }
        for revocation in &list.revocations {
            self.keep(revocation);
        }
        self.answered = Some(newest);
        Ok(())
    }

    /// Takes a revocation as it is published. It takes effect at once, but
    /// does not count as an answer (see the [module](self) documentation).
    pub fn revoked(&mut self, revocation: &Revocation) -> Result<(), RevocationError> {
        self.verified(revocation)?;
        self.keep(revocation);
        Ok(())
    }

    /// Takes the issuer's heartbeat, and says whether to query the list.
    pub fn heartbeat(&mut self, heartbeat: &RevokeHeartbeat) -> Result<Heard, RevocationError> {
        let newest = self.verified_newest(heartbeat)?;
        Ok(match self.answered {
            Some(answered) if answered >= newest => Heard::UpToDate,
            _ => Heard::AskAgain,
        })
    }

    /// Whether `principal` is revoked at `now_ns` on the home's clock.
    pub fn is_revoked(&self, principal: &PrincipalId, now_ns: i64) -> bool {
        self.revoked
            .get(&principal.bytes)
            .is_some_and(|until| now_ns < *until)
    }

    /// Forgets revocations that have run out, at `now_ns` on the home's
    /// clock.
    pub fn prune(&mut self, now_ns: i64) {
        self.revoked.retain(|_, until| now_ns < *until);
    }

    /// How many revoked principals are kept.
    pub fn len(&self) -> usize {
        self.revoked.len()
    }

    /// Whether no principal is kept as revoked.
    pub fn is_empty(&self) -> bool {
        self.revoked.is_empty()
    }
}

#[cfg(test)]
mod tests;
