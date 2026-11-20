//! Grants: a signed, scoped, bounded permission to reach one capability on
//! one node, and the check a provider runs on one offline.
//!
//! A consumer asks the home's issuer for a grant ([`GrantRequest`]), and the
//! issuer answers with a [`Grant`] signed by its Ed25519 key. The consumer
//! presents the grant to the provider with each request, and the provider
//! checks it without calling anyone ([`Grant::check`]): the issuer's
//! signature, that the grant names this node, kind and instance, and that its
//! deadline on the home's clock has not passed and is no further off than a
//! grant can live ([`DEADLINE_SLACK_NS`]). So the issuer stays off the
//! path of every call, and grants keep working while it restarts.
//!
//! A grant is bound to its holder: it names the public key whose private half
//! the holder must prove it has. That proof is the transport's to carry; this
//! check is only the grant's own.
//!
//! # What is signed
//!
//! The signature covers [`Grant::signed_bytes`], not the grant's encoding. A
//! reader built against an older contract decodes a newer grant with its
//! unknown keys dropped, so re-encoding would not reproduce what was signed.
//! The layout is fixed by the version in [`GRANT_CONTEXT`]: every field but
//! the signature, in the order of their numbers in the contract, each
//! length-prefixed. A field added to `Grant` joins it only under a new
//! version, which an older provider then fails to verify. That fails closed,
//! which is the right way to fail.
//!
//! ```text
//! "kuri-api.Grant/v1\0"
//! || u32le(len(principal)) || principal
//! || u32le(len(provider))  || provider
//! || u32le(kind)
//! || u32le(len(instance))  || instance
//! || u32le(scope)
//! || u32le(len(holder_key)) || holder_key
//! || u32le(len(grant_id))  || grant_id
//! || 0x00                  (no expires_utc_ns)
//!    or 0x01 || i64le(expires_utc_ns)
//! || u32le(len(issued_epoch)) || issued_epoch
//! || i64le(max_lifetime_ns)
//! ```
//!
//! Signing grants is the issuer's alone, and not part of this crate.

use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

use crate::registry::{CapabilityKind, NodeId, Scope, MAX_INSTANCE_LEN, MAX_NODE_ID_LEN};

/// Prefixes the bytes a grant's signature covers, so a signature over a grant
/// can never verify as anything else, nor anything else as a grant.
pub const GRANT_CONTEXT: &[u8] = b"kuri-api.Grant/v1\0";

/// The longest `max_lifetime_ns` a provider accepts: five minutes.
pub const MAX_GRANT_LIFETIME_NS: i64 = 300_000_000_000;

/// How far past [`MAX_GRANT_LIFETIME_NS`] from now a grant's deadline may
/// lie: 30 seconds, room for the issuer's and the provider's readings of the
/// home's clock to differ.
///
/// A provider keeps a revocation until its time plus [`MAX_GRANT_LIFETIME_NS`]
/// and this slack. That covers every grant issued before the revocation whose
/// deadline is at most the lifetime plus the slack after its issue. A deadline
/// further off is an issuer's bug. It is refused whenever the grant is
/// presented while more than the lifetime plus the slack remains, so the bug
/// shows; a grant held back unpresented until less remains is not caught
/// here, since a grant does not say when it was issued.
pub const DEADLINE_SLACK_NS: i64 = 30_000_000_000;

/// The length of a holder key: an Ed25519 public key.
pub const HOLDER_KEY_LEN: usize = 32;

/// The longest [`PrincipalId`], in bytes.
pub const MAX_PRINCIPAL_LEN: usize = 64;

/// The longest `grant_id`, in bytes.
pub const MAX_GRANT_ID_LEN: usize = 32;

/// The longest `issued_epoch`, in bytes.
pub const MAX_ISSUED_EPOCH_LEN: usize = 32;

/// The longest `holder_key` the contract carries, in bytes. A grant whose
/// key is not [`HOLDER_KEY_LEN`] long is refused as malformed.
pub const MAX_HOLDER_KEY_LEN: usize = 64;

/// The longest `signature` the contract carries, in bytes.
pub const MAX_SIGNATURE_LEN: usize = 512;

/// An identity that may hold grants: the owner, or a member of the household.
/// Distinct from [`NodeId`]: a principal acts through any number of nodes.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PrincipalId {
    /// The identity's bytes, opaque and at most [`MAX_PRINCIPAL_LEN`].
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
}

/// A request to reach one capability on one node: exactly the tuple a grant
/// is scoped to, so a grant can never be wider than what was asked for.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GrantRequest {
    /// Who is asking.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<PrincipalId>,
    /// The node that serves the capability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<NodeId>,
    /// Which kind of capability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<CapabilityKind>,
    /// Which instance of it, on that node.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// The public key the consumer will prove it holds when it uses the grant.
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub holder_key: Option<Vec<u8>>,
}

/// A signed, scoped, bounded permission to reach one capability on one node.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Grant {
    /// Who the grant was issued to.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub principal: Option<PrincipalId>,
    /// The node it may reach.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<NodeId>,
    /// The kind of capability it may reach.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<CapabilityKind>,
    /// The instance it may reach.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// The scope granted, which may be narrower than the provider offers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    /// The public key whose private half the holder proves it has.
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub holder_key: Option<Vec<u8>>,
    /// Unique per issuance.
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub grant_id: Option<Vec<u8>>,
    /// The deadline, in nanoseconds on the home's clock.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_utc_ns: Option<i64>,
    /// Which run of the issuer issued it, opaque.
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub issued_epoch: Option<Vec<u8>>,
    /// How long it lasts from a provider's first sight of it, the bound a
    /// provider uses before it has read the home's clock. The signature covers
    /// it and [`Grant::check`] requires it between 1 ns and
    /// [`MAX_GRANT_LIFETIME_NS`], but this crate's check never decides expiry
    /// by it: it always has the home's clock, and goes by `expires_utc_ns`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_lifetime_ns: Option<i64>,
    /// The issuer's Ed25519 signature over [`Grant::signed_bytes`].
    #[serde(default, with = "serde_bytes", skip_serializing_if = "Option::is_none")]
    pub signature: Option<Vec<u8>>,
}

flexible_enum! {
    /// Why a grant was refused: by the issuer when asked for one, or by a
    /// provider when one was presented.
    pub enum GrantError {
        /// The principal could not be authenticated.
        Unauthenticated = 1, "unauthenticated";
        /// The provider, or the capability asked for, is not known.
        UnknownCapability = 2, "unknown_capability";
        /// Policy forbids this principal this capability at this scope.
        DeniedByPolicy = 3, "denied_by_policy";
        /// A ceiling forbids it whatever the policy, which an owner cannot
        /// widen.
        TierCeiling = 4, "tier_ceiling";
        /// The party presenting the grant did not prove it holds the grant's
        /// holder key: the grant is genuine, its presenter is not.
        HolderProofFailed = 5, "holder_proof_failed";
        /// A field is missing or out of bounds.
        InvalidGrant = 6, "invalid_grant";
        /// The signature does not verify against the issuer's key.
        UntrustedSignature = 7, "untrusted_signature";
        /// A genuine grant for another node, kind or instance.
        WrongTarget = 8, "wrong_target";
        /// The grant's deadline has passed.
        Expired = 9, "expired";
        /// The grant was already used where it may be used once.
        Spent = 10, "spent";
        /// A proof came before the challenge it answers.
        NoChallenge = 11, "no_challenge";
        /// The provider does not serve the capability asked for.
        UnknownService = 12, "unknown_service";
    }
}

/// A grant that does not have the shape the contract promises: a field is
/// missing or out of bounds. Names the field.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the grant's `{0}` is missing or out of bounds")]
pub struct Malformed(pub &'static str);

/// Why a provider refuses a grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Rejection {
    /// The grant is not well formed. Checked before the signature, so nothing
    /// malformed is ever verified.
    #[error(transparent)]
    Malformed(#[from] Malformed),
    /// The signature does not verify against the issuer's key: forged,
    /// altered, or issued by another issuer.
    #[error("the grant's signature does not verify against the issuer's key")]
    BadSignature,
    /// A genuine grant, for another node, kind or instance than the one it
    /// was presented to.
    #[error("the grant is for another node, kind or instance")]
    WrongTarget,
    /// The grant's deadline on the home's clock has passed.
    #[error("the grant's deadline has passed")]
    Expired,
    /// A genuine grant whose deadline lies further off than a grant can live,
    /// plus [`DEADLINE_SLACK_NS`]: the issuer's bug, refused as invalid.
    #[error("the grant's deadline is further off than a grant can live")]
    DeadlineTooFar,
}

impl From<Rejection> for GrantError {
    fn from(rejection: Rejection) -> Self {
        match rejection {
            Rejection::Malformed(_) => GrantError::InvalidGrant,
            Rejection::BadSignature => GrantError::UntrustedSignature,
            Rejection::WrongTarget => GrantError::WrongTarget,
            Rejection::Expired => GrantError::Expired,
            Rejection::DeadlineTooFar => GrantError::InvalidGrant,
        }
    }
}

/// The issuer's public key, which a provider trusts to sign grants.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerKey(VerifyingKey);

/// Bytes that are not an Ed25519 public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("not an Ed25519 public key")]
pub struct BadKey;

impl IssuerKey {
    /// The issuer's key from its 32 bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, BadKey> {
        VerifyingKey::from_bytes(bytes)
            .map(IssuerKey)
            .map_err(|_| BadKey)
    }

    /// The key's 32 bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_bytes()
    }

    /// Whether the issuer signed `message`. Strict, so a signature has one
    /// valid form and a weak key verifies nothing.
    pub(crate) fn verify(
        &self,
        message: &[u8],
        signature: &Signature,
    ) -> Result<(), ed25519_dalek::SignatureError> {
        self.0.verify_strict(message, signature)
    }
}

/// What a grant is being presented for: the provider's own node, and the
/// capability the request would reach.
#[derive(Clone, Copy, Debug)]
pub struct Target<'a> {
    /// The provider's node.
    pub node: &'a NodeId,
    /// The kind of capability.
    pub kind: CapabilityKind,
    /// The instance.
    pub instance: &'a str,
}

/// A grant that passed [`Grant::check`]: what the provider needs from it
/// afterwards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Verified {
    /// Who the grant was issued to.
    pub principal: PrincipalId,
    /// The grant's id.
    pub grant_id: Vec<u8>,
    /// The key the holder must prove it has.
    pub holder_key: [u8; HOLDER_KEY_LEN],
    /// The scope granted.
    pub scope: Scope,
    /// The deadline on the home's clock, after which the grant serves no
    /// request.
    pub expires_ns: i64,
}

/// Every field the signature covers, checked against the contract's bounds.
struct Fields<'a> {
    principal: &'a [u8],
    provider: &'a [u8],
    kind: u32,
    instance: &'a str,
    scope: Scope,
    scope_number: u32,
    holder_key: [u8; HOLDER_KEY_LEN],
    grant_id: &'a [u8],
    expires_utc_ns: Option<i64>,
    issued_epoch: &'a [u8],
    max_lifetime_ns: i64,
}

impl<'a> Fields<'a> {
    fn of(grant: &'a Grant) -> Result<Self, Malformed> {
        fn bounded<'b>(
            field: Option<&'b [u8]>,
            name: &'static str,
            max: usize,
        ) -> Result<&'b [u8], Malformed> {
            match field {
                Some(bytes) if !bytes.is_empty() && bytes.len() <= max => Ok(bytes),
                _ => Err(Malformed(name)),
            }
        }

        let kind = grant.kind.and_then(CapabilityKind::number);
        let scope = grant.scope.filter(|scope| *scope != Scope::Unknown);
        let instance = grant
            .instance
            .as_deref()
            .filter(|instance| instance.len() <= MAX_INSTANCE_LEN)
            .ok_or(Malformed("instance"))?;
        let holder_key = grant
            .holder_key
            .as_deref()
            .and_then(|key| <[u8; HOLDER_KEY_LEN]>::try_from(key).ok())
            .ok_or(Malformed("holder_key"))?;
        let max_lifetime_ns = grant
            .max_lifetime_ns
            .filter(|ns| (1..=MAX_GRANT_LIFETIME_NS).contains(ns))
            .ok_or(Malformed("max_lifetime_ns"))?;
        Ok(Fields {
            principal: bounded(
                grant.principal.as_ref().map(|p| &p.bytes[..]),
                "principal",
                MAX_PRINCIPAL_LEN,
            )?,
            provider: bounded(
                grant.provider.as_ref().map(|p| &p.bytes[..]),
                "provider",
                MAX_NODE_ID_LEN,
            )?,
            kind: kind.ok_or(Malformed("kind"))?,
            instance,
            scope: scope.ok_or(Malformed("scope"))?,
            scope_number: scope.and_then(Scope::number).ok_or(Malformed("scope"))?,
            holder_key,
            grant_id: bounded(grant.grant_id.as_deref(), "grant_id", MAX_GRANT_ID_LEN)?,
            expires_utc_ns: grant.expires_utc_ns,
            issued_epoch: bounded(
                grant.issued_epoch.as_deref(),
                "issued_epoch",
                MAX_ISSUED_EPOCH_LEN,
            )?,
            max_lifetime_ns,
        })
    }

    fn signed_bytes(&self) -> Vec<u8> {
        let mut out = GRANT_CONTEXT.to_vec();
        put(&mut out, self.principal);
        put(&mut out, self.provider);
        out.extend_from_slice(&self.kind.to_le_bytes());
        put(&mut out, self.instance.as_bytes());
        out.extend_from_slice(&self.scope_number.to_le_bytes());
        put(&mut out, &self.holder_key);
        put(&mut out, self.grant_id);
        match self.expires_utc_ns {
            None => out.push(0),
            Some(ns) => {
                out.push(1);
                out.extend_from_slice(&ns.to_le_bytes());
            }
        }
        put(&mut out, self.issued_epoch);
        out.extend_from_slice(&self.max_lifetime_ns.to_le_bytes());
        out
    }
}

/// Appends a length-prefixed field. Every field is bounded at 64 bytes, so
/// its length fits a `u32` with room to spare.
fn put(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    out.extend_from_slice(bytes);
}

impl Grant {
    /// The bytes the grant's signature covers (see the [module](self)
    /// documentation), or which field keeps the grant from having them.
    pub fn signed_bytes(&self) -> Result<Vec<u8>, Malformed> {
        Ok(Fields::of(self)?.signed_bytes())
    }

    /// Checks the grant offline, for a request to `target` at `now_ns` on the
    /// home's clock.
    ///
    /// In order: the grant is well formed; the issuer signed it; it names
    /// `target`; its deadline has not passed; and its deadline is no later
    /// than `now_ns` plus [`MAX_GRANT_LIFETIME_NS`] and [`DEADLINE_SLACK_NS`].
    /// A grant without a deadline on the home's clock is refused as
    /// malformed, since only that deadline bounds it here.
    ///
    /// The check is the grant's own. The provider still has to see that the
    /// party presenting it holds [`Verified::holder_key`], and that its
    /// principal has not been revoked.
    pub fn check(
        &self,
        issuer: &IssuerKey,
        target: &Target<'_>,
        now_ns: i64,
    ) -> Result<Verified, Rejection> {
        let fields = Fields::of(self)?;
        let expires_ns = fields.expires_utc_ns.ok_or(Malformed("expires_utc_ns"))?;
        let signature = self
            .signature
            .as_deref()
            .and_then(|bytes| <[u8; 64]>::try_from(bytes).ok())
            .ok_or(Malformed("signature"))?;
        issuer
            .verify(&fields.signed_bytes(), &Signature::from_bytes(&signature))
            .map_err(|_| Rejection::BadSignature)?;

        // Only a genuine grant gets this far, so only the issuer's own grants
        // are ever compared with the target.
        if fields.provider != &target.node.bytes[..]
            || Some(fields.kind) != target.kind.number()
            || fields.instance != target.instance
        {
            return Err(Rejection::WrongTarget);
        }
        if now_ns >= expires_ns {
            return Err(Rejection::Expired);
        }
        if expires_ns > now_ns.saturating_add(MAX_GRANT_LIFETIME_NS + DEADLINE_SLACK_NS) {
            return Err(Rejection::DeadlineTooFar);
        }
        Ok(Verified {
            principal: PrincipalId {
                bytes: fields.principal.to_vec(),
            },
            grant_id: fields.grant_id.to_vec(),
            holder_key: fields.holder_key,
            scope: fields.scope,
            expires_ns,
        })
    }
}

#[cfg(test)]
mod tests;
