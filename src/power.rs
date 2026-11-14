//! Power: waking a member, and keeping it awake while work runs on it.
//!
//! A sleeping member cannot answer for itself, so both go through the home's
//! brain, which knows a way to reach it. A hold is a lease: it lapses at its
//! deadline unless renewed, so a consumer that dies does not keep a member
//! awake for ever. A member asleep shows as [`Health::Asleep`] in the graph,
//! and as [`Health::Online`] once it is up.
//!
//! A hold's id is all it takes to renew or release the hold, so keep it as
//! you would a credential.
//!
//! [`Health::Asleep`]: crate::registry::Health::Asleep
//! [`Health::Online`]: crate::registry::Health::Online

use serde::{Deserialize, Serialize};

use crate::registry::NodeId;

/// The longest a hold lasts before it must be renewed: ten minutes.
pub const MAX_HOLD_NS: i64 = 600_000_000_000;

/// The length of a hold's id.
pub const HOLD_ID_LEN: usize = 16;

flexible_enum! {
    /// Why a power call did not succeed.
    pub enum PowerError {
        /// The brain knows no such node. It keeps its own record of how to
        /// wake each node, so a node asleep long enough to have left the
        /// graph can still be woken.
        UnknownNode = 1, "unknown_node";
        /// The brain knows no way to wake this node.
        CannotWake = 2, "cannot_wake";
        /// No such hold: it lapsed, was released, or never was.
        UnknownHold = 3, "unknown_hold";
        /// The duration is not between 1 ns and [`MAX_HOLD_NS`].
        InvalidDuration = 4, "invalid_duration";
    }
}

/// `Wake`: wake `node` if it sleeps. Answered once the wake is sent, not once
/// the node is up.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerWakeRequest {
    /// The node to wake.
    pub node: NodeId,
}

/// `Hold`: keep `node` awake for `duration_ns`, waking it first if it sleeps.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerHoldRequest {
    /// The node to keep awake.
    pub node: NodeId,
    /// For how long, at most [`MAX_HOLD_NS`].
    pub duration_ns: i64,
}

/// The answer to `Hold`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerHoldResponse {
    /// The hold's id, by which it is renewed and released.
    #[serde(with = "serde_bytes")]
    pub hold_id: [u8; HOLD_ID_LEN],
    /// Its deadline, on the home's clock.
    pub until_ns: i64,
}

/// `Renew`: move a live hold's deadline to `duration_ns` from now.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerRenewRequest {
    /// The hold.
    #[serde(with = "serde_bytes")]
    pub hold_id: [u8; HOLD_ID_LEN],
    /// For how long from now, at most [`MAX_HOLD_NS`].
    pub duration_ns: i64,
}

/// The answer to `Renew`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerRenewResponse {
    /// The hold's new deadline, on the home's clock.
    pub until_ns: i64,
}

/// `Release`: end a hold before its deadline.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowerReleaseRequest {
    /// The hold.
    #[serde(with = "serde_bytes")]
    pub hold_id: [u8; HOLD_ID_LEN],
}

#[cfg(test)]
mod tests;
