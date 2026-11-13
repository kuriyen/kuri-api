//! The vocabulary every contract shares: who a node is, what it serves, and
//! how widely.

use serde::{Deserialize, Serialize};

/// A node's identity, opaque and at most 64 bytes, issued when the node is
/// enrolled.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId {
    /// The identity's bytes.
    #[serde(with = "serde_bytes")]
    pub bytes: Vec<u8>,
}

/// The longest [`NodeId`], in bytes.
pub const MAX_NODE_ID_LEN: usize = 64;

flexible_enum! {
    /// What kind of thing a capability is.
    pub enum CapabilityKind {
        /// Reads the world: a camera, a microphone, a thermometer.
        Sensor = 1, "sensor";
        /// Runs models.
        Inference = 2, "inference";
        /// Changes the world: a lock, a light, a motor.
        Actuator = 3, "actuator";
    }
}

flexible_enum! {
    /// How widely a capability, or what it produces, may be shared.
    pub enum Scope {
        /// The owner's alone.
        OwnerPrivate = 1, "owner_private";
        /// The household's, kept inside the home.
        BroodPrivate = 2, "brood_private";
        /// The household's, and may be shared beyond it.
        BroodShared = 3, "brood_shared";
    }
}

/// The longest capability instance name, in bytes.
pub const MAX_INSTANCE_LEN: usize = 64;
