//! The registry: who a node is, what it serves and how widely, and the graph
//! of nodes as a reader sees it, first whole and then as changes.

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
        /// Runs work: accelerators and memory, described in
        /// [`Capability::compute`].
        Compute = 4, "compute";
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

/// The most capabilities one [`Announcement`] may carry.
pub const MAX_CAPABILITIES: usize = 16;

/// The most [`CapabilityKind::Compute`] capabilities one [`Announcement`] may
/// carry. A described compute capability is about a kilobyte; the graph's
/// owner refuses more as [`RegistryError::InvalidAnnouncement`].
pub const MAX_COMPUTE_CAPABILITIES: usize = 2;

/// The most accelerators one [`Compute`] describes.
pub const MAX_ACCELERATORS: usize = 8;

/// The most links one [`Announcement`] may carry.
pub const MAX_LINKS: usize = 8;

/// The longest label, accelerator model or link segment, in bytes.
pub const MAX_NAME_LEN: usize = 64;

/// The most nodes the graph holds.
pub const MAX_NODES: usize = 24;

/// The most events one answer to `Watch` carries.
pub const MAX_NODE_EVENTS: usize = 8;

/// How long a `Watch` with nothing to report waits before it answers empty:
/// ten seconds. A reader that hears nothing for longer has lost the graph's
/// owner, and asks again.
pub const WATCH_TICK_NS: i64 = 10_000_000_000;

/// One capability a node offers.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Capability {
    /// What kind of capability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<CapabilityKind>,
    /// Which one, among the node's capabilities of that kind. At most
    /// [`MAX_INSTANCE_LEN`] bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// The scope its owner gave it. Grants may narrow it, never widen it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<Scope>,
    /// What a [`CapabilityKind::Compute`] capability offers. Absent for every
    /// other kind.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub compute: Option<Compute>,
}

flexible_enum! {
    /// What kind of accelerator.
    pub enum AcceleratorKind {
        /// A graphics processor.
        Gpu = 1, "gpu";
        /// A tensor processor.
        Tpu = 2, "tpu";
        /// A neural processor.
        Npu = 3, "npu";
    }
}

/// One accelerator of a compute capability.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Accelerator {
    /// What kind of accelerator.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<AcceleratorKind>,
    /// The vendor's name for the model.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Its own memory, in bytes. Absent where it shares the system's.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
}

/// What a compute capability offers: a description, for deciding where work
/// should go. How work runs on it is the consumer's.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Compute {
    /// Its accelerators, at most [`MAX_ACCELERATORS`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accelerators: Option<Vec<Accelerator>>,
    /// The system memory it may use, in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
}

flexible_enum! {
    /// What kind of physical link.
    pub enum LinkKind {
        /// Wired Ethernet.
        Ethernet = 1, "ethernet";
        /// Wireless.
        Wifi = 2, "wifi";
        /// A Thunderbolt cable.
        Thunderbolt = 3, "thunderbolt";
        /// InfiniBand.
        Infiniband = 4, "infiniband";
    }
}

flexible_enum! {
    /// Which remote direct memory access a link offers.
    pub enum Rdma {
        /// None.
        None = 1, "none";
        /// RDMA over Converged Ethernet, version 2.
        RoceV2 = 2, "roce_v2";
        /// InfiniBand's own.
        Infiniband = 3, "infiniband";
        /// Over Thunderbolt.
        Thunderbolt = 4, "thunderbolt";
    }
}

/// One physical link of a node: coarse facts, never a MAC or an IP address.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Link {
    /// What kind of link.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<LinkKind>,
    /// The negotiated nominal rate, in bits per second.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub speed_bps: Option<u64>,
    /// The remote direct memory access it offers.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rdma: Option<Rdma>,
    /// The far end of a point-to-point link, such as a Thunderbolt cable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer: Option<NodeId>,
    /// Equal values mean the same switch or segment; present only when the
    /// node knows it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub segment: Option<String>,
}

/// A node's announcement of itself and everything it serves.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Announcement {
    /// Who the node is.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<NodeId>,
    /// A label for people; nothing keys on it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    /// Everything it serves, at most [`MAX_CAPABILITIES`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<Capability>>,
    /// Its physical links, at most [`MAX_LINKS`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<Link>>,
}

flexible_enum! {
    /// Why a node's registration, heartbeat or sleep was refused.
    pub enum RegistryError {
        /// The announcement is malformed: no `NodeId`, `compute` on a
        /// capability that is not compute, or more than
        /// [`MAX_COMPUTE_CAPABILITIES`] of them.
        InvalidAnnouncement = 1, "invalid_announcement";
        /// The node is not known: register again.
        NotEnrolled = 2, "not_enrolled";
        /// The graph holds [`MAX_NODES`] and none of them is stale.
        GraphFull = 3, "graph_full";
    }
}

flexible_enum! {
    /// A node's liveness, as the graph's owner sees it.
    pub enum Health {
        /// Heard from within its window.
        Online = 1, "online";
        /// Missed its window. No new grants.
        Stale = 2, "stale";
        /// Said it was going to sleep, and silent since. No new grants, as
        /// for `Stale`; unlike `Stale`, it can be woken
        /// ([`crate::power`]).
        Asleep = 3, "asleep";
    }
}

/// One node, as the graph holds it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NodeState {
    /// What the node last announced, exactly as it said it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub announcement: Option<Announcement>,
    /// Its liveness.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<Health>,
    /// When the graph's owner last heard from it, on the owner's monotonic
    /// clock: comparable only with other values from the same owner, within
    /// one of its runs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_monotonic_ns: Option<i64>,
}

/// One step that brings a reader's copy of the graph up to date.
///
/// A reader is first sent an `Existing` for each node, then `Idle`, after
/// which it holds the graph; then `Added`, `Changed` and `Removed`, coalesced,
/// so that a node that changed twice is one `Changed` with its latest state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeEvent {
    /// A node that was in the graph when the watch began.
    Existing(NodeState),
    /// The `Existing` events are over.
    Idle,
    /// A node joined the graph.
    Added(NodeState),
    /// A node announced something different, or its health changed: its
    /// whole state.
    Changed(NodeState),
    /// A node left the graph.
    Removed(NodeId),
    /// A member this version of the contract does not know. A reader cannot
    /// tell what it would have done to the graph, so it should read the graph
    /// afresh rather than guess.
    Unknown,
}

impl Serialize for NodeEvent {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::{Error as _, SerializeMap};
        fn entry<S: serde::Serializer, T: Serialize>(
            serializer: S,
            name: &str,
            value: Option<&T>,
        ) -> Result<S::Ok, S::Error> {
            let mut map = serializer.serialize_map(Some(1 + usize::from(value.is_some())))?;
            map.serialize_entry("type", name)?;
            if let Some(value) = value {
                map.serialize_entry("value", value)?;
            }
            map.end()
        }
        match self {
            NodeEvent::Existing(state) => entry(serializer, "existing", Some(state)),
            NodeEvent::Idle => entry::<_, ()>(serializer, "idle", None),
            NodeEvent::Added(state) => entry(serializer, "added", Some(state)),
            NodeEvent::Changed(state) => entry(serializer, "changed", Some(state)),
            NodeEvent::Removed(node) => entry(serializer, "removed", Some(node)),
            NodeEvent::Unknown => Err(S::Error::custom("an unknown NodeEvent cannot be encoded")),
        }
    }
}

impl<'de> Deserialize<'de> for NodeEvent {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            #[serde(rename = "type")]
            name: String,
            #[serde(default)]
            value: Option<ciborium::Value>,
        }
        fn content<T: serde::de::DeserializeOwned, E: serde::de::Error>(
            value: Option<ciborium::Value>,
        ) -> Result<T, E> {
            value
                .ok_or_else(|| E::missing_field("value"))?
                .deserialized()
                .map_err(E::custom)
        }
        let raw = Raw::deserialize(deserializer)?;
        Ok(match raw.name.as_str() {
            "existing" => NodeEvent::Existing(content(raw.value)?),
            "idle" => NodeEvent::Idle,
            "added" => NodeEvent::Added(content(raw.value)?),
            "changed" => NodeEvent::Changed(content(raw.value)?),
            "removed" => NodeEvent::Removed(content(raw.value)?),
            _ => NodeEvent::Unknown,
        })
    }
}

/// The answer to `Watch`: at most [`MAX_NODE_EVENTS`] events, or none after
/// [`WATCH_TICK_NS`] with nothing to report.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryReaderWatchResponse {
    /// The events, in order.
    pub events: Vec<NodeEvent>,
}

#[cfg(test)]
mod tests;
