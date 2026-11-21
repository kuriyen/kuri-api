//! The contracts of a home's system plane, as plain Rust types.
//!
//! A home's machines share one system plane: who is there, what each offers,
//! who may use what. This crate holds its contracts, the types and the checks
//! a node runs on them, and nothing that moves bytes: no transport, no
//! runtime, no clock of its own. So it builds with stable cargo for any
//! target, and the same code checks a grant wherever the grant arrives.
//!
//! # What is here
//!
//! - [`registry`]: a node's identity, what it serves (compute described) and
//!   how widely, its links, and the graph as a reader sees it: whole, then as
//!   changes ([`registry::NodeEvent`]).
//! - [`grant`]: a grant, the signed permission to reach one capability on one
//!   node, and the check a provider runs on it offline.
//! - [`request`]: a request signed by a grant's holder, for a mesh where a
//!   forwarding node sees the grant, and the check a peer runs on it offline.
//! - [`clock`]: the home's clock, read from the issuer, which every check of a
//!   deadline or a request's time is against.
//! - [`revocation`]: principals revoked before their grants expire, and the
//!   heartbeat that finds a revocation a provider missed.
//! - [`power`]: waking a member that sleeps, and holding it awake.
//!
//! # Encoding
//!
//! Every type encodes as CBOR maps with named keys ([`to_cbor`],
//! [`from_cbor`]):
//!
//! - **Tables** are structs whose fields are all optional. A missing key reads
//!   as `None`, and a key this version does not know is ignored, so an older
//!   reader keeps working with a newer writer.
//! - **Enums** encode as their names in `snake_case`. A name this version does
//!   not know reads as the enum's `Unknown` case.
//! - **Unions** encode as a map of `type`, the member's name in `snake_case`,
//!   and `value`, its content, absent for a member that carries none. A name
//!   this version does not know reads as the union's `Unknown` case.
//! - **Structs**, a method's request or answer, have every field required.
//!
//! Decoding checks the shape, not the definition's bounds: a string, byte
//! string or list longer than its `MAX_` constant decodes, and the value can
//! take many times its encoded size in memory. So a reader takes a message
//! from the network in this order:
//!
//! 1. it bounds the bytes, by [`MAX_MESSAGE_BYTES`];
//! 2. where a signature covers the raw bytes, it checks the signature: a
//!    request's body is in its digest, and a node signs the digest of what
//!    it replies and publishes;
//! 3. then it decodes, with [`from_cbor`], which refuses bytes after the
//!    value.
//!
//! Every check this crate runs on a decoded value (a grant, a request, a
//! revocation) refuses one out of bounds; any other value, the reader bounds
//! with the `MAX_` constants.
//!
//! # Versions
//!
//! Each protocol is named with its major version (`grants/1`). Within one,
//! only additions; a change that would break a reader is a new name. Signed
//! layouts carry their version in their context string, so a field joins one
//! only under a new version, which an older peer then fails to verify.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

#[macro_use]
mod wire;

pub mod clock;
pub mod grant;
pub mod power;
pub mod registry;
pub mod request;
pub mod revocation;

pub use wire::{from_cbor, to_cbor, DecodeError, EncodeError, MAX_MESSAGE_BYTES};
