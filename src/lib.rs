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
//! - [`registry`]: the vocabulary every contract shares, a node's identity, the
//!   kinds of capability it serves, and the scope of what it serves.
//! - [`grant`]: a grant, the signed permission to reach one capability on one
//!   node, and the check a provider runs on it offline.
//! - [`request`]: a request signed by a grant's holder, for a mesh where a
//!   forwarding node sees the grant, and the check a peer runs on it offline.
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

pub mod grant;
pub mod registry;
pub mod request;

pub use wire::{from_cbor, to_cbor, DecodeError, EncodeError};
