# kuri-api

The contracts of a home's system plane, as plain Rust types.

A home's machines share one system plane: who is there, what each offers, and
who may use what. `kuri-api` holds its contracts and the checks a node runs on
them, and nothing that moves bytes. It depends on no transport and no runtime,
so it builds with stable cargo for Linux, macOS, Windows and Fuchsia alike,
and the same code checks a grant wherever the grant arrives.

## Grants

A grant is a signed, scoped, bounded permission to reach one capability on one
node. The home's issuer signs it with its Ed25519 key; a provider checks it
offline, with no call to the issuer:

```rust
use kuri_api::grant::{Grant, IssuerKey, Target};

fn admit(grant: &Grant, issuer: &IssuerKey, target: &Target<'_>, now_ns: i64) -> bool {
    grant.check(issuer, target, now_ns).is_ok()
}
```

`check` verifies the signature, that the grant names this node, kind and
instance, and that its deadline on the home's clock has not passed. The
grant is bound to a holder key; proving the presenter holds it is the
transport's part, and so is the revocation check.

`tests/vectors/grants.json` holds grants as they travel, each with the result
a provider's check must reach. Another implementation of the check runs the
same file.

## What else is here

- `request`: requests signed by a grant's holder, for a mesh where every node
  that forwards a request sees the grant in it, and the check a peer runs on
  them: the window on the home's clock, the holder's signature, a nonce not
  seen before. `tests/vectors/requests.json` holds them with their results.
- `clock`: the home's clock, read from the issuer's signed answer and kept as
  an offset from a clock that runs in sleep.
- `revocation`: principals revoked before their grants expire, and the
  heartbeat that tells a provider it missed one.
- `registry`: who a node is, what it serves (compute described: accelerators
  and memory) and how widely, its physical links, and the graph as a reader
  sees it: the nodes there, then as changes.
- `power`: waking a member that sleeps, and holding it awake as a lease.

## Encoding

Every type encodes as CBOR maps with named keys. A table is a struct whose
fields are all optional; a key a reader does not know is ignored, and an enum
or union member it does not know reads as `Unknown`. So an older reader keeps
working with a newer writer. A union is a map of `type` and `value`.

Decoding checks shape, not bounds: the checks here refuse values out of
bounds, and a reader bounds anything else it takes from the network with the
`MAX_` constants.

`tests/surface.json`, generated from the types, lists everything this crate
mirrors from the contracts' definition; a check keeps the two in step.

## Status

0.1. The contracts may grow within 0.1's names; a change that would break a
reader is a new name. No transport is here, and none will be.

## License

MIT OR Apache-2.0, at your option.
