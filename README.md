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

## Encoding

Every type encodes as CBOR maps with named keys. A table is a struct whose
fields are all optional; a key a reader does not know is ignored, and an enum
member it does not know reads as `Unknown`. So an older reader keeps working
with a newer writer.

## Status

0.1 is being written. Besides grants, it carries requests signed by a
grant's holder (`request`), for a mesh where every node that forwards a
request sees the grant in it. Still to come: the registry for readers, the
home's clock, revocations and power.

## License

MIT OR Apache-2.0, at your option.
