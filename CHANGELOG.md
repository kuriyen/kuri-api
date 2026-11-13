# Changelog

## 0.1.0 (unreleased)

- Grants: `Grant`, `GrantRequest` and `GrantError`, and `Grant::check`, the
  check a provider runs offline: the issuer's Ed25519 signature over the
  signed layout `kuri-api.Grant/v1`, the node, kind and instance it names, and
  its deadline on the home's clock.
- The vocabulary they share: `NodeId`, `CapabilityKind`, `Scope`.
- CBOR maps with named keys for every type; unknown keys are ignored, and an
  unknown enum member reads as `Unknown`.
- Test vectors for the grant check, `tests/vectors/grants.json`.
