//! The home's clock: one clock every node checks grants and requests
//! against, read from the issuer.
//!
//! A board without a real-time clock has no UTC at boot, and two nodes'
//! clocks that disagree turn into requests refused at random. So the home
//! has one clock, the issuer's, and every node reads it, a node with UTC of
//! its own included, so that all checks agree.
//!
//! A node asks the issuer `Now` with 16 fresh random bytes, and the issuer
//! answers with its UTC and a signature, by the key that signs grants, over:
//!
//! ```text
//! "kuri-api.Time/v1\0" || nonce || i64le(utc_ns)
//! ```
//!
//! The node takes `utc_ns` plus half the round trip as the time at the
//! answer, and keeps it as an offset from its own monotonic clock, leaving
//! its system clock alone ([`HomeClock::from_answer`]). An answer that took
//! longer than [`MAX_ROUND_TRIP_NS`] is discarded. A node asks at start and
//! then every [`READ_EVERY_NS`].
//!
//! The key is the grant key because every provider already trusts it:
//! whoever could forge the time could forge a grant. The nonce is what keeps
//! a recorded answer from being replayed to set a node's clock back.
//!
//! Where a node's monotonic clock stops while it sleeps, the offset falls
//! behind by the time asleep, so such a node reads the clock again on
//! waking.

use ed25519_dalek::Signature;
use serde::{Deserialize, Serialize};

use crate::grant::IssuerKey;

/// Prefixes the bytes the issuer signs for a reading of its clock.
pub const TIME_CONTEXT: &[u8] = b"kuri-api.Time/v1\0";

/// The length of the nonce a node sends with `Now`.
pub const TIME_NONCE_LEN: usize = 16;

/// The longest round trip an answer may take and still be used: one second.
pub const MAX_ROUND_TRIP_NS: i64 = 1_000_000_000;

/// How often a node reads the clock again: every 10 minutes.
pub const READ_EVERY_NS: i64 = 600_000_000_000;

/// The issuer's answer to `Now`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeAnswer {
    /// The issuer's UTC when it answered, in nanoseconds.
    pub utc_ns: i64,
    /// The issuer's signature over [`TimeAnswer::signed_bytes`].
    #[serde(with = "serde_bytes")]
    pub signature: [u8; 64],
}

impl TimeAnswer {
    /// The bytes the issuer signs, for the nonce the node sent.
    pub fn signed_bytes(nonce: &[u8; TIME_NONCE_LEN], utc_ns: i64) -> Vec<u8> {
        let mut out = TIME_CONTEXT.to_vec();
        out.extend_from_slice(nonce);
        out.extend_from_slice(&utc_ns.to_le_bytes());
        out
    }
}

/// Why an answer to `Now` is not used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClockError {
    /// The answer is not signed by the issuer for this nonce: forged, or
    /// recorded for another question.
    #[error("the time is not signed by the issuer for this question")]
    BadSignature,
    /// The answer took longer than [`MAX_ROUND_TRIP_NS`].
    #[error("the answer took too long to be trusted")]
    TooSlow,
    /// The answer came back before the question went out, on the node's own
    /// monotonic clock: the caller passed its times the wrong way round.
    #[error("the answer arrived before the question was sent")]
    BeforeAsked,
}

/// The home's clock as one node keeps it: an offset from its own monotonic
/// clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HomeClock {
    offset_ns: i64,
    read_at_ns: i64,
}

impl HomeClock {
    /// The clock from the issuer's `answer` to the question that carried
    /// `nonce`, sent at `sent_ns` and answered at `received_ns` on this node's
    /// monotonic clock.
    pub fn from_answer(
        issuer: &IssuerKey,
        nonce: &[u8; TIME_NONCE_LEN],
        answer: &TimeAnswer,
        sent_ns: i64,
        received_ns: i64,
    ) -> Result<Self, ClockError> {
        let round_trip = received_ns
            .checked_sub(sent_ns)
            .filter(|ns| *ns >= 0)
            .ok_or(ClockError::BeforeAsked)?;
        if round_trip > MAX_ROUND_TRIP_NS {
            return Err(ClockError::TooSlow);
        }
        issuer
            .verify(
                &TimeAnswer::signed_bytes(nonce, answer.utc_ns),
                &Signature::from_bytes(&answer.signature),
            )
            .map_err(|_| ClockError::BadSignature)?;
        let home_at_answer = answer.utc_ns.saturating_add(round_trip / 2);
        Ok(HomeClock {
            offset_ns: home_at_answer.saturating_sub(received_ns),
            read_at_ns: received_ns,
        })
    }

    /// The home's time when this node's monotonic clock reads `monotonic_ns`.
    pub fn now(&self, monotonic_ns: i64) -> i64 {
        monotonic_ns.saturating_add(self.offset_ns)
    }

    /// Whether it is time to read the clock again, at `monotonic_ns`.
    pub fn due(&self, monotonic_ns: i64) -> bool {
        monotonic_ns.saturating_sub(self.read_at_ns) >= READ_EVERY_NS
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};

    use super::*;
    use crate::{from_cbor, to_cbor};

    const UTC: i64 = 1_800_000_000_000_000_000;
    const MS: i64 = 1_000_000;

    fn issuer() -> SigningKey {
        SigningKey::from_bytes(&[7; 32])
    }

    fn key() -> IssuerKey {
        IssuerKey::from_bytes(&issuer().verifying_key().to_bytes()).unwrap()
    }

    fn answer(nonce: &[u8; 16], utc_ns: i64) -> TimeAnswer {
        TimeAnswer {
            utc_ns,
            signature: issuer()
                .sign(&TimeAnswer::signed_bytes(nonce, utc_ns))
                .to_bytes(),
        }
    }

    #[test]
    fn the_time_at_the_answer_is_the_issuers_plus_half_the_round_trip() {
        let nonce = [1; 16];
        // Asked at 5 s on this node's monotonic clock, answered 40 ms later.
        let sent = 5_000 * MS;
        let clock =
            HomeClock::from_answer(&key(), &nonce, &answer(&nonce, UTC), sent, sent + 40 * MS)
                .unwrap();
        assert_eq!(clock.now(sent + 40 * MS), UTC + 20 * MS);
        assert_eq!(clock.now(sent + 1_040 * MS), UTC + 1_020 * MS);
    }

    #[test]
    fn an_answer_for_another_nonce_is_not_used() {
        let recorded = answer(&[1; 16], UTC);
        assert_eq!(
            HomeClock::from_answer(&key(), &[2; 16], &recorded, 0, MS),
            Err(ClockError::BadSignature)
        );
    }

    #[test]
    fn an_answer_with_another_time_is_not_used() {
        let nonce = [1; 16];
        let mut moved = answer(&nonce, UTC);
        moved.utc_ns -= 1;
        assert_eq!(
            HomeClock::from_answer(&key(), &nonce, &moved, 0, MS),
            Err(ClockError::BadSignature)
        );
    }

    #[test]
    fn an_answer_signed_by_another_key_is_not_used() {
        let nonce = [1; 16];
        let forged = TimeAnswer {
            utc_ns: UTC,
            signature: SigningKey::from_bytes(&[8; 32])
                .sign(&TimeAnswer::signed_bytes(&nonce, UTC))
                .to_bytes(),
        };
        assert_eq!(
            HomeClock::from_answer(&key(), &nonce, &forged, 0, MS),
            Err(ClockError::BadSignature)
        );
    }

    #[test]
    fn a_slow_answer_is_discarded() {
        let nonce = [1; 16];
        let answer = answer(&nonce, UTC);
        assert!(HomeClock::from_answer(&key(), &nonce, &answer, 0, MAX_ROUND_TRIP_NS).is_ok());
        assert_eq!(
            HomeClock::from_answer(&key(), &nonce, &answer, 0, MAX_ROUND_TRIP_NS + 1),
            Err(ClockError::TooSlow)
        );
        assert_eq!(
            HomeClock::from_answer(&key(), &nonce, &answer, MS, 0),
            Err(ClockError::BeforeAsked)
        );
    }

    #[test]
    fn the_clock_is_read_again_every_ten_minutes() {
        let nonce = [1; 16];
        let clock = HomeClock::from_answer(&key(), &nonce, &answer(&nonce, UTC), 0, MS).unwrap();
        assert!(!clock.due(MS + READ_EVERY_NS - 1));
        assert!(clock.due(MS + READ_EVERY_NS));
    }

    #[test]
    fn the_signed_layout_is_the_documented_one() {
        let mut expected = b"kuri-api.Time/v1\0".to_vec();
        expected.extend_from_slice(&[3; 16]);
        expected.extend_from_slice(&UTC.to_le_bytes());
        assert_eq!(TimeAnswer::signed_bytes(&[3; 16], UTC), expected);
    }

    #[test]
    fn an_answer_survives_the_wire() {
        let answer = answer(&[1; 16], UTC);
        assert_eq!(
            from_cbor::<TimeAnswer>(&to_cbor(&answer).unwrap()).unwrap(),
            answer
        );
    }
}
