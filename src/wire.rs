//! The encoding every contract shares: CBOR maps with named keys.

use serde::de::DeserializeOwned;
use serde::Serialize;

/// A value could not be encoded.
#[derive(Debug, thiserror::Error)]
#[error("could not encode: {0}")]
pub struct EncodeError(String);

/// Bytes are not the CBOR of the type asked for.
#[derive(Debug, thiserror::Error)]
#[error("could not decode: {0}")]
pub struct DecodeError(String);

/// Encodes `value` as CBOR.
pub fn to_cbor<T: Serialize>(value: &T) -> Result<Vec<u8>, EncodeError> {
    let mut out = Vec::new();
    ciborium::into_writer(value, &mut out).map_err(|e| EncodeError(e.to_string()))?;
    Ok(out)
}

/// Decodes `bytes` as CBOR of a `T`. Keys `T` does not know are ignored.
///
/// `bytes` must hold the one value and nothing after it: a writer never
/// sends more, and bytes left over would hide a framing error, such as two
/// messages run together. It sets no limit on the size of `bytes`; a reader
/// bounds that before it decodes.
pub fn from_cbor<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, DecodeError> {
    let mut rest = bytes;
    let value = ciborium::from_reader(&mut rest).map_err(|e| DecodeError(e.to_string()))?;
    if !rest.is_empty() {
        return Err(DecodeError(format!("{} bytes after the value", rest.len())));
    }
    Ok(value)
}

/// Declares a flexible enum: each member has its name on the wire and its
/// number in the contract's definition, and any other name reads as
/// `Unknown`.
///
/// The number is what signed layouts carry, so it never changes for a member;
/// `Unknown` has none, and a signed value holding it cannot be verified.
macro_rules! flexible_enum {
    (
        $(#[$meta:meta])*
        pub enum $name:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident = $number:literal, $wire:literal;
            )*
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )*
            /// A member this version of the contract does not know.
            Unknown,
        }

        impl $name {
            /// Every member this version knows, in the definition's order.
            pub const ALL: &'static [Self] = &[$(Self::$variant,)*];

            /// The member's number in the contract's definition, or `None`
            /// for [`Self::Unknown`].
            pub fn number(self) -> Option<u32> {
                match self {
                    $(Self::$variant => Some($number),)*
                    Self::Unknown => None,
                }
            }

            /// The member with this number, or [`Self::Unknown`].
            pub fn from_number(number: u32) -> Self {
                match number {
                    $($number => Self::$variant,)*
                    _ => Self::Unknown,
                }
            }

            /// The member's name on the wire.
            pub fn name(self) -> &'static str {
                match self {
                    $(Self::$variant => $wire,)*
                    Self::Unknown => "unknown",
                }
            }

            /// The member with this name on the wire, or [`Self::Unknown`].
            pub fn from_name(name: &str) -> Self {
                match name {
                    $($wire => Self::$variant,)*
                    _ => Self::Unknown,
                }
            }
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(self.name())
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let name = String::deserialize(deserializer)?;
                Ok(Self::from_name(&name))
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    struct Pair {
        a: u8,
        b: String,
    }

    #[test]
    fn a_value_with_nothing_after_it_decodes() {
        let pair = Pair {
            a: 1,
            b: "two".into(),
        };
        assert_eq!(from_cbor::<Pair>(&to_cbor(&pair).unwrap()).unwrap(), pair);
    }

    #[test]
    fn bytes_after_the_value_are_refused() {
        let pair = Pair {
            a: 1,
            b: "two".into(),
        };
        let mut bytes = to_cbor(&pair).unwrap();
        bytes.extend_from_slice(&[0xff, 0xff, 0x00]);
        let error = from_cbor::<Pair>(&bytes).unwrap_err();
        assert!(
            error.to_string().contains("3 bytes after the value"),
            "{error}"
        );
    }

    #[test]
    fn two_values_run_together_are_refused() {
        let pair = Pair {
            a: 1,
            b: "two".into(),
        };
        let mut bytes = to_cbor(&pair).unwrap();
        bytes.extend(to_cbor(&pair).unwrap());
        assert!(from_cbor::<Pair>(&bytes).is_err());
    }
}
