// Set of libraries for privacy-preserving networking apps
//
// SPDX-License-Identifier: Apache-2.0
//
// Designed and written in 2019-2026 by Dr. Maxim Orlovsky <orlovsky@cyphernet.io>
//
// Copyright 2022-2026 Cyphernet Labs, Institute for Distributed and Cognitive Computing.
// All rights reserved.
//
// Copyright (C) 2021-2025 Dr Maxim Orlovsky.
// All rights under the above copyrights are reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except
// in compliance with the License. You may obtain a copy of the License at
//
//        http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software distributed under the License
// is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied. See the License for the specific language governing permissions and limitations under
// the License.

use std::fmt::{self, Display, Formatter};
use std::str::FromStr;

use base32;

const SUFFIX_I2P: &str = ".i2p";
const SUFFIX_I2P_ALT: &str = ".i2p.alt";

/// Checks if the given string ends with a valid I2P address suffix,
/// and thus could be considered for parsing as an I2P address.
pub fn ends_with_suffix(s: &str) -> bool { s.ends_with(SUFFIX_I2P) || s.ends_with(SUFFIX_I2P_ALT) }

const SUFFIX_B32_I2P: &str = ".b32.i2p";
const SUFFIX_B32_I2P_ALT: &str = ".b32.i2p.alt";

const ALPHABET: base32::Alphabet = base32::Alphabet::RFC4648 { padding: false };

const B32_LEN_BYTES: usize = 32;
const B32_LEN_CHARS: usize = 52;

const EXT_B32_CHECKSUM_BYTES: usize = 3;
const EXT_B32_MIN_LEN_CHARS: usize = 56;

/// An I2P address, with support for [Base32 Names] and the [.i2p.alt Domain].
///
/// The main purpose of this implementation is to reliably detect I2P addresses,
/// and differentiate them from other types of addresses, such as Tor onion
/// addresses or regular domain names. It is not inteded to be fully compliant
/// with I2P. The following limitations are known:
///
///   1. Base64 names are not parsed/validated. In particular, this implementation does not check
///      whether their length is within bounds (between 516 and 616 bytes).
///   2. [Naming Rules] are not checked. In particular, this implementation does not exclude
///      malformed names, such as those containing "..".
///   3. Checksums of [Extended Base32 Names] are not checked.
///
/// If these limitations are addressed in the future, some invalid addresses
/// might not be accepted in future versions.
///
/// [.i2p.alt Domain]: https://i2p.net/docs/overview/naming/#i2palt-domain
/// [Base32 Names]: https://i2p.net/docs/overview/naming/#base32-names
/// [Extended Base32 Names]: https://i2p.net/docs/overview/naming/#extended-base32-names
/// [Naming Rules]: https://i2p.net/docs/overview/naming/#naming-rules
#[derive(Clone, Ord, PartialOrd, Eq, PartialEq, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum I2pAddr {
    Base32 {
        digest: [u8; B32_LEN_BYTES],
        alt: bool,
    },
    ExtendedBase32 {
        checksum: [u8; EXT_B32_CHECKSUM_BYTES],
        payload: Vec<u8>,
        alt: bool,
    },
    Name {
        name: String,
        alt: bool,
    },
}

#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[display(doc_comments)]
#[non_exhaustive]
pub enum I2pAddrParseError {
    /// I2P address {0} does not end with known I2P suffix.
    NoSuffix(String),

    /// I2P address {0} is not valid Base32.
    InvalidBase32(String),

    /// I2P address {0} has an invalid length.
    InvalidLen(String),
}

impl I2pAddr {
    fn try_from_b32(stripped: &str, alt: bool) -> Result<Self, I2pAddrParseError> {
        if stripped.len() == B32_LEN_CHARS {
            let Some(digest) = base32::decode(ALPHABET, stripped) else {
                return Err(I2pAddrParseError::InvalidBase32(stripped.to_owned()));
            };
            if digest.len() != B32_LEN_BYTES {
                return Err(I2pAddrParseError::InvalidLen(stripped.to_owned()));
            }
            match digest.try_into() {
                Ok(digest) => Ok(Self::Base32 { digest, alt }),
                Err(_) => unreachable!("digest length is checked"),
            }
        } else if stripped.len() >= EXT_B32_MIN_LEN_CHARS {
            let Some(decoded) = base32::decode(ALPHABET, stripped) else {
                return Err(I2pAddrParseError::InvalidBase32(stripped.to_owned()));
            };
            let (checksum, payload) = decoded.split_at(EXT_B32_CHECKSUM_BYTES);

            // TODO: Check checksum.

            Ok(Self::ExtendedBase32 {
                checksum: checksum
                    .try_into()
                    .unwrap_or_else(|_| unreachable!("checksum length is guaranteed by split_at")),
                payload: payload.to_vec(),
                alt,
            })
        } else {
            Err(I2pAddrParseError::InvalidLen(stripped.to_owned()))
        }
    }

    fn prefix(&self) -> String {
        match self {
            Self::Base32 { digest, .. } => {
                base32::encode(ALPHABET, digest.as_slice()).to_lowercase()
            }
            Self::ExtendedBase32 {
                checksum, payload, ..
            } => base32::encode(ALPHABET, &[checksum.as_slice(), payload.as_slice()].concat())
                .to_lowercase(),
            Self::Name { name, .. } => name.clone(),
        }
    }

    fn suffix(&self) -> &'static str {
        match self {
            Self::Base32 { alt, .. } | Self::ExtendedBase32 { alt, .. } => {
                if *alt {
                    SUFFIX_B32_I2P_ALT
                } else {
                    SUFFIX_B32_I2P
                }
            }
            Self::Name { alt, .. } => {
                if *alt {
                    SUFFIX_I2P_ALT
                } else {
                    SUFFIX_I2P
                }
            }
        }
    }
}

impl FromStr for I2pAddr {
    type Err = I2pAddrParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if let Some(stripped) = s.strip_suffix(SUFFIX_B32_I2P) {
            Self::try_from_b32(stripped, false)
        } else if let Some(stripped) = s.strip_suffix(SUFFIX_B32_I2P_ALT) {
            Self::try_from_b32(stripped, true)
        } else if let Some(stripped) = s.strip_suffix(SUFFIX_I2P) {
            Ok(Self::Name {
                name: stripped.to_owned(),
                alt: false,
            })
        } else if let Some(stripped) = s.strip_suffix(SUFFIX_I2P_ALT) {
            Ok(Self::Name {
                name: stripped.to_owned(),
                alt: true,
            })
        } else {
            Err(I2pAddrParseError::NoSuffix(s.to_owned()))
        }
    }
}

impl Display for I2pAddr {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.prefix(), self.suffix())
    }
}

impl From<I2pAddr> for String {
    fn from(addr: I2pAddr) -> Self { addr.to_string() }
}

impl TryFrom<String> for I2pAddr {
    type Error = I2pAddrParseError;

    fn try_from(s: String) -> Result<Self, Self::Error> { Self::from_str(&s) }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn roundtrip() {
        for raw in [
            // https://pablo.rauzy.name/outreach/2600/how-to-run-an-i2p-hidden-service.txt
            "khpazz3f747z5zet72s6g3dccw53bfdqyhxt5da4sv7ouve5veuq.b32.i2p",
            // https://i2p.net/docs/overview/naming/
            "udhdrtrcetjm5sxzskjyr5ztpeszydbh4dpl3pl4utgqqw2v4jna.b32.i2p",
            "i2p-projekt.i2p",
            // https://github.com/PurpleI2P/i2pd_docs_en/blob/838f712527ae0c58c03f419c1fa31f16d52152bb/docs/tutorials/Filesharing/qBittorrent.md?plain=1#L20
            "shx5vqsw7usdaunyzr2qmes2fq37oumybpudrd4jjj4e4vk4uusa.b32.i2p",
            // https://www.reddit.com/r/i2p/comments/njm1d6/comment/gzf05kx/
            "lhxgk47niirkle3zb35fyq2iyzgvpmzydjqbirzcjng3lookrmmxalzz.b32.i2p",
        ] {
            assert_eq!(raw, I2pAddr::from_str(raw).unwrap().to_string());

            let raw = raw.to_owned() + ".alt";
            assert_eq!(raw, I2pAddr::from_str(&raw).unwrap().to_string());
        }
    }

    #[test]
    fn invalid() {
        for raw in [
            // No suffix.
            "khpazz3f747z5zet72s6g3dccw53bfdqyhxt5da4sv7ouve5veuq",
            // Invalid length.
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.b32.i2p",
        ] {
            assert!(I2pAddr::from_str(raw).is_err());
        }
    }
}
