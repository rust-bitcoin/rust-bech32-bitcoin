// Copyright (c) 2017 Clark Moody
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

//! Encoding and decoding Bech32 Bitcoin Segwit Addresses
//!
//! Encoding and decoding for Bitcoin Segregated Witness addresses. Bech32 is an
//! encoding scheme described in [BIP-0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki),
//! and segregated witness addresses encoded by Bech32 simply combine a coin-specific
//! human-readable part with the data of the witness program as the Bech32 data
//! payload.
//!
//! # Examples
//!
//! ```rust
//! use bitcoin_bech32::{WitnessProgram, u5};
//! use bitcoin_bech32::constants::Network;
//!
//! let witness_program = WitnessProgram::new(
//!     u5::try_from_u8(0).unwrap(),
//!     vec![
//!         0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62,
//!         0x21, 0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66,
//!         0x36, 0x2b, 0x99, 0xd5, 0xe9, 0x1c, 0x6c, 0xe2,
//!         0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64, 0x33],
//!     Network::Testnet
//! ).unwrap();
//!
//! let address = witness_program.to_address();
//! assert_eq!(address,
//!     "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy".to_string());
//!
//! let decoded = WitnessProgram::from_address(&address).unwrap();
//! assert_eq!(decoded, witness_program);
//! ```

// Allow trait objects without dyn on nightly and make 1.22 ignore the unknown lint
#![allow(unknown_lints)]
#![allow(bare_trait_objects)]
#![deny(missing_docs)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![cfg_attr(feature = "strict", deny(warnings))]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
extern crate bech32;
pub use bech32::u5;
use bech32::{decode, encode, FromBase32, ToBase32, Variant};

use alloc::vec;
use alloc::vec::Vec;
use alloc::str::FromStr;
use alloc::string::{String, ToString};
#[cfg(feature = "std")]
use std::{error, fmt};
#[cfg(not(feature = "std"))]
use core::fmt;

pub mod constants;
use constants::Network;

/// Witness version and program data
#[derive(PartialEq, Eq, Debug, Clone, PartialOrd, Ord, Hash)]
pub struct WitnessProgram {
    /// Witness program version
    version: u5,
    /// Witness program content
    program: Vec<u8>,
    /// Cryptocurrency network
    network: Network,
    /// Cached bech32 representation of the witness program
    bech32: String,
}

impl WitnessProgram {
    /// Construct a new WitnessProgram given the constituent version, witness program and network version
    pub fn new(version: u5, program: Vec<u8>, network: Network) -> Result<WitnessProgram, Error> {
        // Compute bech32
        let hrp = constants::hrp(&network);
        let mut b32_data: Vec<u5> = vec![version];
        let p5 = program.to_base32();
        b32_data.extend_from_slice(&p5);
        let variant = program_version_to_variant(version).ok_or(Error::InvalidScriptVersion)?;
        let bech32 = encode(&hrp, b32_data, variant)?;

        // Create return object
        let ret = WitnessProgram {
            version,
            program,
            network,
            bech32,
        };

        // Verify that the program is valid
        ret.validate()?;
        Ok(ret)
    }

    /// Converts a Witness Program to a SegWit Address
    pub fn to_address(&self) -> String {
        self.to_string()
    }

    /// Decodes a segwit address into a Witness Program
    ///
    /// Verifies that the `address` contains a known human-readable part
    /// `hrp` and decodes as proper Bech32-encoded string. Allowed values of
    /// the human-readable part correspond to the defined types in `constants`
    pub fn from_address(address: &str) -> Result<WitnessProgram, Error> {
        WitnessProgram::from_str(address)
    }

    /// Converts a `WitnessProgram` to a script public key
    ///
    /// The format for the output is
    /// `[version, program length, <program>]`
    pub fn to_scriptpubkey(&self) -> Vec<u8> {
        let mut pubkey: Vec<u8> = Vec::new();
        let mut v: u8 = self.version.into();
        if v > 0 {
            v += 0x50;
        }
        pubkey.push(v);
        pubkey.push(self.program.len() as u8);
        pubkey.extend_from_slice(&self.program);
        pubkey
    }

    /// Extracts a WitnessProgram out of a provided script public key
    pub fn from_scriptpubkey(pubkey: &[u8], network: Network) -> Result<WitnessProgram, Error> {
        // We need a version byte and a program length byte, with a program at
        // least 2 bytes long.
        if pubkey.len() < 4 {
            return Err(Error::ScriptPubkeyTooShort);
        }
        let proglen: usize = pubkey[1] as usize;
        // Check that program length byte is consistent with pubkey length
        if pubkey.len() != 2 + proglen {
            return Err(Error::ScriptPubkeyInvalidLength);
        }
        // Process script version
        let mut v: u8 = pubkey[0];
        if v > 0x50 {
            v -= 0x50;
        }

        let v = u5::try_from_u8(v).expect("range is already guaranteed by code above");
        let program = &pubkey[2..];

        WitnessProgram::new(v, program.to_vec(), network)
    }

    /// Validates the WitnessProgram against version and length constraints
    pub fn validate(&self) -> Result<(), Error> {
        if self.version.to_u8() > 16 {
            // Invalid script version
            return Err(Error::InvalidScriptVersion);
        }
        if self.program.len() < 2 || self.program.len() > 40 {
            return Err(Error::InvalidLength);
        }
        // Check proper script length
        if self.version.to_u8() == 0 && self.program.len() != 20 && self.program.len() != 32 {
            return Err(Error::InvalidVersionLength);
        }
        Ok(())
    }

    /// Witness program version
    pub fn version(&self) -> u5 {
        self.version
    }

    /// Witness program serialized as 8-bit bytes
    pub fn program(&self) -> &[u8] {
        &self.program
    }

    /// Which network this witness program is intended to be run on
    pub fn network(&self) -> Network {
        self.network
    }
}

impl ToString for WitnessProgram {
    fn to_string(&self) -> String {
        self.bech32.to_string()
    }
}

impl FromStr for WitnessProgram {
    type Err = Error;

    fn from_str(s: &str) -> Result<WitnessProgram, Error> {
        let (hrp, data, variant) = decode(s)?;
        let network_classified = match constants::classify(&hrp) {
            Some(nc) => nc,
            None => return Err(Error::InvalidHumanReadablePart),
        };
        if data.is_empty() || data.len() > 65 {
            return Err(Error::Bech32(bech32::Error::InvalidLength));
        }
        // Get the script version and program (converted from 5-bit to 8-bit)
        let (version, program) = {
            let (v, p5) = data.split_at(1);
            let program = Vec::from_base32(p5)?;
            (v[0], program)
        };
        let wp = WitnessProgram {
            version,
            program,
            network: network_classified,
            bech32: s.to_string(),
        };
        wp.validate()?;
        if let Some(version_variant) = program_version_to_variant(version) {
            if version_variant != variant {
                return Err(Error::InvalidEncoding);
            }
        }
        Ok(wp)
    }
}

fn program_version_to_variant(version: u5) -> Option<Variant> {
    match version.to_u8() {
        0 => Some(Variant::Bech32),
        1 | 2 | 3 | 4 | 5 | 6 | 7 | 8 | 9 | 10 | 11 | 12 | 13 | 14 | 15 | 16 => {
            Some(Variant::Bech32m)
        }
        _ => None,
    }
}

/// Error types for witness programs
///
/// BIP141 specifies Segregated Witness and defines valid program lengths
/// for Version 0 scripts. Script version is also limited to values 0-16.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Error {
    /// Some Bech32 conversion error
    Bech32(bech32::Error),
    /// The human-readable part is invalid (must be "bc" or "tb")
    InvalidHumanReadablePart,
    /// scriptpubkeys does not have enough data
    ScriptPubkeyTooShort,
    /// The provided length byte does not match the data
    ScriptPubkeyInvalidLength,
    /// Denotes that the WitnessProgram is too long or too short
    ///
    /// Programs must be between 2 and 40 bytes
    InvalidLength,
    /// Given the program version, the length is invalid
    ///
    /// Version 0 scripts must be either 20 or 32 bytes
    InvalidVersionLength,
    /// Script version must be 0 to 16 inclusive
    InvalidScriptVersion,
    /// Improper encoding used for address
    ///
    /// Witness version 0 addresses must use Bech32 encoding, and all other
    /// versions must use Bech32m
    InvalidEncoding,
}

impl From<bech32::Error> for Error {
    fn from(e: bech32::Error) -> Error {
        Error::Bech32(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Bech32(ref e) => write!(f, "{}", e),
            Error::InvalidHumanReadablePart => write!(f, "invalid human-readable part"),
            Error::ScriptPubkeyTooShort => write!(f, "scriptpubkey too short"),
            Error::ScriptPubkeyInvalidLength => write!(f, "scriptpubkey length mismatch"),
            Error::InvalidLength => write!(f, "invalid length"),
            Error::InvalidVersionLength => write!(f, "program length incompatible with version"),
            Error::InvalidScriptVersion => write!(f, "invalid script version"),
            Error::InvalidEncoding => write!(f, "invalid Bech32 encoding"),
        }
    }
}

#[cfg(feature = "std")]
impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Bech32(_) => "Bech32 error",
            Error::InvalidHumanReadablePart => "invalid human-readable part",
            Error::ScriptPubkeyTooShort => "scriptpubkey too short",
            Error::ScriptPubkeyInvalidLength => "scriptpubkey length mismatch",
            Error::InvalidLength => "invalid length",
            Error::InvalidVersionLength => "program length incompatible with version",
            Error::InvalidScriptVersion => "invalid script version",
            Error::InvalidEncoding => "invalid Bech32 encoding",
        }
    }

    fn cause(&self) -> Option<&std::error::Error> {
        match *self {
            Error::Bech32(ref e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use bech32;
    use constants::Network;
    use *;

    #[test]
    fn valid_address() {
        let pairs: Vec<(&str, Vec<u8>, Network)> = vec![
            (
                "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
                vec![
                    0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c,
                    0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
                ],
                Network::Bitcoin,
            ),
            (
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
                vec![
                    0x00, 0x20, 0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04, 0xbd, 0x19,
                    0x20, 0x33, 0x56, 0xda, 0x13, 0x6c, 0x98, 0x56, 0x78, 0xcd, 0x4d, 0x27, 0xa1,
                    0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32, 0x62,
                ],
                Network::Testnet,
            ),
            (
                "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y",
                vec![
                    0x51, 0x28, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c,
                    0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6, 0x75, 0x1e, 0x76, 0xe8,
                    0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1,
                    0x43, 0x3b, 0xd6,
                ],
                Network::Bitcoin,
            ),
            (
                "BC1SW50QGDZ25J",
                vec![0x60, 0x02, 0x75, 0x1e],
                Network::Bitcoin,
            ),
            (
                "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs",
                vec![
                    0x52, 0x10, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c,
                    0x45, 0xd1, 0xb3, 0xa3, 0x23,
                ],
                Network::Bitcoin,
            ),
            (
                "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
                vec![
                    0x00, 0x20, 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21, 0xb2, 0xa1,
                    0x87, 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5, 0xe9, 0x1c, 0x6c, 0xe2,
                    0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64, 0x33,
                ],
                Network::Testnet,
            ),
            (
                "bcrt1qn3h68k2u0rr49skx05qw7veynpf4lfppd2demt",
                vec![
                    0x00, 0x14, 0x9c, 0x6f, 0xa3, 0xd9, 0x5c, 0x78, 0xc7, 0x52, 0xc2, 0xc6, 0x7d,
                    0x00, 0xef, 0x33, 0x24, 0x98, 0x53, 0x5f, 0xa4, 0x21,
                ],
                Network::Regtest,
            ),
            (
                "tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c",
                vec![
                    0x51, 0x20, 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21, 0xb2, 0xa1,
                    0x87, 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5, 0xe9, 0x1c, 0x6c, 0xe2,
                    0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64, 0x33,
                ],
                Network::Testnet,
            ),
            (
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0",
                vec![
                    0x51, 0x20, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62,
                    0x95, 0xce, 0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9,
                    0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98,
                ],
                Network::Bitcoin,
            ),
        ];
        for p in pairs {
            let (address, scriptpubkey, network) = p;
            let version = if scriptpubkey[0] == 0 {
                0
            } else {
                scriptpubkey[0] - 0x50
            };
            let prog = match WitnessProgram::from_address(&address) {
                Ok(prog) => prog,
                Err(e) => panic!("{}, {:?}", address, e),
            };

            let pubkey = prog.to_scriptpubkey();
            assert_eq!(pubkey, scriptpubkey);

            assert_eq!(prog.network(), network);
            assert_eq!(prog.version().to_u8(), version);
            assert_eq!(prog.program(), &scriptpubkey[2..]); // skip version and length

            match WitnessProgram::from_scriptpubkey(&scriptpubkey, prog.network) {
                Ok(prog) => {
                    assert_eq!(
                        prog.to_string().to_lowercase(),
                        prog.to_string().to_lowercase()
                    );
                    let enc_address = prog.to_address();
                    assert_eq!(address.to_lowercase(), enc_address.to_lowercase());
                }
                Err(e) => panic!("{:?}, {:?}", scriptpubkey, e),
            }
        }
    }

    #[test]
    fn invalid_address() {
        let pairs: Vec<(&str, Error)> = vec![
            // BIP-0173 Invalid Addresses
            (
                "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
                Error::InvalidHumanReadablePart,
            ),
            (
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
                Error::Bech32(bech32::Error::InvalidChecksum),
            ),
            (
                "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
                Error::InvalidScriptVersion,
            ),
            ("bc1rw5uspcuh", Error::InvalidLength),
            (
                "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
                Error::Bech32(bech32::Error::InvalidLength),
            ),
            (
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
                Error::Bech32(bech32::Error::MixedCase),
            ),
            (
                "tb1pw508d6qejxtdg4y5r3zarqfsj6c3",
                Error::Bech32(bech32::Error::InvalidPadding),
            ),
            (
                "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
                Error::Bech32(bech32::Error::InvalidPadding),
            ),
            (
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
                Error::Bech32(bech32::Error::InvalidPadding),
            ),
            // BIP-0350 Invalid Addresses
            (
                "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
                Error::InvalidHumanReadablePart,
            ),
            (
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
                Error::InvalidEncoding,
            ),
            (
                "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
                Error::InvalidEncoding,
            ),
            (
                "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
                Error::InvalidEncoding,
            ),
            (
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
                Error::InvalidEncoding,
            ),
            (
                "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
                Error::InvalidEncoding,
            ),
            (
                "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
                Error::Bech32(bech32::Error::InvalidChar('o')),
            ),
            (
                "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
                Error::InvalidScriptVersion,
            ),
            ("bc1pw5dgrnzv", Error::InvalidLength),
            (
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
                Error::Bech32(bech32::Error::InvalidLength),
            ),
            (
                "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
                Error::InvalidVersionLength,
            ),
            (
                "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
                Error::Bech32(bech32::Error::MixedCase),
            ),
            (
                "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
                Error::Bech32(bech32::Error::InvalidPadding),
            ),
            (
                "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
                Error::Bech32(bech32::Error::InvalidPadding),
            ),
            ("bc1gmk9yu", Error::Bech32(bech32::Error::InvalidLength)),
        ];
        for p in pairs {
            let (address, desired_error) = p;
            match WitnessProgram::from_address(&address) {
                Ok(_) => panic!("Should be invalid: {:?}", address),
                Err(e) => assert_eq!(e, desired_error, "{}", address),
            }
        }
    }
}
