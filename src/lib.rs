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
//! use bitcoin_bech32::WitnessProgram;
//! use bitcoin_bech32::constants::Network;
//!
//! let witness_program = WitnessProgram {
//!     version: 0,
//!     program: vec![
//!                 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62,
//!                 0x21, 0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66,
//!                 0x36, 0x2b, 0x99, 0xd5, 0xe9, 0x1c, 0x6c, 0xe2,
//!                 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64, 0x33],
//!     network: Network::Testnet
//! };
//!
//! let address = witness_program.to_address().unwrap();
//! assert_eq!(address,
//!     "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy".to_string());
//!
//! let decoded = WitnessProgram::from_address(address).unwrap();
//! assert_eq!(decoded, witness_program);
//! ```

#![deny(missing_docs)]
#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]

extern crate bech32;
use bech32::{Bech32, convert_bits};

use std::{error, fmt};

pub mod constants;
use constants::Network;

/// Witness version and program data
#[derive(PartialEq, Debug, Clone)]
pub struct WitnessProgram {
    /// Witness program version
    pub version: u8,
    /// Witness program content
    pub program: Vec<u8>,
    /// Cryptocurrency network
    pub network: Network,
}

type EncodeResult = Result<String, Error>;
type DecodeResult = Result<WitnessProgram, Error>;
type PubKeyResult = Result<WitnessProgram, ScriptPubKeyError>;
type ValidationResult = Result<(), WitnessProgramError>;

impl WitnessProgram {
    /// Converts a Witness Program to a SegWit Address
    pub fn to_address(&self) -> EncodeResult {
        // Verify that the program is valid
        let val_result = self.validate();
        if val_result.is_err() {
            return Err(Error::WitnessProgram(val_result.unwrap_err()))
        }
        let mut data: Vec<u8> = vec![self.version];
        // Convert 8-bit program into 5-bit
        let p5 = match convert_bits(&self.program, 8, 5, true) {
            Ok(p) => p,
            Err(e) => return Err(Error::Conversion(e))
        };
        let hrp = constants::hrp(&self.network);
        data.extend_from_slice(&p5);
        let b32 = match Bech32::new(hrp.clone(), data) {
            Ok(b) => b,
            Err(e) => return Err(Error::Bech32(e))
        };
        let address = b32.to_string();
        // Ensure that the address decodes into a program properly
        WitnessProgram::from_address(address.clone())?;
        Ok(address)
    }

    /// Decodes a segwit address into a Witness Program
    ///
    /// Verifies that the `address` contains a known human-readable part
    /// `hrp` and decodes as proper Bech32-encoded string. Allowed values of
    /// the human-readable part correspond to the defined types in `constants`
    pub fn from_address(address: String) -> DecodeResult {
        let b32 = match address.parse::<Bech32>() {
            Ok(b) => b,
            Err(e) => return Err(Error::Bech32(e)),
        };
        let network_classified = constants::classify(b32.hrp());
        if network_classified.is_none() {
            return Err(Error::InvalidHumanReadablePart)
        }
        if b32.data().len() == 0 || b32.data().len() > 65 {
            return Err(Error::Bech32(bech32::Error::InvalidLength))
        }
        // Get the script version and 5-bit program
        let (v, p5) = b32.data().split_at(1);
        let wp = WitnessProgram {
            version: v.to_vec()[0],
            // Convert to 8-bit program and assign
            program: match convert_bits(&p5, 5, 8, false) {
                Ok(p) => p,
                Err(e) => return Err(Error::Conversion(e))
            },
            network: network_classified.unwrap()
        };
        match wp.validate() {
            Ok(_) => Ok(wp),
            Err(e) => Err(Error::WitnessProgram(e))
        }
    }

    /// Converts a `WitnessProgram` to a script public key
    ///
    /// The format for the output is
    /// `[version, program length, <program>]`
    pub fn to_scriptpubkey(&self) -> Vec<u8> {
        let mut pubkey: Vec<u8> = Vec::new();
        let mut v = self.version;
        if v > 0 {
            v += 0x50;
        }
        pubkey.push(v);
        pubkey.push(self.program.len() as u8);
        pubkey.extend_from_slice(&self.program);
        pubkey
    }

    /// Extracts a WitnessProgram out of a provided script public key
    pub fn from_scriptpubkey(pubkey: &[u8], network: Network) -> PubKeyResult {
        // We need a version byte and a program length byte, with a program at
        // least 2 bytes long.
        if pubkey.len() < 4 {
            return Err(ScriptPubKeyError::TooShort)
        }
        let proglen: usize = pubkey[1] as usize;
        // Check that program length byte is consistent with pubkey length
        if pubkey.len() != 2 + proglen {
            return Err(ScriptPubKeyError::InvalidLengthByte)
        }
        // Process script version
        let mut v: u8 = pubkey[0];
        if v > 0x50 {
            v -= 0x50;
        }
        let program = &pubkey[2..];
        Ok(WitnessProgram {
            version: v,
            program: program.to_vec(),
            network: network,
        })
    }

    /// Validates the WitnessProgram against version and length constraints
    pub fn validate(&self) -> ValidationResult {
        if self.version > 16 {
            // Invalid script version
            return Err(WitnessProgramError::InvalidScriptVersion)
        }
        if self.program.len() < 2 || self.program.len() > 40 {
            return Err(WitnessProgramError::InvalidLength)
        }
        // Check proper script length
        if self.version == 0 &&
                self.program.len() != 20 && self.program.len() != 32 {
            return Err(WitnessProgramError::InvalidVersionLength)
        }
        Ok(())
    }
}

/// Error types while encoding and decoding SegWit addresses
#[derive(PartialEq, Debug)]
pub enum Error {
    /// Some Bech32 conversion error
    Bech32(bech32::Error),
    /// Some witness program error
    WitnessProgram(WitnessProgramError),
    /// Some 5-bit <-> 8-bit conversion error
    Conversion(bech32::Error),
    /// The human-readable part is invalid (must be "bc" or "tb")
    InvalidHumanReadablePart,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::Bech32(ref e) => write!(f, "{}", e),
            Error::WitnessProgram(ref e) => write!(f, "{}", e),
            Error::Conversion(ref e) => write!(f, "{}", e),
            Error::InvalidHumanReadablePart => write!(f, "invalid human-readable part"),
        }
    }
}

impl error::Error for Error {
    fn description(&self) -> &str {
        match *self {
            Error::Bech32(_) => "Bech32 error",
            Error::WitnessProgram(_) => "witness program error",
            Error::Conversion(_) => "bit conversion error",
            Error::InvalidHumanReadablePart => "invalid human-readable part",
        }
    }

    fn cause(&self) -> Option<&std::error::Error> {
        match *self {
            Error::Bech32(ref e) => Some(e),
            Error::WitnessProgram(ref e) => Some(e),
            Error::Conversion(ref e) => Some(e),
            _ => None,
        }
    }
}

/// Error types for validating scriptpubkeys
#[derive(PartialEq, Debug)]
pub enum ScriptPubKeyError {
    /// scriptpubkeys does not have enough data
    TooShort,
    /// The provided length byte does not match the data
    InvalidLengthByte,
}

/// Error types for witness programs
///
/// BIP141 specifies Segregated Witness and defines valid program lengths
/// for Version 0 scripts. Script version is also limited to values 0-16.
#[derive(PartialEq, Debug)]
pub enum WitnessProgramError {
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
}

impl fmt::Display for WitnessProgramError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            WitnessProgramError::InvalidLength => write!(f, "invalid length"),
            WitnessProgramError::InvalidVersionLength => write!(f, "program length incompatible with version"),
            WitnessProgramError::InvalidScriptVersion => write!(f, "invalid script versio"),
        }
    }
}

impl error::Error for WitnessProgramError {
    fn description(&self) -> &str {
        match *self {
            WitnessProgramError::InvalidLength => "invalid length",
            WitnessProgramError::InvalidVersionLength => "program length incompatible with version",
            WitnessProgramError::InvalidScriptVersion => "invalid script version"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_address() {
        let pairs: Vec<(&str, Vec<u8>)> = vec![
            (
                "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
                vec![
                    0x00, 0x14, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
                    0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
                ]
            ),
            (
                "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7",
                vec![
                    0x00, 0x20, 0x18, 0x63, 0x14, 0x3c, 0x14, 0xc5, 0x16, 0x68, 0x04,
                    0xbd, 0x19, 0x20, 0x33, 0x56, 0xda, 0x13, 0x6c, 0x98, 0x56, 0x78,
                    0xcd, 0x4d, 0x27, 0xa1, 0xb8, 0xc6, 0x32, 0x96, 0x04, 0x90, 0x32,
                    0x62
                ]
            ),
            (
                "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
                vec![
                    0x51, 0x28, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
                    0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6,
                    0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54, 0x94, 0x1c,
                    0x45, 0xd1, 0xb3, 0xa3, 0x23, 0xf1, 0x43, 0x3b, 0xd6
                ]
            ),
            (
                "BC1SW50QA3JX3S",
                vec![
                   0x60, 0x02, 0x75, 0x1e
                ]
            ),
            (
                "bc1zw508d6qejxtdg4y5r3zarvaryvg6kdaj",
                vec![
                    0x52, 0x10, 0x75, 0x1e, 0x76, 0xe8, 0x19, 0x91, 0x96, 0xd4, 0x54,
                    0x94, 0x1c, 0x45, 0xd1, 0xb3, 0xa3, 0x23
                ]
            ),
            (
                "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy",
                vec![
                    0x00, 0x20, 0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62, 0x21,
                    0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66, 0x36, 0x2b, 0x99, 0xd5,
                    0xe9, 0x1c, 0x6c, 0xe2, 0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64,
                    0x33
                ]
            ),
        ];
        for p in pairs {
            let (address, scriptpubkey) = p;
            let dec_result = WitnessProgram::from_address(address.to_string());
            assert!(dec_result.is_ok());

            let prog = dec_result.unwrap();
            let pubkey = prog.clone().to_scriptpubkey();
            assert_eq!(pubkey, scriptpubkey);

            let spk_result = WitnessProgram::from_scriptpubkey(&scriptpubkey, prog.network.clone());
            assert!(spk_result.is_ok());
            assert_eq!(prog, spk_result.unwrap());

            let enc_result = prog.to_address();
            assert!(enc_result.is_ok());

            let enc_address = enc_result.unwrap();
            assert_eq!(address.to_lowercase(), enc_address.to_lowercase());
        }
    }

    #[test]
    fn invalid_address() {
        let pairs: Vec<(&str, Error)> = vec!(
            ("tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
                Error::InvalidHumanReadablePart),
            ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
                Error::Bech32(bech32::Error::InvalidChecksum)),
            ("BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
                Error::WitnessProgram(WitnessProgramError::InvalidScriptVersion)),
            ("bc1rw5uspcuh",
                Error::WitnessProgram(WitnessProgramError::InvalidLength)),
            ("bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
                Error::Bech32(bech32::Error::InvalidLength)),
            ("BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
                Error::WitnessProgram(WitnessProgramError::InvalidVersionLength)),
            ("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
                Error::Bech32(bech32::Error::MixedCase)),
            ("tb1pw508d6qejxtdg4y5r3zarqfsj6c3",
                Error::Conversion(bech32::Error::InvalidPadding)),
            ("bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
                Error::Conversion(bech32::Error::InvalidPadding)),
            ("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
                Error::Conversion(bech32::Error::InvalidPadding)),
            ("bc1gmk9yu",
                Error::Bech32(bech32::Error::InvalidLength)),
        );
        for p in pairs {
            let (address, desired_error) = p;
            let dec_result = WitnessProgram::from_address(address.to_string());
            if dec_result.is_ok() {
                panic!("Should be invalid: {:?}", address);
            }
            assert_eq!(dec_result.unwrap_err(), desired_error);
        }
    }
}
