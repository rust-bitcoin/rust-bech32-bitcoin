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

//! Human-readable constants for various cryptocurrencies
//!
//! The authoratative list of Human-readable parts for Bech32 addresses is
//! maintained in [SLIP-0173](https://github.com/satoshilabs/slips/blob/master/slip-0173.md).

use alloc::string::{String, ToString};

/// The cryptocurrency to act on
#[derive(PartialEq, Eq, Debug, Clone, Copy, PartialOrd, Ord, Hash)]
pub enum Network {
    /// Bitcoin mainnet
    Bitcoin,
    /// Bitcoin testnet
    Testnet,
    /// Bitcoin signet,
    Signet,
    /// Bitcoin regtest,
    Regtest,
    /// Groestlcoin Mainnet
    Groestlcoin,
    /// Groestlcoin Testnet,
    GroestlcoinTestnet,
    /// Litecoin mainnet
    Litecoin,
    /// Litecoin testnet
    LitecoinTestnet,
    /// Vertcoin mainnet
    Vertcoin,
    /// Vertcoin testnet
    VertcoinTestnet,
}

/// Returns the Human-readable part for the given network
pub fn hrp(network: &Network) -> String {
    match *network {
        Network::Bitcoin => "bc".to_string(),
        Network::Testnet => "tb".to_string(),
        Network::Signet => "tb".to_string(),
        Network::Groestlcoin => "grs".to_string(),
        Network::GroestlcoinTestnet => "tgrs".to_string(),
        Network::Litecoin => "ltc".to_string(),
        Network::LitecoinTestnet => "tltc".to_string(),
        Network::Vertcoin => "vtc".to_string(),
        Network::VertcoinTestnet => "tvtc".to_string(),
        Network::Regtest => "bcrt".to_string(),
    }
}

/// Classify a Human-readable part as its cryptocurrency
pub fn classify(hrp: &str) -> Option<Network> {
    match hrp {
        "bc" => Some(Network::Bitcoin),
        "tb" => Some(Network::Testnet),
        "grs" => Some(Network::Groestlcoin),
        "tgrs" => Some(Network::GroestlcoinTestnet),
        "ltc" => Some(Network::Litecoin),
        "tltc" => Some(Network::LitecoinTestnet),
        "vtc" => Some(Network::Vertcoin),
        "tvtc" => Some(Network::VertcoinTestnet),
        "bcrt" => Some(Network::Regtest),
        _ => None,
    }
}
