# Bitcoin Bech32
[![Docs.rs badge](https://docs.rs/bitcoin-bech32/badge.svg)](https://docs.rs/bitcoin-bech32/)
[![Continuous Integration](https://github.com/rust-bitcoin/rust-bech32-bitcoin/workflows/Continuous%20Integration/badge.svg)](https://github.com/rust-bitcoin/rust-bech32-bitcoin/actions?query=workflow%3A%22Continuous+Integration%22)

Encodes and decodes Bitcoin Segregated Witness addresses in the Bech32 format described in [BIP-0173](https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki) and Bech32m format described in [BIP-0350](https://github.com/bitcoin/bips/blob/master/bip-0350.mediawiki).

## Example

```rust
use bitcoin_bech32::{WitnessProgram, u5};
use bitcoin_bech32::constants::Network;

let witness_program = WitnessProgram::new(
    u5::try_from_u8(0).unwrap(),
    vec![
        0x00, 0x00, 0x00, 0xc4, 0xa5, 0xca, 0xd4, 0x62,
        0x21, 0xb2, 0xa1, 0x87, 0x90, 0x5e, 0x52, 0x66,
        0x36, 0x2b, 0x99, 0xd5, 0xe9, 0x1c, 0x6c, 0xe2,
        0x4d, 0x16, 0x5d, 0xab, 0x93, 0xe8, 0x64, 0x33],
    Network::Testnet,
).unwrap();

let address = witness_program.to_address();
assert_eq!(address,
           "tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy".to_string());

let decoded = WitnessProgram::from_address(&address).unwrap();
assert_eq!(decoded, witness_program);
```
