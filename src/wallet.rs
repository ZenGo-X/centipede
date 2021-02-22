#![allow(non_snake_case)]
/*
centipede

Copyright 2018 by Kzen Networks

This file is part of centipede library
(https://github.com/KZen-networks/centipede)

Escrow-recovery is free software: you can redistribute
it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, either
version 3 of the License, or (at your option) any later version.

@license GPL-3.0+ <https://github.com/KZen-networks/centipede/blob/master/LICENSE>
*/

use curv::arithmetic::traits::*;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::*;
use curv::elliptic::curves::secp256_k1::FE;
use curv::elliptic::curves::secp256_k1::GE;
use curv::elliptic::curves::traits::*;
use curv::BigInt;
pub struct SecretShare {
    pub secret: FE,
    pub pubkey: GE,
}

impl SecretShare {
    pub fn generate() -> SecretShare {
        let base_point: GE = ECPoint::generator();
        let secret: FE = ECScalar::new_random();

        let pubkey = base_point * &secret;
        return SecretShare { secret, pubkey };
    }
    //based on VRF construction from ellitpic curve: https://eprint.iacr.org/2017/099.pdf
    //TODO: consider to output in str format
    pub fn generate_randomness(&self, label: &BigInt) -> BigInt {
        let h = generate_random_point(&Converter::to_bytes(label));
        let gamma = h * &self.secret;
        let beta = HSha256::create_hash_from_ge(&[&gamma]);
        beta.to_big_int()
    }
}

pub fn generate_random_point(bytes: &[u8]) -> GE {
    let result: Result<GE, _> = ECPoint::from_bytes(&bytes);
    if result.is_ok() {
        return result.unwrap();
    } else {
        let two = BigInt::from(2);
        let bn = BigInt::from_bytes(bytes);
        let bn_times_two = BigInt::mod_mul(&bn, &two, &FE::q());
        let bytes = BigInt::to_bytes(&bn_times_two);
        return generate_random_point(&bytes);
    }
}

#[cfg(test)]
mod tests {
    use curv::arithmetic::traits::*;
    use curv::BigInt;
    use wallet::SecretShare;
    #[test]
    fn test_randomness() {
        let x = SecretShare::generate();
        let bitcoin_label = String::from("Bitcoin1").into_bytes();
        let ethereum_label = String::from("Ethereum1").into_bytes();
        let label_btc = BigInt::from_bytes(&bitcoin_label[..]);
        let label_eth = BigInt::from_bytes(&ethereum_label[..]);
        let randmoness_btc = x.generate_randomness(&label_btc);
        let randmoness_eth = x.generate_randomness(&label_eth);
        assert_ne!(randmoness_btc, randmoness_eth)
    }
}
