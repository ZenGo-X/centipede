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
use curv::BigInt;

use curv::cryptographic_primitives::hashing::{Digest, DigestExt};
use curv::elliptic::curves::{secp256_k1::Secp256k1, Curve, ECPoint, Point, Scalar};
use generic_array::{typenum::Unsigned, GenericArray};
use sha2::Sha256;

pub struct SecretShare {
    pub secret: Scalar<Secp256k1>,
    pub pubkey: Point<Secp256k1>,
}

impl SecretShare {
    pub fn generate() -> SecretShare {
        let base_point = Point::<Secp256k1>::generator();
        let secret: Scalar<Secp256k1> = Scalar::<Secp256k1>::random();

        let pubkey = base_point * &secret;
        return SecretShare { secret, pubkey };
    }
    //based on VRF construction from ellitpic curve: https://eprint.iacr.org/2017/099.pdf
    //TODO: consider to output in str format
    pub fn generate_randomness(&self, label: &BigInt) -> BigInt {
        let h = generate_random_point(&Converter::to_bytes(label));
        let gamma = h * &self.secret;
        let beta: Scalar<Secp256k1> = Sha256::new().chain_points([&gamma]).result_scalar();
        beta.to_bigint()
    }
}

pub fn generate_random_point(bytes: &[u8]) -> Point<Secp256k1> {
    let compressed_point_len =
        <<Secp256k1 as Curve>::Point as ECPoint>::CompressedPointLength::USIZE;
    let truncated = if bytes.len() > compressed_point_len - 1 {
        &bytes[0..compressed_point_len - 1]
    } else {
        &bytes
    };
    let mut buffer = GenericArray::<
        u8,
        <<Secp256k1 as Curve>::Point as ECPoint>::CompressedPointLength,
    >::default();
    buffer.as_mut_slice()[0] = 0x2;
    buffer.as_mut_slice()[1..1 + truncated.len()].copy_from_slice(truncated);
    if let Ok(point) = Point::from_bytes(buffer.as_slice()) {
        return point;
    }

    let bn = BigInt::from_bytes(bytes);
    let two = BigInt::from(2);
    let bn_times_two = BigInt::mod_mul(&bn, &two, Scalar::<Secp256k1>::group_order());
    let bytes = BigInt::to_bytes(&bn_times_two);
    generate_random_point(&bytes)
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
