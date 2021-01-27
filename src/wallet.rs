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

use curv::arithmetic::traits::Converter;
use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
use curv::cryptographic_primitives::hashing::traits::*;
use curv::elliptic::curves::traits::*;
use curv::BigInt;

pub struct SecretShare<P: ECPoint> {
    pub secret: P::Scalar,
    pub pubkey: P,
}

impl<P> SecretShare<P>
where
    P: ECPoint,
    P::Scalar: Clone,
{
    pub fn generate() -> SecretShare<P> {
        let base_point: P = ECPoint::generator();
        let secret: P::Scalar = ECScalar::new_random();

        let pubkey = base_point * secret.clone();
        return SecretShare { secret, pubkey };
    }
    //based on VRF construction from ellitpic curve: https://eprint.iacr.org/2017/099.pdf
    //TODO: consider to output in str format
    pub fn generate_randomness(&self, label: &BigInt) -> BigInt {
        let h: P = derive_point(&Converter::to_vec(label));
        let gamma = h * self.secret.clone();
        let beta = HSha256::create_hash_from_ge::<P>(&[&gamma]);
        beta.to_big_int()
    }
}

// TODO: Copy-paste from https://github.com/survived/bulletproofs/blob/1e856b17aefd37e2085144097df69c26832bb2b6/src/proofs/utils.rs#L6
pub fn derive_point<P: ECPoint>(source: &[u8]) -> P {
    let bn = BigInt::from(source);
    let scalar = <P::Scalar as ECScalar>::from(&bn);
    P::generator() * scalar
}

#[cfg(test)]
mod tests {
    use curv::elliptic::curves::traits::*;
    use curv::{test_for_all_curves, BigInt};

    use super::SecretShare;

    test_for_all_curves!(test_randomness);
    fn test_randomness<P>()
    where
        P: ECPoint,
        P::Scalar: Clone,
    {
        let x = SecretShare::<P>::generate();
        let bitcoin_label = String::from("Bitcoin1").into_bytes();
        let ethereum_label = String::from("Ethereum1").into_bytes();
        let label_btc = BigInt::from(&bitcoin_label[..]);
        let label_eth = BigInt::from(&ethereum_label[..]);
        let randmoness_btc = x.generate_randomness(&label_btc);
        let randmoness_eth = x.generate_randomness(&label_eth);
        assert_ne!(randmoness_btc, randmoness_eth)
    }
}
