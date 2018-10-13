
/*

    Copyright 2018 by Kzen Networks

    This file is part of escrow-recovery library
    (https://github.com/KZen-networks/cryptography-utils)

    Cryptography utilities is free software: you can redistribute
    it and/or modify it under the terms of the GNU General Public
    License as published by the Free Software Foundation, either
    version 3 of the License, or (at your option) any later version.

    @license GPL-3.0+ <https://github.com/KZen-networks/cryptography-utils/blob/master/LICENSE>
*/


use cryptography_utils::{FE,GE,BigInt};
use cryptography_utils::elliptic::curves::traits::*;


pub struct SecretShare{
    pub secret: FE,
    pub pubkey: GE,
}

impl SecretShare{

    pub fn generate() -> SecretShare{
        let base_point: GE = ECPoint::generator();
        let secret: FE = ECScalar::new_random();
        let temp :FE= ECScalar::from(&BigInt::from(128));
        let pubkey = base_point * &secret;
        SecretShare{
            secret,
            pubkey,
        }

    }
}