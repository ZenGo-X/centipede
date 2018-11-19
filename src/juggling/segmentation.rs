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

use cryptography_utils::elliptic::curves::traits::*;
use cryptography_utils::{BigInt, FE, GE};
use juggling::proof_system::{Helgamal, Helgamalsegmented, Witness};
use std::ops::{Shl, Shr};
use Errors::{self, ErrorDecrypting};

pub struct Msegmentation;

impl Msegmentation {
    pub fn get_segment_k(secret: &FE, segment_size: &usize, k: u8) -> FE {
        let ss_bn = secret.to_big_int();
        let segment_size_u32 = segment_size.clone() as u32;
        let msb = segment_size_u32 * (k + 1) as u32;
        let lsb = segment_size_u32 * k as u32;
        let two_bn = BigInt::from(2);
        let max = BigInt::pow(&two_bn, msb) - BigInt::from(1);
        let min = BigInt::pow(&two_bn, lsb) - BigInt::from(1);
        let mask = max - min;
        let segment_k_bn = mask & ss_bn;
        let segment_k_bn_rotated =
            BigInt::shr(segment_k_bn, (k * segment_size.clone() as u8) as usize);
        // println!("test = {:?}", test.to_str_radix(16));
        if segment_k_bn_rotated == BigInt::zero() {
            ECScalar::zero()
        } else {
            ECScalar::from(&segment_k_bn_rotated)
        }
    }
    //returns r_k,{D_k,E_k}
    pub fn encrypt_segment_k(
        secret: &FE,
        random: &FE,
        segment_size: &usize,
        k: u8,
        pub_ke_y: &GE,
        G: &GE,
    ) -> Helgamal {
        let segment_k = Msegmentation::get_segment_k(secret, segment_size, k);
        let E_k = G * random;
        let r_kY = pub_ke_y * random;
        if segment_k == ECScalar::zero() {
            let D_k = r_kY;
            Helgamal { D: D_k, E: E_k }
        } else {
            let x_kG = G * &segment_k;
            let D_k = r_kY + x_kG;
            Helgamal { D: D_k, E: E_k }
        }
    }

    // TODO: find a way using generics to combine the following two fn's
    pub fn assemble_fe(segments: &Vec<FE>, segment_size: &usize) -> FE {
        let two = BigInt::from(2);
        let mut segments_2n = segments.clone();
        let seg1 = segments_2n.remove(0);
        let seg_sum = segments_2n
            .iter()
            .zip(0..segments_2n.len())
            .fold(seg1, |acc, x| {
                if x.0.clone() == FE::zero() {
                    acc
                } else {
                    let two_to_the_n = two.pow(segment_size.clone() as u32);
                    let two_to_the_n_shifted = two_to_the_n.shl(x.1 * segment_size);
                    let two_to_the_n_shifted_fe: FE = ECScalar::from(&two_to_the_n_shifted);
                    let shifted_segment = x.0.clone() * two_to_the_n_shifted_fe;
                    acc + shifted_segment
                }
            });
        return seg_sum;
    }

    pub fn assemble_ge(segments: &Vec<GE>, segment_size: &usize) -> GE {
        let two = BigInt::from(2);
        let mut segments_2n = segments.clone();
        let seg1 = segments_2n.remove(0);
        let seg_sum = segments_2n
            .iter()
            .zip(0..segments_2n.len())
            .fold(seg1, |acc, x| {
                let two_to_the_n = two.pow(segment_size.clone() as u32);
                let two_to_the_n_shifted = two_to_the_n.shl(x.1 * segment_size);
                let two_to_the_n_shifted_fe: FE = ECScalar::from(&two_to_the_n_shifted);
                let shifted_segment = x.0.clone() * two_to_the_n_shifted_fe;
                acc + shifted_segment
            });
        return seg_sum;
    }

    pub fn to_encrypted_segments(
        secret: &FE,
        segment_size: &usize,
        num_of_segments: usize,
        pub_ke_y: &GE,
        G: &GE,
    ) -> (Witness, Helgamalsegmented) {
        let r_vec = (0..num_of_segments)
            .map(|_| ECScalar::new_random())
            .collect::<Vec<FE>>();
        let segmented_enc = (0..num_of_segments)
            .map(|i| {
                //  let segment_i = mSegmentation::get_segment_k(secret,segment_size,i as u8);
                Msegmentation::encrypt_segment_k(
                    secret,
                    &r_vec[i],
                    &segment_size,
                    i as u8,
                    pub_ke_y,
                    G,
                )
            }).collect::<Vec<Helgamal>>();
        let x_vec = (0..num_of_segments)
            .map(|i| Msegmentation::get_segment_k(secret, segment_size, i as u8))
            .collect::<Vec<FE>>();
        let w = Witness { x_vec, r_vec };
        let heg_segmented = Helgamalsegmented { DE: segmented_enc };
        (w, heg_segmented)
    }

    //TODO: implement a more advance algorithm for dlog
    // we run the full loop to avoid timing attack
    pub fn decrypt_segment(
        DE: &Helgamal,
        G: &GE,
        private_key: &FE,
        segment_size: &usize,
    ) -> Result<FE, Errors> {
        let mut result = Err(ErrorDecrypting);
        let limit = 2u32.pow(segment_size.clone() as u32);
        let limit_plus_one = limit + 1u32;
        let out_of_limit_fe: FE = ECScalar::from(&BigInt::from(limit_plus_one));
        let out_of_limit_ge: GE = G.clone() * &out_of_limit_fe;
        let yE = DE.E.clone() * private_key;
        // handling 0 segment
        let mut D_minus_yE: GE = out_of_limit_ge;
        if yE.get_element() == DE.D.clone().get_element() {
            result = Ok(ECScalar::zero())
        } else {
            D_minus_yE = DE.D.sub_point(&yE.get_element());
        }
        // TODO: make bound bigger then 32
        let mut test_fe: FE = ECScalar::from(&BigInt::one());
        let mut test_ge: GE = G.clone() * &test_fe;
        for i in 1..limit {
            test_fe = ECScalar::from(&BigInt::from(i));
            test_ge = G * &test_fe;
            if test_ge.get_element() == D_minus_yE.get_element() {
                result = Ok(test_fe.clone());
            }
        }
        result
    }

    pub fn decrypt(
        DE_vec: &Helgamalsegmented,
        G: &GE,
        private_key: &FE,
        segment_size: &usize,
    ) -> FE {
        let vec_secret = (0..DE_vec.DE.len())
            .map(|i| {
                let result =
                    Msegmentation::decrypt_segment(&DE_vec.DE[i], G, private_key, segment_size)
                        .expect("error decrypting");
                println!("{:?}", result.clone());
                result
            }).collect::<Vec<FE>>();
        Msegmentation::assemble_fe(&vec_secret, &segment_size)
    }
}
