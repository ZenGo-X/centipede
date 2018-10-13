/*
escrow-recovery

Copyright 2018 by Kzen Networks

This file is part of escrow-recovery library
(https://github.com/KZen-networks/cryptography-utils)

Escrow-recovery is free software: you can redistribute
it and/or modify it under the terms of the GNU General Public
License as published by the Free Software Foundation, either
version 3 of the License, or (at your option) any later version.

@license GPL-3.0+ <https://github.com/KZen-networks/escrow-recovery/blob/master/LICENSE>
*/



use cryptography_utils::{FE,GE,BigInt};
use cryptography_utils::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_encryption_of_dlog::HomoELGamalDlogProof;
use cryptography_utils::cryptographic_primitives::proofs::sigma_correct_homomrphic_elgamal_enc::HomoELGamalProof;
use cryptography_utils::cryptographic_primitives::hashing::hash_sha512::HSha512;
use cryptography_utils::cryptographic_primitives::hashing::traits::*;
use bulletproofs::RangeProof;
use cryptography_utils::elliptic::curves::traits::*;
use std::ops::Shr;
use wallet::SecretShare;


pub struct hElGamal{
    D: GE,
    E: GE,
}

pub struct hElGamalSegmented{
    D: Vec<GE>,
    E: Vec<GE>,
}

pub struct Witness{
    x_vec: Vec<FE>,
    r_vec: Vec<FE>,
}

pub struct mSegmentation;

impl mSegmentation{

    pub fn get_segment_k(secret: &FE, segment_size: u8, k: u8) -> FE{
        let ss_bn = secret.to_big_int();
        let temp: FE = ECScalar::from(&ss_bn);
        let segment_size_u32 = segment_size as u32;
        let msb = segment_size_u32 * (k+1) as u32;
        let lsb = segment_size_u32 * k as u32;
        let two_bn = BigInt::from(2);
        let max = BigInt::pow(&two_bn,msb) - BigInt::from(1);
        let min = BigInt::pow(&two_bn,lsb) - BigInt::from(1);
        let mask = max - min;
        let segment_k_bn = mask & ss_bn;
        let segment_k_bn_rotated = BigInt::shr(segment_k_bn,(k*segment_size) as usize);
       // println!("test = {:?}", test.to_str_radix(16));
        ECScalar::from(&segment_k_bn_rotated)
    }
    //returns r_k,{D_k,E_k}
    pub fn encrypt_segment_k(secret: &FE,  segment_size: u8, k: u8, pub_ke_y: &GE) -> (FE, hElGamal){
        let segment_k = mSegmentation::get_segment_k(secret,segment_size,k);
        let r_k:FE = ECScalar::new_random();
        let base_point: GE = ECPoint::generator();
        let E_k = base_point * &r_k;
        let r_kY = pub_ke_y.clone() * &r_k;
        let base_point: GE = ECPoint::generator();
        let x_kG = base_point * segment_k ;
        let D_k = r_kY + x_kG;
        (r_k, hElGamal{D:D_k,E:E_k})
    }

    pub fn to_encrypted_segments(secret: &FE,  segment_size: u8, k: u8, pub_ke_y: &GE) -> (Witness, hElGamalSegmented){


    }
}

pub struct Proof{
    bulletproof: RangeProof,
    elgamal_enc: Vec<HomoELGamalProof>,
    elgamal_enc_dlog: HomoELGamalDlogProof,
};

impl Proof{

    pub fn prove(w: &Witness, c: &hElGamalSegmented) -> Proof{

        // bulletproofs:
        let num_segments = w.x_vec.len();
        // bit range
        let n = 256 / num_segments;
        // batch size
        let m = num_segments;
        let nm = n * m;
        // some seed for generating g and h vectors
        let KZen: &[u8] = &[75, 90, 101, 110];
        let kzen_label = BigInt::from(KZen);

        // G,H - points for pederson commitment: com  = vG + rH
        let G: GE = ECPoint::generator();
        let label = BigInt::from(1);
        let hash = HSha512::create_hash(&[&label]);
        let H = generate_random_point(&Converter::to_vec(&hash));

        let g_vec = (0..nm)
            .map(|i| {
                let kzen_label_i = BigInt::from(i as u32) + &kzen_label;
                let hash_i = HSha512::create_hash(&[&kzen_label_i]);
                generate_random_point(&Converter::to_vec(&hash_i))
            }).collect::<Vec<GE>>();

        // can run in parallel to g_vec:
        let h_vec = (0..nm)
            .map(|i| {
                let kzen_label_j = BigInt::from(n as u32) + BigInt::from(i as u32) + &kzen_label;
                let hash_j = HSha512::create_hash(&[&kzen_label_j]);
                generate_random_point(&Converter::to_vec(&hash_j))
            }).collect::<Vec<GE>>();

        let range = BigInt::from(2).pow(n as u32);


        let range_proof = RangeProof::prove(&g_vec, &h_vec, &G, &H, w.x_vec.clone(), w.r_vec.clone(), n);

        // proofs of correct elgamal:
        let elgamal_proofs = (0..num_segments).map

    }
}

#[cfg(test)]
mod tests {
    use cryptography_utils::BigInt;
    use cryptography_utils::{FE, GE};
    use juggling::server::{SecretShare,mSegmentation};
    use cryptography_utils::elliptic::curves::traits::*;
    use wallet::SecretShare;


    #[test]
    fn test_m_segmentation() {

        let x =  SecretShare::generate();
        println!("x = {:?}", x.secret);
        println!("ss = {:?}", x.secret.to_big_int().to_str_radix(16));
        let x0 = mSegmentation::get_segment_k(&x.secret,16,15);
        println!("s0 = {:?}", x0.to_big_int().to_str_radix(16));

    }
}