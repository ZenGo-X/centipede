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
use curv::BigInt;
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_encryption_of_dlog::{HomoELGamalDlogProof,HomoElGamalDlogWitness,HomoElGamalDlogStatement};
use curv::cryptographic_primitives::proofs::sigma_correct_homomorphic_elgamal_enc::{HomoELGamalProof,HomoElGamalWitness,HomoElGamalStatement};
use curv::cryptographic_primitives::hashing::hash_sha512::HSha512;
use curv::cryptographic_primitives::hashing::traits::*;
use curv::arithmetic::traits::Converter;
use bulletproof::proofs::range_proof::{RangeProof};
use bulletproof::proofs::utils::derive_point;
use juggling::segmentation::Msegmentation;
use Errors::{self, ErrorProving};
use grad_release::FirstMessage;
use ::Errors::ErrorFirstMessage;
use grad_release::SegmentProof;
use ::Errors::ErrorSegmentProof;
use curv::elliptic::curves::traits::*;
use serde::{Serialize, Deserialize};
use zeroize::Zeroize;

#[derive(Serialize, Deserialize)]
pub struct Helgamal<P: ECPoint> {
    pub D: P,
    pub E: P,
}

#[derive(Serialize, Deserialize)]
pub struct Helgamalsegmented<P: ECPoint> {
    pub DE: Vec<Helgamal<P>>,
}

#[derive(Serialize, Deserialize)]
pub struct Witness<S: ECScalar> {
    pub x_vec: Vec<S>,
    pub r_vec: Vec<S>,
}

#[derive(Serialize, Deserialize)]
#[serde(bound(serialize = "P: Serialize, P::Scalar: Serialize"))]
#[serde(bound(deserialize = "P: Deserialize<'de>, P::Scalar: Deserialize<'de>"))]
pub struct Proof<P: ECPoint> {
    pub bulletproof: RangeProof<P>,
    pub elgamal_enc: Vec<HomoELGamalProof<P>>,
    pub elgamal_enc_dlog: HomoELGamalDlogProof<P>,
}

impl<P> Proof<P>
where
    P: ECPoint + Clone + Zeroize,
    P::Scalar: Clone + PartialEq + Zeroize,
{
    pub fn prove(
        w: &Witness<P::Scalar>,
        c: &Helgamalsegmented<P>,
        G: &P,
        Y: &P,
        segment_size: &usize,
    ) -> Proof<P> {
        // bulletproofs:
        let num_segments = w.x_vec.len();
        // bit range
        let n = segment_size.clone();
        // batch size
        let m = num_segments;
        let nm = n * m;
        // some seed for generating g and h vectors
        let KZen: &[u8] = &[75, 90, 101, 110];
        let kzen_label = BigInt::from(KZen);

        let g_vec = (0..nm)
            .map(|i| {
                let kzen_label_i = BigInt::from(i as u32) + &kzen_label;
                let hash_i = HSha512::create_hash(&[&kzen_label_i]);
                derive_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<_>>();

        // can run in parallel to g_vec:
        let h_vec = (0..nm)
            .map(|i| {
                let kzen_label_j = BigInt::from(n as u32) + BigInt::from(i as u32) + &kzen_label;
                let hash_j = HSha512::create_hash(&[&kzen_label_j]);
                derive_point(&Converter::to_vec(&hash_j))
            })
            .collect::<Vec<_>>();

        let range_proof =
            RangeProof::prove(&g_vec, &h_vec, G, &Y, w.x_vec.clone(), &w.r_vec, n.clone());

        // proofs of correct elgamal:

        let elgamal_proofs = (0..num_segments)
            .map(|i| {
                let w = HomoElGamalWitness {
                    r: w.r_vec[i].clone(),
                    x: w.x_vec[i].clone(),
                };
                let delta = HomoElGamalStatement {
                    G: G.clone(),
                    H: G.clone(),
                    Y: Y.clone(),
                    D: c.DE[i].D.clone(),
                    E: c.DE[i].E.clone(),
                };
                HomoELGamalProof::<P>::prove(&w, &delta)
            })
            .collect::<Vec<HomoELGamalProof<P>>>();

        // proof of correct ElGamal DLog
        let D_vec: Vec<P> = (0..num_segments).map(|i| c.DE[i].D.clone()).collect();
        let E_vec: Vec<P> = (0..num_segments).map(|i| c.DE[i].E.clone()).collect();
        let sum_D = Msegmentation::assemble_ge(&D_vec, segment_size);
        let sum_E = Msegmentation::assemble_ge(&E_vec, segment_size);
        let sum_r = Msegmentation::assemble_fe(&w.r_vec, segment_size);
        let sum_x = Msegmentation::assemble_fe(&w.x_vec, segment_size);
        let Q = G.clone() * sum_x.clone();
        let delta = HomoElGamalDlogStatement {
            G: G.clone(),
            Y: Y.clone(),
            Q,
            D: sum_D,
            E: sum_E,
        };
        let w = HomoElGamalDlogWitness { r: sum_r, x: sum_x };
        let elgamal_dlog_proof = HomoELGamalDlogProof::prove(&w, &delta);

        Proof {
            bulletproof: range_proof,
            elgamal_enc: elgamal_proofs,
            elgamal_enc_dlog: elgamal_dlog_proof,
        }
    }

    pub fn verify(
        &self,
        c: &Helgamalsegmented<P>,
        G: &P,
        Y: &P,
        Q: &P,
        segment_size: &usize,
    ) -> Result<(), Errors> {
        // bulletproofs:
        let num_segments = self.elgamal_enc.len();
        // bit range
        let n = segment_size.clone();
        // batch size
        let m = num_segments;
        let nm = n * m;
        // some seed for generating g and h vectors
        let KZen: &[u8] = &[75, 90, 101, 110];
        let kzen_label = BigInt::from(KZen);

        let g_vec = (0..nm)
            .map(|i| {
                let kzen_label_i = BigInt::from(i as u32) + &kzen_label;
                let hash_i = HSha512::create_hash(&[&kzen_label_i]);
                derive_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<P>>();

        // can run in parallel to g_vec:
        let h_vec = (0..nm)
            .map(|i| {
                let kzen_label_j = BigInt::from(n as u32) + BigInt::from(i as u32) + &kzen_label;
                let hash_j = HSha512::create_hash(&[&kzen_label_j]);
                derive_point(&Converter::to_vec(&hash_j))
            })
            .collect::<Vec<P>>();

        let D_vec: Vec<P> = (0..num_segments).map(|i| c.DE[i].D.clone()).collect();
        let bp_ver = self
            .bulletproof
            .verify(&g_vec, &h_vec, G, Y, &D_vec, segment_size.clone())
            .is_ok();

        let elgamal_proofs_ver = (0..num_segments)
            .map(|i| {
                let delta = HomoElGamalStatement {
                    G: G.clone(),
                    H: G.clone(),
                    Y: Y.clone(),
                    D: c.DE[i].D.clone(),
                    E: c.DE[i].E.clone(),
                };
                self.elgamal_enc[i].verify(&delta).is_ok()
            })
            .collect::<Vec<bool>>();

        let E_vec: Vec<P> = (0..num_segments).map(|i| c.DE[i].E.clone()).collect();
        let sum_D = Msegmentation::assemble_ge(&D_vec, segment_size);
        let sum_E = Msegmentation::assemble_ge(&E_vec, segment_size);

        let delta = HomoElGamalDlogStatement {
            G: G.clone(),
            Y: Y.clone(),
            Q: Q.clone(),
            D: sum_D,
            E: sum_E,
        };

        let elgamal_dlog_proof_ver = self.elgamal_enc_dlog.verify(&delta).is_ok();
        if bp_ver && elgamal_dlog_proof_ver && elgamal_proofs_ver.iter().all(|&x| x == true) {
            Ok(())
        } else {
            Err(ErrorProving)
        }
    }

    pub fn verify_first_message(
        first_message: &FirstMessage<P>,
        encryption_key: &P,
    ) -> Result<(), Errors> {
        // bulletproofs:
        let num_segments = first_message.D_vec.len();
        // bit range
        let n = first_message.segment_size.clone();
        // batch size
        let m = num_segments;
        let nm = n * m;
        // some seed for generating g and h vectors
        let KZen: &[u8] = &[75, 90, 101, 110];
        let kzen_label = BigInt::from(KZen);

        let g_vec = (0..nm)
            .map(|i| {
                let kzen_label_i = BigInt::from(i as u32) + &kzen_label;
                let hash_i = HSha512::create_hash(&[&kzen_label_i]);
                derive_point(&Converter::to_vec(&hash_i))
            })
            .collect::<Vec<P>>();

        let Y = encryption_key.clone();
        // can run in parallel to g_vec:
        let h_vec = (0..nm)
            .map(|i| {
                let kzen_label_j = BigInt::from(n as u32) + BigInt::from(i as u32) + &kzen_label;
                let hash_j = HSha512::create_hash(&[&kzen_label_j]);
                derive_point(&Converter::to_vec(&hash_j))
            })
            .collect::<Vec<P>>();

        let D_vec: Vec<P> = (0..num_segments)
            .map(|i| first_message.D_vec[i].clone())
            .collect();
        let bp_ver = first_message
            .range_proof
            .verify(
                &g_vec,
                &h_vec,
                &P::generator(),
                &Y,
                &first_message.D_vec,
                first_message.segment_size.clone(),
            )
            .is_ok();

        let sum_D = Msegmentation::assemble_ge(&D_vec, &first_message.segment_size);
        let sum_E = first_message.E.clone();

        let delta = HomoElGamalDlogStatement {
            G: P::generator(),
            Y,
            Q: first_message.Q.clone(),
            D: sum_D,
            E: sum_E,
        };

        let elgamal_dlog_proof_ver = first_message.dlog_proof.verify(&delta).is_ok();
        if bp_ver && elgamal_dlog_proof_ver {
            Ok(())
        } else {
            Err(ErrorFirstMessage)
        }
    }

    pub fn verify_segment(
        first_message: &FirstMessage<P>,
        segment: &SegmentProof<P>,
        encryption_key: &P,
    ) -> Result<(), Errors> {
        let delta = HomoElGamalStatement {
            G: P::generator(),
            H: P::generator(),
            Y: encryption_key.clone(),
            D: first_message.D_vec[segment.k].clone(),
            E: segment.E_k.clone(),
        };

        let elgamal_proof = segment.correct_enc_proof.verify(&delta).is_ok();

        if elgamal_proof {
            Ok(())
        } else {
            Err(ErrorSegmentProof)
        }
    }
}

#[cfg(test)]
mod tests {
    use curv::elliptic::curves::traits::*;
    use curv::test_for_all_curves;
    use juggling::proof_system::*;
    use juggling::segmentation::Msegmentation;
    use wallet::SecretShare;
    use zeroize::Zeroize;

    test_for_all_curves!(test_verifiable_encryption);
    fn test_verifiable_encryption<P>()
    where
        P: ECPoint + Clone + Zeroize + Sync + Send,
        P::Scalar: Clone + PartialEq + Zeroize + Sync + Send + std::fmt::Debug,
    {
        let segment_size = 8;
        let y: P::Scalar = ECScalar::new_random();
        let G: P = ECPoint::generator();
        let Y = G.clone() * y.clone();
        let x = SecretShare::<P>::generate();
        let Q = G.clone() * x.secret.clone();
        let (segments, encryptions) =
            Msegmentation::to_encrypted_segments(&x.secret, &segment_size, 32, &Y, &G);
        let secret_new = Msegmentation::assemble_fe(&segments.x_vec, &segment_size);
        let secret_decrypted = Msegmentation::decrypt(&encryptions, &G, &y, &segment_size);

        assert_eq!(x.secret, secret_new);
        assert_eq!(x.secret, secret_decrypted.unwrap());

        let proof = Proof::prove(&segments, &encryptions, &G, &Y, &segment_size);
        let result = proof.verify(&encryptions, &G, &Y, &Q, &segment_size);
        assert!(result.is_ok());
    }

    test_for_all_curves!(
        #[should_panic]
        test_verifiable_encryption_bad_Q
    );
    fn test_verifiable_encryption_bad_Q<P: ECPoint>()
    where
        P: ECPoint + Clone + Zeroize + Sync + Send,
        P::Scalar: Clone + PartialEq + Zeroize + Sync + Send + std::fmt::Debug,
    {
        let segment_size = 8;
        let y: P::Scalar = ECScalar::new_random();
        let G: P = ECPoint::generator();
        let Y = G.clone() * y.clone();
        let x = SecretShare::<P>::generate();
        let Q = G.clone() * x.secret.clone() + G.clone();
        let (segments, encryptions) =
            Msegmentation::to_encrypted_segments::<P>(&x.secret, &segment_size, 32, &Y, &G);
        let secret_new = Msegmentation::assemble_fe(&segments.x_vec, &segment_size);
        let secret_decrypted = Msegmentation::decrypt(&encryptions, &G, &y, &segment_size);
        assert_eq!(x.secret, secret_new);
        assert_eq!(x.secret, secret_decrypted.unwrap());

        let proof = Proof::<P>::prove(&segments, &encryptions, &G, &Y, &segment_size);
        let result = proof.verify(&encryptions, &G, &Y, &Q, &segment_size);
        assert!(result.is_ok());
    }
}
