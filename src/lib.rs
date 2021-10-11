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

pub mod grad_release;
pub mod juggling;
pub mod wallet;
extern crate bulletproof;
extern crate curv;
extern crate generic_array;
extern crate rayon;
extern crate sha2;

#[macro_use]
extern crate serde_derive;
extern crate serde;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Errors {
    ErrorDecrypting,
    ErrorProving,
    ErrorFirstMessage,
    ErrorSegmentProof,
    ErrorSegmentNum,
}
