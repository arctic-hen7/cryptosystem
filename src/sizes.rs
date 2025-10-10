use crate::crypto_array::{ConstWrapper, ToBitstring};
use typebits::{bs, B0, B1};

unsafe impl ToBitstring for ConstWrapper<0> {
    type Bitstring = B0;
}

/// A helper macro for implementation [`ToBitstring`] for various constant sizes. You're required
/// to put the keyword `unsafe` in here to make it clear that an incorrect pairing of coonstant
/// with binary representation *will* lead to extremely confusing errors! (Though not formal
/// undefined behaviour.)
#[macro_export]
macro_rules! impl_const {
    (unsafe $const:literal, $bitstring:ty) => {
        unsafe impl $crate::crypto_array::ToBitstring
            for $crate::crypto_array::ConstWrapper<$const>
        {
            type Bitstring = $bitstring;
        }
    };
}

// REGULAR NUMERIC IMPLEMENTATIONS BEGIN HERE

impl_const!(unsafe 1, B1);

// The build script works out other implementations from `sizes.txt`
include!(concat!(env!("OUT_DIR"), "/generated_sizes.rs"));
