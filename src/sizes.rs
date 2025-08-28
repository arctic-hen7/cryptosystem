use crate::crypto_array::{Const, ToBitstring};
use typebits::{bs, B0, B1};

unsafe impl ToBitstring for Const<0> {
    type Bitstring = B0;
}

/// A helper macro for implementation [`ToBitstring`] for various constant sizes. You're required
/// to put the keyword `unsafe` in here
#[macro_export]
macro_rules! impl_const {
    (unsafe $const:literal, $bitstring:ty) => {
        unsafe impl $crate::crypto_array::ToBitstring for $crate::crypto_array::Const<$const> {
            type Bitstring = $bitstring;
        }
    };
}

// REGULAR NUMERIC IMPLEMENTATIONS BEGIN HERE

impl_const!(unsafe 1, B1);
impl_const!(unsafe 2, bs!(1, 0));
impl_const!(unsafe 3, bs!(1, 1));
impl_const!(unsafe 4, bs!(1, 0, 0));
impl_const!(unsafe 5, bs!(1, 0, 1));
impl_const!(unsafe 6, bs!(1, 1, 0));
impl_const!(unsafe 7, bs!(1, 1, 1));
impl_const!(unsafe 8, bs!(1, 0, 0, 0));
impl_const!(unsafe 9, bs!(1, 0, 0, 1));
impl_const!(unsafe 10, bs!(1, 0, 1, 0));
impl_const!(unsafe 11, bs!(1, 0, 1, 1));
impl_const!(unsafe 12, bs!(1, 1, 0, 0));
impl_const!(unsafe 13, bs!(1, 1, 0, 1));
impl_const!(unsafe 14, bs!(1, 1, 1, 0));
impl_const!(unsafe 15, bs!(1, 1, 1, 1));
impl_const!(unsafe 16, bs!(1, 0, 0, 0, 0));

impl_const!(unsafe 32, bs!(1, 0, 0, 0, 0, 0));
impl_const!(unsafe 40, bs!(1, 0, 1, 0, 0, 0));
impl_const!(unsafe 64, bs!(1, 0, 0, 0, 0, 0, 0));
impl_const!(unsafe 768, bs!(1, 1, 0, 0, 0, 0, 0, 0, 0, 0));
impl_const!(unsafe 800, bs!(1, 1, 0, 0, 1, 0, 0, 0, 0, 0));
impl_const!(unsafe 1632, bs!(1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0));

impl_const!(unsafe 832, bs!(1, 1, 0, 1, 0, 0, 0, 0, 0, 0)); // 32 + 800 for Kyber and x25519 together
impl_const!(unsafe 1664, bs!(1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0)); // 32 + 1632 for Kyber and x25519 together
                                                                // 32 + 768 = 800 for Kyber and x25519, but already covered!
