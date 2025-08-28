use crate::crypto_array::{Const, ToBitstring};
use typebits::{bs, B0, B1};

impl ToBitstring for Const<0> {
    type Bitstring = B0;
}

macro_rules! impl_const {
    ($const:literal, $bitstring:ty) => {
        impl $crate::crypto_array::ToBitstring for $crate::crypto_array::Const<$const> {
            type Bitstring = $bitstring;
        }
    };
}

// REGULAR NUMERIC IMPLEMENTATIONS BEGIN HERE

impl_const!(1, B1);
impl_const!(2, bs!(1, 0));
impl_const!(3, bs!(1, 1));
impl_const!(4, bs!(1, 0, 0));
impl_const!(5, bs!(1, 0, 1));
impl_const!(6, bs!(1, 1, 0));
impl_const!(7, bs!(1, 1, 1));
impl_const!(8, bs!(1, 0, 0, 0));
impl_const!(9, bs!(1, 0, 0, 1));
impl_const!(10, bs!(1, 0, 1, 0));
impl_const!(11, bs!(1, 0, 1, 1));
impl_const!(12, bs!(1, 1, 0, 0));
impl_const!(13, bs!(1, 1, 0, 1));
impl_const!(14, bs!(1, 1, 1, 0));
impl_const!(15, bs!(1, 1, 1, 1));
impl_const!(16, bs!(1, 0, 0, 0, 0));

impl_const!(32, bs!(1, 0, 0, 0, 0, 0));
impl_const!(40, bs!(1, 0, 1, 0, 0, 0));
impl_const!(64, bs!(1, 0, 0, 0, 0, 0, 0));
impl_const!(768, bs!(1, 1, 0, 0, 0, 0, 0, 0, 0, 0));
impl_const!(800, bs!(1, 1, 0, 0, 1, 0, 0, 0, 0, 0));
impl_const!(1632, bs!(1, 1, 0, 0, 1, 1, 0, 0, 0, 0, 0));

impl_const!(832, bs!(1, 1, 0, 1, 0, 0, 0, 0, 0, 0)); // 32 + 800 for Kyber and x25519 together
impl_const!(1664, bs!(1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0)); // 32 + 1632 for Kyber and x25519 together
                                                         // 32 + 768 = 800 for Kyber and x25519, but already covered!
