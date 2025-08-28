use std::ops::{Index, IndexMut};

use thiserror::Error;
use typebits::{
    conditionals::{bitstring::SimpleIf, IsB0},
    And, Array, Bitstring, Diff, Sum, B0,
};

pub struct CryptoArray<N: Bitstring>(CryptoArrayInner<N>);
impl<N: Bitstring> CryptoArray<N> {
    pub fn new() -> Self {
        if N::UNSIGNED == 0 {
            Self(CryptoArrayInner::Variable(Vec::new()))
        } else {
            Self(CryptoArrayInner::Fixed(Array::default())) // This will be zeroed
        }
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self, BadSize> {
        if N::UNSIGNED == 0 {
            Ok(Self(CryptoArrayInner::Variable(slice.to_vec())))
        } else {
            let arr = Array::try_new_from_slice(slice).map_err(|_| BadSize {
                expected: N::UNSIGNED,
                found: slice.len(),
            })?;
            Ok(Self(CryptoArrayInner::Fixed(arr)))
        }
    }

    pub fn set_size(&mut self, size: usize) {
        match &mut self.0 {
            CryptoArrayInner::Fixed(arr) => {
                assert_eq!(size, N::UNSIGNED);
                let _ = arr; // Silence unused mut warning
            }
            CryptoArrayInner::Variable(vec) => {
                vec.resize(size, 0);
            }
        }
    }

    pub fn into_vec(self) -> Vec<u8> {
        match self.0 {
            CryptoArrayInner::Fixed(arr) => arr.as_ref().to_vec(),
            CryptoArrayInner::Variable(vec) => vec,
        }
    }
}
impl<N: Bitstring> Clone for CryptoArray<N> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl<N: Bitstring> AsRef<[u8]> for CryptoArray<N> {
    fn as_ref(&self) -> &[u8] {
        match &self.0 {
            CryptoArrayInner::Fixed(arr) => arr.as_ref(),
            CryptoArrayInner::Variable(vec) => vec.as_ref(),
        }
    }
}
impl<N: Bitstring> AsMut<[u8]> for CryptoArray<N> {
    fn as_mut(&mut self) -> &mut [u8] {
        match &mut self.0 {
            CryptoArrayInner::Fixed(arr) => arr.as_mut(),
            CryptoArrayInner::Variable(vec) => vec.as_mut(),
        }
    }
}
impl<N: Bitstring> Index<usize> for CryptoArray<N> {
    type Output = u8;

    fn index(&self, index: usize) -> &Self::Output {
        &self.as_ref()[index]
    }
}
impl<N: Bitstring> IndexMut<usize> for CryptoArray<N> {
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.as_mut()[index]
    }
}

enum CryptoArrayInner<N: Bitstring> {
    Fixed(Array<u8, N>),
    Variable(Vec<u8>),
}
impl<N: Bitstring> Clone for CryptoArrayInner<N> {
    fn clone(&self) -> Self {
        match self {
            CryptoArrayInner::Fixed(arr) => CryptoArrayInner::Fixed(arr.clone()),
            CryptoArrayInner::Variable(vec) => CryptoArrayInner::Variable(vec.clone()),
        }
    }
}

// TODO: Could add an extra associated type to mark whether we're on the stack or the heap...then
// consider length 0 it's own thing and we could support `Box<[u8]>` with a generic for
// size...would be easy to create from `N::UNSIGNED`

pub trait HasCryptoLen: Clone + AsRef<[u8]> + AsMut<[u8]> {
    type Length: Bitstring;

    // /// Returns a new instance of this array type, populated with zeroes. For a variable-length
    // /// array, it will be empty.
    // fn zeroed() -> Self;

    /// Creates a new [`HasCryptoLen`] from the given slice of bytes. This will fail with a
    /// [`BadSize`] error if the given slice is the wrong size (which of course can only be the
    /// case with a fixed-length array, as a variable-length one will accept anything).
    fn from_slice(slice: &[u8]) -> Result<Self, BadSize>;

    /// Gets the *runtime* length of this array. For fixed-length arrays, this will be the same as
    /// the constant [`Self::Length::UNSIGNED`], but for variable-length arrays, this will be the
    /// actual length.
    fn len(&self) -> usize {
        self.as_ref().len()
    }

    fn is_fixed_length() -> bool {
        Self::Length::UNSIGNED != 0
    }
}
impl HasCryptoLen for Vec<u8> {
    type Length = B0;

    fn from_slice(slice: &[u8]) -> Result<Self, BadSize> {
        Ok(slice.to_vec())
    }
}
impl<const N: usize> HasCryptoLen for [u8; N]
where
    Const<N>: ToBitstring,
{
    type Length = <Const<N> as ToBitstring>::Bitstring;

    fn from_slice(slice: &[u8]) -> Result<Self, BadSize> {
        if slice.len() != N {
            return Err(BadSize {
                expected: N,
                found: slice.len(),
            });
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(slice);
        Ok(arr)
    }
}
impl<B: Bitstring> HasCryptoLen for CryptoArray<B> {
    type Length = B;

    fn from_slice(slice: &[u8]) -> Result<Self, BadSize> {
        Self::from_slice(slice)
    }
}

pub trait OwnedHasCryptoLen: AsRef<[u8]> + AsMut<[u8]> {
    type Owned: HasCryptoLen;

    /// Gets the *runtime* length of this array. For fixed-length arrays, this will be the same as
    /// the constant [`Self::Owned::Length::UNSIGNED`], but for variable-length arrays, this will
    /// be the actual length.
    fn len(&self) -> usize {
        self.as_ref().len()
    }

    /// Sets the size of this array. This is intended to standardise operations across fixed and
    /// variable-length arrays. For fixed-length arrays, this is a no-op that applies an assertion
    /// that the size set is the array's actual size, while for variable-length arrays, this will
    /// extend the array with zeroes or truncate it as appropriate.
    ///
    /// This is designed for operations that need to run on a user-provided buffer to make sure
    /// it's the right size.
    fn set_size(&mut self, size: usize);
}
impl<const N: usize> OwnedHasCryptoLen for [u8; N]
where
    Const<N>: ToBitstring,
{
    type Owned = [u8; N];

    fn set_size(&mut self, size: usize) {
        assert_eq!(size, N);
    }
}
impl<B: Bitstring> OwnedHasCryptoLen for CryptoArray<B> {
    type Owned = CryptoArray<B>;

    fn set_size(&mut self, size: usize) {
        self.set_size(size);
    }
}
impl OwnedHasCryptoLen for Vec<u8> {
    type Owned = Vec<u8>;

    fn set_size(&mut self, size: usize) {
        self.resize(size, 0);
    }
}
impl OwnedHasCryptoLen for [u8] {
    type Owned = Vec<u8>; // A slice is a view into a vector, so we use the vector as the owned
                          // type

    fn set_size(&mut self, size: usize) {
        // NOTE: This is the most likely place to fail if the user has a vector and they provide a
        // mutable reference to a *slice* of it, which we can't resize!
        assert_eq!(
            size,
            self.len(),
            "expected slice of length {}, found {} (if you had a vector and gave a slice to a cryptographic operation, you need to set its size first, otherwise provide the vector itself instead)",
            self.len(),
            size
        )
    }
}

/// A trait for adding two bitstrings in such a way that, if either is zero, the result is zero.
/// This allows the kind of addition we use for adding fixed and variable-length arrays, in which a
/// variable-length array has size zero and "corrupts" everything it touches.
pub trait CryptoArrayAdd: Bitstring {
    /// The fallback-to-zero sum.
    type LenSum<Rhs: CryptoArrayAdd>: Bitstring;
}
impl<B: Bitstring> CryptoArrayAdd for B {
    // The sum is zero if either input is zero (if the `AND` of the two is zero, then one of them
    // is zero), otherwise it's the proper binary sum
    type LenSum<Rhs: CryptoArrayAdd> =
        SimpleIf<<And<Self, Rhs> as IsB0>::BitstringIsB0, B0, Sum<Self, Rhs>>;
}

/// A trait for subtracting two bitstrings in such a way that, if either is zero, the result is
/// zero. This allows the kind of subtraction we use for subtracting fixed and variable-length
/// arrays, in which a variable-length array has size zero and "corrupts" everything it touches.
pub trait CryptoArraySub: Bitstring {
    /// The fallback-to-zero difference.
    type LenDiff<Rhs: CryptoArraySub>: Bitstring;
}
impl<B: Bitstring> CryptoArraySub for B {
    // The difference is zero if either input is zero (if the `AND` of the two is zero, then one of
    // them is zero), otherwise it's the proper binary difference
    type LenDiff<Rhs: CryptoArraySub> =
        SimpleIf<<And<Self, Rhs> as IsB0>::BitstringIsB0, B0, Diff<Self, Rhs>>;
}

/// A type alias for the length of the array created when the two given arrays are summed.
pub type CryptoArraySumLen<A1 /*: ArrayLen*/, A2 /*: ArrayLen*/> =
    <<A1 as HasCryptoLen>::Length as CryptoArrayAdd>::LenSum<<A2 as HasCryptoLen>::Length>;
/// A type alias for the length of the array created when the two given arrays are subtracted.
pub type CryptoArrayDiffLen<A1 /*: ArrayLen*/, A2 /*: ArrayLen*/> =
    <<A1 as HasCryptoLen>::Length as CryptoArraySub>::LenDiff<<A2 as HasCryptoLen>::Length>;

/// A type alias for the resulting array created when summing the two given arrays. This will only
/// work under the following bounds:
///
/// ```rust,ignore
/// where
///     A1: ArrayLen,
///     A2: ArrayLen,
/// ```
pub type CryptoArraySum<A1 /*: ArrayLen*/, A2 /*: ArrayLen*/> =
    CryptoArray<CryptoArraySumLen<A1, A2>>;

/// A type alias for the resulting array created when subtracting the two given arrays. This will
/// only work under the following bounds:
///
/// ```rust,ignore
/// where
///    A1: ArrayLen,
///    A2: ArrayLen,
/// ```
pub type CryptoArrayDiff<A1 /*: ArrayLen*/, A2 /*: ArrayLen*/> =
    CryptoArray<CryptoArrayDiffLen<A1, A2>>;

// /// A type alias for the acceptable length of a buffer to hold the result of a cryptographic
// /// operation. This is designed to be used in a bound like so:
// ///
// /// ```rust, ignore
// /// where
// ///     <B as OwnedHasCryptoLen>::Owned:
// ///         HasCryptoLen<Length = CryptoBufLen<CryptoArraySumLen<P::Owned, C::OverheadBytes>, B>>
// /// ```
// ///
// /// Rather than checking that the buffer `B` has the *exact* length demanded by, say, the sum of
// /// the plaintext length and the overhead bytes in an encryption operation, `CryptoBufLen` will
// /// add, and then subtract, the buffer's length from this. If the buffer is of fixed-length, this
// /// will do nothing, anf that fixed length will be enforced. But if it's variable-length, this will
// /// corrupt to zero. This essentially allows variable-length buffers to be valid for holding
// /// fixed-length results.
// pub type CryptoBufLen<A /*: Bitstring*/, B /*: HasCryptoLen*/> =
//     <<A as CryptoArrayAdd>::LenSum<<B as HasCryptoLen>::Length> as CryptoArraySub>::LenDiff<
//         <B as HasCryptoLen>::Length,
//     >;

pub trait CryptoBuffer<N: Bitstring> {}
impl<const N: usize> CryptoBuffer<<Const<N> as ToBitstring>::Bitstring> for [u8; N] where
    Const<N>: ToBitstring
{
}
impl<N: Bitstring> CryptoBuffer<N> for Vec<u8> {}
impl<N: Bitstring> CryptoBuffer<N> for CryptoArray<N> {}
// NOTE: We don't implement for all `N: Bitstring` for `CryptoArray<B0>` even though it's variable,
// because this would create a double implementation unfortunately. Regardless, if either the
// plaintext or overhead bytes are variable-length, everything will resolve correctly because the
// functions using these bounds will expect a variable-length buffer. The only problem would be
// manually constructing a variable-length `CryptoArray`, which is sort of silly, because you can
// just use a vector...in short, it's a foot-shooting case in which users would do this anyway.
// Once we get specialisation though, go ahead!

/// An intermediate type that has no function other than to implement [`ToBitstring`] for the given
/// constant.
pub struct Const<const N: usize>;

/// A trait for converting numbers into bitstrings. This is implemented for a large number of
/// [`Const<N>`] types.
pub trait ToBitstring {
    type Bitstring: Bitstring;
}

#[derive(Error, Debug)]
#[error("expected slice of length {expected}, found {found}")]
pub struct BadSize {
    expected: usize,
    found: usize,
}

// ---

// pub struct True;
// pub struct False;
//
// pub trait TypeBool: ZeroGate {
//     type And<Other: TypeBool>: TypeBool;
//     type Or<Other: TypeBool>: TypeBool;
//     type Not: TypeBool;
// }
// impl TypeBool for True {
//     type And<Other: TypeBool> = Other;
//     type Or<Other: TypeBool> = True;
//     type Not = False;
// }
// impl TypeBool for False {
//     type And<Other: TypeBool> = False;
//     type Or<Other: TypeBool> = Other;
//     type Not = True;
// }
//
// pub trait IsZero {
//     type Output: TypeBool;
// }
// impl IsZero for UTerm {
//     type Output = True;
// }
// impl<U: Unsigned, B: Bit> IsZero for UInt<U, B> {
//     type Output = False;
// }
//
// /// A type alias for the associated type of [`IsPositive`]. If `L` or `R` is zero, this will
// /// evaluate to zero, otherwise it will evaluate to `R`.
// pub type EitherZero<L, R> = <L as EitherIsZero>::Output<R>;
// /// When given another [`Unsigned`] type integer, the associated type of this trait will return
// /// zero if `Self` or the other type is zero, otherwise it will return the other type.
// pub trait EitherIsZero: IsZero {
//     type Output<Other: Unsigned + IsZero>: TypeBool + ZeroGate;
// }
// impl<U: Unsigned + IsZero> EitherIsZero for U {
//     type Output<Other: Unsigned + IsZero> =
//         <<U as IsZero>::Output as TypeBool>::Or<<Other as IsZero>::Output>;
// }
//
// /// A type alias for the associated type of [`ZeroGate`]. If `L` is zero, this will evaluate to
// /// zero, otherwise it will evaluate to `R`.
// pub type ZeroGated<L, R> = <L as ZeroGate>::Output<R>;
//
// /// When given another [`Unsigned`] type integer, the associated type of this trait will return
// /// that integer if `Self` is non-zero, otherwise it will return zero.
// ///
// /// Said another way, [`ZeroGated<L, R>`] will be zero if `L` is zero, or `R` otherwise.
// pub trait ZeroGate {
//     type Output<Other>;
// }
// // `ZeroOr<UTerm, X>` should always be zero
// impl ZeroGate for False {
//     type Output<Other> = UTerm;
// }
// // If our term is non-zero though, take the value of the other term
// impl ZeroGate for True {
//     type Output<Other> = Other;
// }
//
// /// A type alias that will evaluate to `X` if neither `A` or `B` is zero, or otherwise zero.
// pub type EitherZeroOr<A, B, X> = ZeroGated<EitherZero<A, B>, X>;
//
// pub trait ArraySize: hybrid_array::ArraySize + Unsigned + EitherIsZero {}
// impl<U: hybrid_array::ArraySize + Unsigned + IsZero + EitherIsZero> ArraySize for U {}
