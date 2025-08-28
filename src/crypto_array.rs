use std::ops::{Index, IndexMut};
use thiserror::Error;
use typebits::{
    conditionals::{bitstring::SimpleIf, IsB0},
    And, Array, Bitstring, Diff, Sum, B0,
};

/// An "array" type for holding cryptographic values.
///
/// # How `cryptosystem` handles lengths
///
/// ***Tl;DR:* use [`CryptoArraySum`] and [`CryptoArrayDiff`] to create buffers of the right
/// length, or just use the `encrypt` APIs to work with `Vec<u8>`. If you need to encrypt keys with
/// other keys, or other fixed-length data, read on!
///
/// For symmetric encryption particularly, nearly all algorithms have a fixed-size overhead that
/// they apply on top of the plaintext. That is, given a plaintext of length `P`, the ciphertext
/// will be of length `P + O`. This means we can optimise ever so slightly by stack-allocating a
/// ciphertext `[u8; P + O]` when given a plaintext `[u8; P]`. But if we're given a variable-length
/// plaintext as, say, a `Vec<u8>`, then we can't do this, so we should return a `Vec<u8>` for the
/// ciphertext too. The same thing should happen in reverse for the ciphertext. Ideally, we should
/// also support when a symmetric algorithm doesn't declare its overhead length (perhaps because
/// it's doing something complex with padding), in which case we should use a `Vec<u8>` for
/// everything.
///
/// This crate achieves this by implementing binary addition in the compiler. No, I'm not kidding,
/// we built a Turing machine in the damn compiler to make this work. Was it way too much effort
/// for a tiny optimisation? Yes. Was it fun as all hell? Absolutely!
///
/// Specifically, we use [`typebits`] to represent lengths as bitstrings, and then we add them
/// conditionally so that, if either size is zero (representing variable-length), the result gets
/// "corrupted" to zero.
///
/// Most of the time, end users will use `Vec<u8>`-driven simple APIs, but if they want to, they
/// can pass in buffers themselves or use the `encrypt_bytes` API, which will return
/// [`CryptoArray`] buffers.
///
/// This type is simple: give it a length as a type parameter, and it will internally work out if
/// it should be fixed-length (and stack-allocated) ot variable-length (and heap-allocated). The
/// length parameter needs to be a [`Bitstring`], which you can either construct from binary with
/// [`typebits::bitstring!`] (don't do this), or you can use [`Const<const N: usize>`], which will
/// take in an actual number and work from that.
///
/// **However**, the vast majority of the time you will never need to do that! We expose
/// [`CryptoArraySum<A, B>`] and [`CryptoArrayDiff<A, B>`] type aliases that will do the addition
/// and subtraction for you, given two arrays. For example, if you had a symmetric cryptosystem `K`
/// and a plaintext 15 bytes long, you could create a ciphertext buffer like so:
///
/// ```rust,ignore
/// let mut buf = CryptoArraySum::<[u8; 15], K::OverheadBytes>::new();
/// ```
///
/// That will internally create a [`CryptoArray`] of exactly the right length, and that length will
/// adjust at *compile-time* according to the cryptosystem you're using. In other words, you can
/// write code that's completely generic over the encryption algorithms involved, and still get
/// everything done on the stack when it's possible. This particularly makes encrypting keys with
/// other keys (when you know the plaintext length, usually something like 32 bytes) very efficient
/// and elegant (especially because a fixed-length [`CryptoArray`] serializes to bytes with zero
/// overhead).
///
/// And of course, all this is done at compile-time, and doesn't even need to optimise away, none
/// of it ends up in your runtime assembly, period.
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

/// A trait for values that have a length associated with them, which can be added or subtracted
/// with each other to produce new cryptographic arrays of the right length. This is implemented
/// for vectors, and any `[u8; N]` whose `N` we can parse.
pub trait HasCryptoLen: Clone + AsRef<[u8]> + AsMut<[u8]> {
    /// The bitstring length of this array, which lets us do fancy addition and subtraction.
    type Length: Bitstring;

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

    /// Returns whether or not this is a fixed-length array. If you need this at const time, use
    /// [`Self::Length::UNSIGNED`] instead, it will be `0` if variable-length, or non-zero if
    /// fixed.
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
    // Parsing bound!
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

/// A trait for reference types whose owned versions implement [`HasCryptoLen`]. This exists purely
/// to allow users to pass `&[u8]` where we don't know the length, and for us to interpret these as
/// variable-length.
pub trait OwnedHasCryptoLen: AsRef<[u8]> + AsMut<[u8]> {
    /// The owned type that implements [`HasCryptoLen`].
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
pub type CryptoArraySumLen<A1 /*: HasCryptoLen*/, A2 /*: HasCryptoLen*/> =
    <<A1 as HasCryptoLen>::Length as CryptoArrayAdd>::LenSum<<A2 as HasCryptoLen>::Length>;
/// A type alias for the length of the array created when the two given arrays are subtracted.
pub type CryptoArrayDiffLen<A1 /*: HasCryptoLen*/, A2 /*: HasCryptoLen*/> =
    <<A1 as HasCryptoLen>::Length as CryptoArraySub>::LenDiff<<A2 as HasCryptoLen>::Length>;

/// A type alias for the resulting array created when summing the two given arrays. You can use
/// this to create buffers to hold your ciphertexts that will be stack-allocated when they can be,
/// and variable-length when they need to be, in a way that's generic over the encryption algorithm
/// used. See [`CryptoArray`] for more details (the output type this will always produce).
pub type CryptoArraySum<A1 /*: HasCryptoLen*/, A2 /*: HasCryptoLen*/> =
    CryptoArray<CryptoArraySumLen<A1, A2>>;

/// A type alias for the resulting array created when subtracting the two given arrays. You can use
/// this to create buffers to hold your plaintexts that will be stack-allocated when they can be,
/// and variable-length when they need to be, in a way that's generic over the encryption
/// algorithm used. See [`CryptoArray`] for more details (the output type this will always
/// produce).
pub type CryptoArrayDiff<A1 /*: HasCryptoLen*/, A2 /*: HasCryptoLen*/> =
    CryptoArray<CryptoArrayDiffLen<A1, A2>>;

/// A marker trait for cryptographic buffers. This doesn't implement any functionality, it's used
/// as a compile-time way of asserting that a buffer the user provides to an encryption or
/// decryption function is of the right length.
///
/// This is, as you'd expect, implemented for stack-allocated arrays, but `Vec<u8>` implements it
/// for *any* length, expressing that you can use a variable-length array to store any length of
/// data.
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
/// constant. This acts as a bridge between raw `usize` values and [`Bitstring`].
pub struct Const<const N: usize>;

/// A trait for converting numbers into bitstrings. This is implemented for a large number of
/// [`Const<N>`] types.
///
/// # I can't convert to my number!
///
/// If you're working with a large or otherwise obscure number (especially if you're doing anything
/// post-quantum...), a conversion to a bitstring might not be implemented yet! To fix this, you
/// can either manually construct the bitstring with [`typebits::bitstring!`] (e.g. `bitstring!(1,
/// 0, 1)` for 5), you can implement [`ToBitstring`] yourself (as below), or you can open a PR
/// doing this so others can benefit too! Here's how to do the implementation:
///
/// ```rust,ignore
/// use typebits::bs; // Alias for `bitstring!`
/// use cryptosystem::impl_const;
///
/// impl_const!(unsafe 16, bs!(1, 0, 0, 0, 0));
/// ```
///
/// This is an unsafe trait because getting the bitstring wrong will cause panics internally. It
/// won't lead to memory unsafety, but we mark it as unsafe anyway because it's a very clear and
/// fundamental design contract, the violation of which will be extremely subtle and very hard to
/// work out the cause of (imagine the kinds of compiler errors that come from binary addition).
/// Please double-check your binary!!
///
/// Also, note that this is the *only* part of the crate that is not fully generic yet. Once we
/// have a few nightly features stabilised, we should be able to implement it truly generically. If
/// anyone has any magical ideas on how to implement it automatically for all `usize` (other than
/// a build script), I'm open!
pub unsafe trait ToBitstring {
    /// The bitstring associated with the given number. The invariant that
    /// `Self::Bitstring::UNSIGNED == N` must hold.
    type Bitstring: Bitstring;
}

#[derive(Error, Debug)]
#[error("expected slice of length {expected}, found {found}")]
pub struct BadSize {
    expected: usize,
    found: usize,
}
