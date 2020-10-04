//!Safe bindings to [xxHash](https://github.com/Cyan4973/xxHash)

#![no_std]
#![warn(missing_docs)]
#![cfg_attr(feature = "cargo-clippy", allow(clippy::style))]

use xxhash_c_sys as sys;

use core::{hash, mem};

#[inline(always)]
///Calculates 32bit hash of provided `input`
///
///Optimal on 32bit targets.
pub fn xxh32(input: &[u8], seed: u32) -> u32 {
    unsafe {
        sys::XXH32(input.as_ptr() as _, input.len(), seed)
    }
}

#[inline(always)]
///Calculates 64bit hash of provided `input`
///
///Runs faster on 64bit systems, and slower on 32bit systems
pub fn xxh64(input: &[u8], seed: u64) -> u64 {
    unsafe {
        sys::XXH64(input.as_ptr() as _, input.len(), seed)
    }
}

#[inline(always)]
///Calculates 64bit hash of provided `input` using XXH3.
///
///Runs faster on 64bit systems and generally faster comparing to `xxh64`.
pub fn xxh3_64(input: &[u8]) -> u64 {
    unsafe {
        sys::XXH3_64bits(input.as_ptr() as _, input.len())
    }
}

#[inline(always)]
///Calculates 128bit hash of provided `input` using XXH3.
///
///Generally the same algorithm as 64bit version, but allowing to get 128bit output.
pub fn xxh3_128(input: &[u8]) -> u128 {
    let result = unsafe {
        sys::XXH3_128bits(input.as_ptr() as _, input.len())
    };

    (result.high64 as u128) << 64 | result.low64 as u128
}

///Streaming version of `XXH64` algorithm.
pub struct XXH64 {
    state: mem::MaybeUninit<sys::XXH64_state_t>,
}

impl XXH64 {
    #[inline]
    ///Creates uninitialized instance.
    ///
    ///It is unsafe to use any method before calling `reset`
    pub const unsafe fn uninit() -> Self {
        let state = mem::MaybeUninit::uninit();
        Self {
            state
        }
    }

    #[inline]
    ///Creates new instance.
    ///
    ///Returns `None` if `XXH64_reset` fails
    pub fn new(seed: u64) -> Self {
        let mut result = unsafe {
            Self::uninit()
        };

        result.reset(seed);

        result
    }

    #[inline]
    ///Resets hasher's state.
    pub fn reset(&mut self, seed: u64) {
        let result = unsafe { sys::XXH64_reset(self.state.as_mut_ptr(), seed) };
        debug_assert_eq!(result, sys::XXH_errorcode_XXH_OK);
    }
}

impl hash::Hasher for XXH64 {
    #[inline]
    fn finish(&self) -> u64 {
        unsafe {
            sys::XXH64_digest(self.state.as_ptr())
        }
    }

    #[inline]
    fn write(&mut self, input: &[u8]) {
        let result = unsafe {
            sys::XXH64_update(self.state.as_mut_ptr(), input.as_ptr() as _, input.len())
        };

        debug_assert_eq!(result, sys::XXH_errorcode_XXH_OK);
    }
}

impl Default for XXH64 {
    #[inline(always)]
    fn default() -> Self {
        Self::new(0)
    }
}

///Describes method to reset XXH3 algorithm state.
///
///Policies:
///- [Default](html.Xxh3DefaultReset.struct) - requires nothing and just resets using default values.
///- Seed - updates with `u64` seed.
///- Secret - updates with specified slice of bytes. It should be no less than `xxhash_c_sys::XXH3_SECRET_SIZE_MIN`
pub trait Xxh3Reset {
    ///Reset implementation
    fn reset(self, state: *mut sys::XXH3_state_t);
}

///Default reset policy.
pub struct Xxh3DefaultReset;

impl Xxh3Reset for Xxh3DefaultReset {
    fn reset(self, state: *mut sys::XXH3_state_t) {
        let result = unsafe { sys::XXH3_64bits_reset(state) };
        debug_assert_eq!(result, sys::XXH_errorcode_XXH_OK);
    }
}

impl Xxh3Reset for u64 {
    fn reset(self, state: *mut sys::XXH3_state_t) {
        let result = unsafe { sys::XXH3_64bits_reset_withSeed(state, self) };
        debug_assert_eq!(result, sys::XXH_errorcode_XXH_OK);
    }
}

impl Xxh3Reset for &'_ [u8] {
    fn reset(self, state: *mut sys::XXH3_state_t) {
        debug_assert!(self.len() >= xxhash_c_sys::XXH3_SECRET_SIZE_MIN);
        let result = unsafe { sys::XXH3_64bits_reset_withSecret(state, self.as_ptr() as _, self.len()) };
        debug_assert_eq!(result, sys::XXH_errorcode_XXH_OK);
    }
}

///Streaming version of `XXH3` 64 bit algorithm.
///
///*NOTE:* state is rather large for `XXH3` so it is advised to allocate it on heap if you plan to move it around.
pub struct XXH3_64 {
    state: mem::MaybeUninit<sys::XXH3_state_t>,
}

impl XXH3_64 {
    #[inline]
    ///Creates uninitialized instance.
    ///
    ///It is unsafe to use any method before calling `reset`
    pub const unsafe fn uninit() -> Self {
        let state = mem::MaybeUninit::uninit();
        Self {
            state
        }
    }

    #[inline]
    ///Creates new instance.
    ///
    ///Returns `None` if `XXH64_reset` fails
    pub fn new() -> Self {
        let mut result = unsafe {
            Self::uninit()
        };

        result.reset(Xxh3DefaultReset);

        result
    }

    #[inline(always)]
    ///Resets hasher's state according to specified reset policy.
    ///
    ///If `None` uses default.
    pub fn reset<R: Xxh3Reset>(&mut self, reset: R) {
        reset.reset(self.state.as_mut_ptr());
    }
}

impl hash::Hasher for XXH3_64 {
    #[inline]
    fn finish(&self) -> u64 {
        unsafe {
            sys::XXH3_64bits_digest(self.state.as_ptr())
        }
    }

    #[inline]
    fn write(&mut self, input: &[u8]) {
        let result = unsafe {
            sys::XXH3_64bits_update(self.state.as_mut_ptr(), input.as_ptr() as _, input.len())
        };

        debug_assert_eq!(result, sys::XXH_errorcode_XXH_OK);
    }
}

impl Default for XXH3_64 {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}
