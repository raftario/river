use std::sync::atomic::{AtomicU32, Ordering};

use rand::{RngCore, SeedableRng};

pub struct Lfsr24 {
    initial: u32,
    lfsr: u32,
    mask: u32,
}

pub struct AtomicXorShift32 {
    state: AtomicU32,
}

impl Lfsr24 {
    pub fn next(&mut self) -> u32 {
        let lfsr = self.lfsr - 1;
        self.lfsr = (self.lfsr >> 1) ^ (0u32.wrapping_sub(self.lfsr & 1u32) & 0xd80000);
        assert!(self.lfsr != self.initial);
        lfsr ^ self.mask
    }
}

impl SeedableRng for Lfsr24 {
    type Seed = [u8; 8];

    fn from_seed(seed: Self::Seed) -> Self {
        let s24 = |b: [u8; 4]| u32::from_le_bytes(b).saturating_add(1) & 0xffffff;

        let initial = s24([seed[0], seed[1], seed[2], seed[3]]);
        let mask = s24([seed[4], seed[5], seed[6], seed[7]]);

        Self {
            initial,
            lfsr: initial,
            mask,
        }
    }
}

impl SeedableRng for AtomicXorShift32 {
    type Seed = [u8; 4];

    fn from_seed(seed: Self::Seed) -> Self {
        Self {
            state: AtomicU32::from(u32::from_le_bytes(seed).saturating_add(1)),
        }
    }
}

impl RngCore for &AtomicXorShift32 {
    fn next_u32(&mut self) -> u32 {
        loop {
            let initial = self.state.load(Ordering::Relaxed);

            let mut state = initial;
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;

            let swap = self.state.compare_exchange_weak(
                initial,
                state,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            if swap.is_ok() {
                break state;
            }
        }
    }

    fn next_u64(&mut self) -> u64 {
        u64::from(self.next_u32()) << 32 | u64::from(self.next_u32())
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(4) {
            chunk.copy_from_slice(&self.next_u32().to_le_bytes()[..chunk.len()])
        }
    }
}
