/*
* A DES implementation in pure Rust
*/

use cryptography_playground::BlockCipher;

// TODO: overkill, rewrite this using u64 and then manually extract lower 48 bits
// 48 bit unsigned integer
type U48 = [u8; 6];

// the initial permutation table as defined by FIPS 46-3
const IP: [u8; 64] = [
    58, 50, 42, 34, 26, 18, 10,  2,
    60, 52, 44, 36, 28, 20, 12,  4,
    62, 54, 46, 38, 30, 22, 14,  6,
    64, 56, 48, 40, 32, 24, 16,  8,
    57, 49, 41, 33, 25, 17,  9,  1,
    59, 51, 43, 35, 27, 19, 11,  3,
    61, 53, 45, 37, 29, 21, 13,  5,
    63, 55, 47, 39, 31, 23, 15,  7,
];

// the inverse of the initial permutation function table
const IPinverse: [u8; 64] = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25, 
];

// table used to expand a 32 bit r into a 48 bit r inside the round function
const E: [u8; 48] = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1, 
];

// SBox parameters taken from the official FIPS 46-3
const S_BOX: [u8; 64] = [
    14,  4, 13, 1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7, 
     0, 15,  7, 4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
     4,  1, 14, 8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0, 
    15, 12,  8, 2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
];

pub struct DES {
    // currently used key
    key: u64
}

impl BlockCipher for DES {
    type Block = u64;

    fn encrypt_block(&self, block: Self::Block) -> Self::Block {
        self.des_encrypt_block(block)
    }

    fn decrypt_block(&self, block: Self::Block) -> Self::Block {
        self.des_decrypt_block(block)
    }
}

impl DES {
    // initialize the cipher
    pub fn new(key: u64) -> Self {
        Self { key }
    }

    // change the secret key to use
    pub fn change_key(&mut self, new_key: u64) {
        self.key = new_key;
    }

    // encrypts a single bloc
    pub fn des_encrypt_block(&self, p: u64) -> u64 {
        // 1. IP (initial permutation)
        let mut out = self.apply_initial_permutation(p, false);

        // 2. split it into two halves 32 bit blocks for the feistel net
        let (mut old_l, mut old_r) = self.split_block(out);

        // 3. apply 16 feistel rounds
        for round_number in 0..16 {
            // compute this round
            let new_l = old_r;
            let new_r = old_l ^ self.round_function(
                self.expand_r(old_r),
                [1, 2, 3, 4, 5, 6]
            );

            // update old values for next round
            old_l = new_l;
            old_r = new_r;
        }
        
        // 4. combine back L and R
        out = self.combine_block(old_r, old_l);

        // 5. return IP^-1(out)
        self.apply_initial_permutation(out, true)
    }

    // decrypts a single block
    pub fn des_decrypt_block(&self, c: u64) -> u64 {
        unimplemented!()
    }
    
    // round keys are 48 bit of size
    fn round_function(&self, old_r: U48, round_key: U48) -> u32 {
        unimplemented!()
    }

    // takes a 64 bit DES block and permutates it using IP or IP^-1 if inverse if false
    fn apply_initial_permutation(&self, input: u64, inverse: bool) -> u64 {
        // select which IP table to use (IP or IP^-1) based on the value of inverse
        let ip_table = if inverse { IPinverse } else { IP };
        // output
        let mut out = 0u64;
        // loop through the chosen IP table
        for (i, &src_pos) in ip_table.iter().enumerate() {
            // extract the corresponding bit from the source input
            // NOTE: the IP tables are 1-indexed, that why 64 - src_pos
            let src_bit = (input >> (64 - src_pos)) & 0x1;
            // add it to the output
            out |= src_bit << (63 - i);
        }
        out
    }

    // takes a 32 bit r and expands it to a 48 bit number using the E table
    fn expand_r(&self, r: u32) -> U48 {
        let mut out = [0u8; 6];
        
        // i: bit position in the output number
        // src_pos: bit position 1-indexed in the E matrix
        for (i, &src_pos) in E.iter().enumerate() {
            // extract the i-th bit from the source r (0-indexed)
            // NOTE: the E table is 1-index, that's why 32 - src_pos
            let src_bit = (r >> (32 - src_pos)) & 0x1;
            // add it to the output
            // NOTE out[5] are the 8 most significant bits
            let mut j = 0;
            match i {
                0..=7 => { j = 0 }
                8..=15 => { j = 1 }
                16..=23 => { j = 2 }
                24..=31 => { j = 3 }
                32..=39 => { j = 4 }
                40..=48 => { j = 5 }
                _ => { panic!("Invalid position in expand_r"); }
            }
            out[j] |= (src_bit as u8) << 7 - (i % 8);
        }
        out
    }

    fn query_s_box(&self) {
        todo!();
    }

    // splits a 64 bit block into two 32 bit halves
    fn split_block(&self, block: u64) -> (u32, u32) {
        let high: u32 = (block >> 32) as u32;
        let low: u32 = (block & 0xFFFFFFFF) as u32;
        (high, low)
    }

    // combines two 32 bit halves into a single 64 bit block
    fn combine_block(&self, high: u32, low: u32) -> u64 {
        ((high as u64) << 32) | (low as u64)
    }

}
