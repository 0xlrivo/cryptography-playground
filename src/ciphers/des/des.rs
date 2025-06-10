/*
* A DES implementation in pure Rust
* 
* NOTE to interpret the tables below (IP, E, S_BOX)
* - in FIPS 46-3 bits are 1-indexed
* - bit 1 is the most significant bit
*/

use cryptography_playground::BlockCipher;
use crate::ciphers::des::des_constants::*;
use crate::ciphers::des::des_utils::*;

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
        let mut out = apply_initial_permutation(p, false);

        // 2. compute all the round keys
        let round_keys = self.schedule_subkeys();

        // 3. split it into two halves 32 bit blocks for the feistel net
        let (mut old_l, mut old_r) = split_block(out);

        // 4. apply 16 feistel rounds
        for round_number in 0..FEISTEL_ROUNDS {
            // compute this round
            let new_l = old_r;
            let new_r = old_l ^ self.round_function(
                expand_r(old_r),                        // expand r to 48 bits
                round_keys[round_number]            // current round's key
            );

            // update old values for next round
            old_l = new_l;
            old_r = new_r;
        }
        
        // 5. combine back L and R
        out = combine_block(old_r, old_l);

        // 6. return IP^-1(out)
        apply_initial_permutation(out, true)
    }

    // decrypts a single block
    pub fn des_decrypt_block(&self, c: u64) -> u64 {
        unimplemented!()
    }
    
    // round function
    // old_r: already expanded 32 bit r using the E matrix
    // round_key: the round key for this round
    fn round_function(&self, old_r: U48, round_key: U48) -> u32 {
        let mut out = 0u32;

        // 1. r XOR round_key
        let e: U48 = old_r ^ round_key;

        // 2. apply the s-boxes
        for sb_number in 0..8 {
            // extract the input for this S-box
            let sb_input = extract_sbox_input(sb_number, e);
            // run this S-Box
            let sb_output = query_s_box(sb_number, sb_input);
            // put the sb_output in the corret position
            out |= pad_sbox_output(sb_number, sb_output);
        }

        // 3. return the s-boxes result
        apply_p(out)
    }

    // key scheduler
    fn schedule_subkeys(&self) -> [U48; FEISTEL_ROUNDS] {
        let mut round_keys = [0u64; 16];

        // 1. apply PC-1 to convert self.key into a 56 bit key
        let key = apply_pc1(self.key);

        // 2. split the key into two 28 bit halves
        let (mut c, mut d) = split_key(key);
        
        // 3. compute the 48 bit round key for all 16 rounds
        for round_number in 0..FEISTEL_ROUNDS {
            // apply the specified number of left rotations for the round
            c = c.rotate_left(ITER_SX_SHIFT[round_number]);
            d = d.rotate_left(ITER_SX_SHIFT[round_number]);

            // combine c and d togheter and apply PC-2 over the result
            round_keys[round_number] = apply_pc2(combine_round_key(c, d));
        }

        round_keys
    }
}
