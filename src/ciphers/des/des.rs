/*
* A DES implementation in pure Rust
* 
* NOTE to interpret the tables below (IP, E, S_BOX)
* - in FIPS 46-3 bits are 1-indexed
* - bit 1 is the most significant bit
*/

use std::u64;

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
        let round_keys = self.schedule_subkeys();
        self.run_feistel_network(p, &round_keys)
    }

    // decrypts a single block
    pub fn des_decrypt_block(&self, c: u64) -> u64 {
        let round_keys = self.schedule_subkeys();
        let reversed_keys: Vec<U48> = round_keys.iter().rev().copied().collect();
        self.run_feistel_network(c, &reversed_keys)
    }
    
    fn run_feistel_network(&self, block: u64, round_keys: &[U48]) -> u64 {
        // 1) apply the initial permutation and split the output
        let (mut l, mut r) = split_block(apply_initial_permutation(block, false));

        // 2) apply 16 rounds
        for i in 0..FEISTEL_ROUNDS {
            let tmp = l ^ self.round_function(expand_r(r), round_keys[i]);
            l = r;
            r = tmp;
        }

        // 3) combine back and apply the inverse of the initial permutation
        apply_initial_permutation(combine_block(r, l), true)
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
        for i in 0..FEISTEL_ROUNDS {
            // apply the specified number of left rotations for the round
            c = rotate_left_28(c, ITER_SX_SHIFT[i]);
            d = rotate_left_28(d, ITER_SX_SHIFT[i]);

            // combine c and d togheter and apply PC-2 over the result
            round_keys[i] = apply_pc2(combine_round_key(c, d));
        }

        round_keys
    }
}

#[test]
// https://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm
fn test_know_des_vector() {
    // parameters
    let key: u64 = 0x133457799BBCDFF1;
    let plaintext: u64 = 0x0123456789ABCDEF;
    let expected: u64 = 0x85E813540F0AB405;

    // encryption
    let cipher = DES::new(key);
    let ciphertext = cipher.encrypt_block(plaintext);
    assert_eq!(
        ciphertext, expected,
        "Known DES vector failed encryption"
    );

    // decryption
    let result = cipher.des_decrypt_block(ciphertext);
    assert_eq!(
        result, plaintext,
        "Known DES vector failed decryption"
    );
}
