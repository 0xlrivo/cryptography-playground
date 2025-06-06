/*
* A super simple block chyper implementation
* Carachteristics:
* - block size is 64 bit
* - key size is 64 bit too
* - 8 rounds
* - feistel round function:
*   0. s = block splitted in 4 chunks of 1 byte each
*   0. k = key splitted in 4 chnks of 1 byte each
*   1. s[i] XOR k[i]
*   2. s[i] << 1 without loosing information
*   3. s[i] = s[i+2] (right rotation by 2 places)
*/

use cryptography_playground::BlockCipher;

const FEISTEL_ROUNDS: usize = 8;

pub struct MiniFeistel64 {
    // currently used key
    key: u64    
}

impl BlockCipher for MiniFeistel64 {
    type Block = u64;

    fn encrypt_block(&self, block: Self::Block) -> Self::Block {
        self.feistel_encrypt_block(block)
    }

    fn decrypt_block(&self, block: Self::Block) -> Self::Block {
        self.feistel_decrypt_block(block)
    }
}

impl MiniFeistel64 {
    // initialize the cyper
    pub fn new(key: u64) -> Self {
        Self {
            key,
        }
    }

    pub fn feistel_encrypt_block(&self, p: u64) -> u64 {
        // split p into L and R
        let (mut old_l, mut old_r) = self.split_block(p);

        // compute round keys
        let round_keys = self.derive_round_keys();
        
        // for every round
        for round_number in 0..FEISTEL_ROUNDS {
            // compute this round;
            let new_l = old_r;
            let new_r = old_l ^ self.round_function(
                old_r, 
                round_keys[round_number]
            );

            // update old values for next iteration
            old_l = new_l;
            old_r = new_r;
        }
        
        // combine back l and r in reverse (final permutation)
        self.combine_block(old_r, old_l)
    }

    pub fn feistel_decrypt_block(&self, c: u64) -> u64 {
        // split c into L and R
        let (mut old_r, mut old_l) = self.split_block(c);
        
        // compute round keys
        let round_keys = self.derive_round_keys();
        
        for round_number in (0..FEISTEL_ROUNDS).rev() {
            // compute this round
            let new_r = old_l;
            let new_l = old_r ^ self.round_function(
                old_l,
                round_keys[round_number]
            );
            
            // update old values for next iteration
            old_l = new_l;
            old_r = new_r;
        }

        // combine back l and r
        self.combine_block(old_l, old_r)
    }
    
    fn round_function(&self, old_r: u32, round_key: u32) -> u32 {
        // convert old_r into an array [u8; 4]
        let mut s: [u8; 4] = old_r.to_be_bytes();
        // same for the round key
        let k: [u8; 4] = round_key.to_be_bytes();

        // phase 1 (substitution) -> s[i] XOR k[i]
        //
        for i in 0..4 {
            s[i] ^= k[i];
        }

        // phase 2 (substitution) -> left shift every bit by 1
        // rotate_left() makes sure we don't lose any bit due to shifting
        // by appending any "cut out" bit
        for i in 0..4 {
            s[i] = s[i].rotate_left(1);
        }

        // phase 3 (permutation) -> shift every chunk by 2 positions to the right
        // before:
        //  s = [s1, s2, s3, s4]
        // after
        //  s = [s3, s4, s2, s1]
        s.rotate_right(2);
        
        // return s, casted into a native-endianess u32
        u32::from_be_bytes(s)
    }
    
    // compute the round keys for all rounds
    fn derive_round_keys(&self) -> [u32; FEISTEL_ROUNDS] {
        let mut keys = [0u32; FEISTEL_ROUNDS];
        
        // super simle key derivation function that does:
        // 1) key << (round_number * 8)
        // 2) take the 32th most significant bits out
        for i in 0..FEISTEL_ROUNDS {
            let rotated = self.key.rotate_left((i * 8) as u32);
            keys[i] = (rotated >> 32) as u32
        }

        keys
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


// Demonstration of rotate_righ() for [u8; 4]
#[test]
fn test_rotate_right_u8array() {
    let number: u32 = 0xAABBCCDD;
    let mut chunks = number.to_be_bytes();
    println!("Original chunks:");
    for c in chunks {
        print!("{:x} ", c);
    }
    chunks.rotate_right(2);
    println!("\nRight-rotateed by 2 chunks:");
    for c in chunks {
        print!("{:x} ", c);
    }
}

// Demonstration of rotate_left() for a u8
// (left shift without loosing information)
#[test]
fn test_rotate_left_u8_no_loss() {
    let number: u8 = 0b11010111;
    println!("{}", number.rotate_left(1));
    println!("{}", number << 1);  // in this case you loose the MSB (1)
}
