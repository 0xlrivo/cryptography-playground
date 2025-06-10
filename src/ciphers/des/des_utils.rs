use crate::ciphers::des::des_constants::*;

// takes a 64 bit DES block and permutates it using IP or IP^-1 if inverse if false
pub fn apply_initial_permutation(input: u64, inverse: bool) -> u64 {
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

// takes a 64 bit DES key and compress it into a 56 bit key
// by removing the 8 parity bits
pub fn apply_pc1(key: u64) -> U56 {
    let mut out: U56 = 0;
    
    //       i: bit position (0-indexed) in the output number
    // src_pos: bit position (1-indexed) in the PC1 matrix to take from key 
    for (i, &src_pos) in PC1.iter().enumerate() {
        // extract the src_pos th bit from the input key 
        let src_bit = (key >> (64 - src_pos)) & 0x1;
        
        // add it to the output
        // NOTE: in DES standard the bit in position 1 is the MSB
        out |= src_bit << (55 - i);
    }
    
    out
}

// takes a 56 bit DES key and compress it into a 48 bit round key
pub fn apply_pc2(key: U56) -> U48 {
    let mut out: U48 = 0;
    
    for (i, &src_pos) in PC2.iter().enumerate() {
        // extract the src_pos th bit from the input key
        let src_bit = (key >> (56 - src_pos)) & 0x1;

        // add it to the output
        // NOTE: in DES standard the bit in positin 1 is the MSB
        out |= src_bit << (47 - i);
    }
    out
}

// takes a 32 bit number and permutates it using the P table
pub fn apply_p(input: u32) -> u32 {
    let mut out = 0u32;

    for (i, &src_pos) in P.iter().enumerate() {
        let src_bit = (input >> (32 - src_pos)) & 0x1;
        out |= src_bit << (31 - i);
    }
    out
}

// takes a 32 bit r and expands it to a 48 bit number using the E table
pub fn expand_r(r: u32) -> U48 {
    let mut out: U48 = 0;
        
    //       i: bit position (0-indexed) in the output number
    // src_pos: bit position (1-indexed) in the E matrix
    for (i, &src_pos) in E.iter().enumerate() {
        // extract the src_pos th bit from the source r number 
        // NOTE: the E table is 1-index, that's why 32 - src_pos
        let src_bit = (r >> (32 - src_pos)) & 0x1;

        // add it to the output number
        out |= (src_bit as U48) << (47 - i);
    }
    out
}

// takes a 6 bit input (6 LSB of the u8) and returns a 4 bit output
pub fn query_s_box(idx: usize, input: u8) -> u8 {
    // row is byte 5th and 0th
    let row = ((input & 0x20) >> 4) | (input & 0x1);
    // col are bytes 4th, ..., 1th
    let col = (input >> 1) & 0x0F;
     
    SBOXES[idx][row as usize][col as usize]
}

// splits a 64 bit number into two 32 bit halves
pub fn split_block(block: u64) -> (u32, u32) {
    let high: u32 = (block >> 32) as u32;
    let low: u32 = (block & 0xFFFFFFFF) as u32;
    (high, low)
}

// splits a 56 bit key into two 28 bit halves
pub fn split_key(key: U56) -> (U28, U28) {
    let high = (key >> 28) as U28;
    let low = (key & 0xFFFFFFF) as u32;
    (high, low)
}

// combines two 32 bit halves into a single 64 bit number
pub fn combine_block(high: u32, low: u32) -> u64 {
    ((high as u64) << 32) | (low as u64)
}

// combines two 28 bit halves into a single 56 bit number
pub fn combine_round_key(high: U28, low: U28) -> U56 {
    ((high as U56) << 28) | (low as U56)
}

// extracts the 6 bit input for the specified S-Box index
// NOTE: the S1 takes the 6 most significant bits
pub fn extract_sbox_input(idx: usize, input: U48) -> u8 {
    assert!(idx < 8, "invalid S-box index");
    // TODO: not sure if correct
    (input >> (43 - idx)) as u8
}

// takes a 4 bit output from an S-box and pads it
// in their combined 32 bit output
pub fn pad_sbox_output(sb_idx: usize, sb_out: u8) -> u32 {
    assert!(sb_idx < 8, "invalid S-box index");
    // TODO: not sure if correct
    (sb_out as u32) << (28 - (sb_idx * 4))
}

// Unit Tests
#[test]
fn test_apply_ip_works() {
    let input = 0x0123456789ABCDEF;
    let expected = 0xCC00CCFFF0AAF0AA;
    assert_eq!(apply_initial_permutation(input, false), expected, "Wrong IP");
    assert_eq!(apply_initial_permutation(expected, true), input, "Wrong IP^-1");
}

#[test]
fn test_apply_pc1_works() {
    let key = 0x133457799BBCDFF1u64;
    let expected: U56 = 0xF0CCAAF55668F;
    let compressed = apply_pc1(key);
    println!("0x{:014X}", compressed);
    assert_eq!(compressed, expected);
}
