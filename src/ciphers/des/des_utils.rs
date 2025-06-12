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
        if (input >> (64 - src_pos)) & 0x1 == 1 {
            out |= 1 << (63 - i);
        }
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
        if (key >> (64 - src_pos)) & 0x1 == 1 {
            out |= 1 << (55 - i)
        };
    }
    
    out
}

// takes a 56 bit DES key and compress it into a 48 bit round key
pub fn apply_pc2(key: U56) -> U48 {
    let mut out: U48 = 0;
    
    for (i, &src_pos) in PC2.iter().enumerate() {
        if (key >> (56 - src_pos)) & 0x1 == 1 {
            out |= 1 << (47 - i);
        }
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
        if (r >> (32 - src_pos)) & 0x1 == 1 {
            out |= 1 << (47 - i);
        }
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
    ((input >> (42 - 6 * idx)) & 0b111111) as u8
}

// takes a 4 bit output from an S-box and pads it
// in their combined 32 bit output
pub fn pad_sbox_output(sb_idx: usize, sb_out: u8) -> u32 {
    assert!(sb_idx < 8, "invalid S-box index");
    (sb_out as u32) << (28 - (sb_idx * 4))
}

// val: 28 bit number to rotate
// n: number of left rotations
pub fn rotate_left_28(val: U28, n: u32) -> U28 {
    let n = n % 28;
    let mask = 0x0FFFFFFF; // lower 28 bits
    let value = val & mask;

    ((value << n) | (value >> (28 - n))) & mask
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
    use crate::utils::*;
    
    // 64 bit key
    let key = 0b00010011_00110100_01010111_01111001_10011011_10111100_11011111_11110001;
    // 56 bit compressed key
    let expected = 0b1111000_0110011_0010101_0101111_0101010_1011001_1001111_0001111;
    let result = apply_pc1(key);
    assert_eq!(
        result, expected,
        "PC1 failed. Expected 0x{:014X}, Got 0x{:014X}", expected, result 
    );

    println!("Logical bit dump (MSB -> LSB) of result:");
    logical_dump_bits_u64(result);
}

#[test]
// E is the expansion function that takes a 32 bit into a 48 bit
fn test_expand_r_works() {
    use crate::utils::*;
    
    let r: u32 = 0b11110000101010101111000010101010;
    let expected: U48 = 0b011110100001010101010101011110100001010101010101;
    let result = expand_r(r);
    assert_eq!(
        result, expected,
        "Expansion of r failed. Expected 0x{:012X}, Got 0x{:012X}", expected, result
    );
    
    logical_dump_bits_u64(result);
}

#[test]
fn test_key_scheduling_correct() {
    use crate::utils::*;
   
    let key = 0x133457799BBCDFF1u64; 

    // PC-1
    let pc1 = apply_pc1(key);
    println!("PC1 logical bits (MSB->LSB):");
    logical_dump_bits_u64(key);
    
    // TEST TABLE WITH EXPECTED C1-C16 VALUES
    const C: [u32; 16] = [
        0b1110000110011001010101011111,  // C1
        0b1100001100110010101010111111,  // C2
        0b0000110011001010101011111111,  // C3
        0b0011001100101010101111111100,  // C4
        0b1100110010101010111111110000,  // C5
        0b0011001010101011111111000011,  // C6
        0b1100101010101111111100001100,  // C7
        0b0010101010111111110000110011,  // C8
        0b0101010101111111100001100110,  // C9
        0b0101010111111110000110011001,  // C10
        0b0101011111111000011001100101,  // C11
        0b0101111111100001100110010101,  // C12
        0b0111111110000110011001010101,  // C13
        0b1111111000011001100101010101,  // C14
        0b1111100001100110010101010111,  // C15
        0b1111000011001100101010101111,  // C16
    ];
    
    // TEST TABLE OF EXPECTED D1=D16 VALUES
    const D: [u32; 16] = [
        0b1010101011001100111100011110,  // D1
        0b0101010110011001111000111101,  // D2
        0b0101011001100111100011110101,  // D3
        0b0101100110011110001111010101,  // D4
        0b0110011001111000111101010101,  // D5
        0b1001100111100011110101010101,  // D6
        0b0110011110001111010101010110,  // D7
        0b1001111000111101010101011001,  // D8
        0b0011110001111010101010110011,  // D9
        0b1111000111101010101011001100,  // D10
        0b1100011110101010101100110011,  // D11
        0b0001111010101010110011001111,  // D12
        0b0111101010101011001100111100,  // D13
        0b1110101010101100110011110001,  // D14
        0b1010101010110011001111000111,  // D15
        0b0101010101100110011110001111,  // D16
    ];

    // TEST TABLE OF EXPECTED K1-K16 VALUES
    const K: [u64; 16] = [
        0b000110110000001011101111111111000111000001110010,
        0b011110011010111011011001110110111100100111100101,
        0b010101011111110010001010010000101100111110011001,
        0b011100101010110111010110110110110011010100011101,
        0b011111001110110000000111111010110101001110101000,
        0b011000111010010100111110010100000111101100101111,
        0b111011001000010010110111111101100001100010111100,
        0b111101111000101000111010110000010011101111111011,
        0b111000001101101111101011111011011110011110000001,
        0b101100011111001101000111101110100100011001001111,
        0b001000010101111111010011110111101101001110000110,
        0b011101010111000111110101100101000110011111101001,
        0b100101111100010111010001111110101011101001000001,
        0b010111110100001110110111111100101110011100111010,
        0b101111111001000110001101001111010011111100001010,
        0b110010110011110110001011000011100001011111110101,
    ];

    // split into C0 and D0
    let (c0, d0) = split_key(pc1);
    assert_eq!(c0, 0b1111000011001100101010101111, "C0 failed");
    assert_eq!(d0, 0b0101010101100110011110001111, "D0 failed");
    println!("C0 logical bits (MSB->LSB):");
    logical_dump_bits_u28(c0);
    println!("D0 logical bits (MSB->LSB):");
    logical_dump_bits_u28(d0);
    
    // assert that rotations are correctly performed
    let mut c = c0;
    let mut d = d0;
    for i in 0..16 {
        c = rotate_left_28(c, ITER_SX_SHIFT[i]); 
        d = rotate_left_28(d, ITER_SX_SHIFT[i]);
        assert_eq!(c, C[i], "wrong C{}", i+1);
        assert_eq!(d, D[i], "wrond D{}", i+1);
        
        // compute the actual subkey
        let sub_key = apply_pc2(combine_round_key(c, d));
        assert_eq!(sub_key, K[i]);
        println!("round key {}:", i+1);
        logical_dump_bits_u64(sub_key);
    }
}
