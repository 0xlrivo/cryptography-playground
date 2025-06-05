// utility function to convert a string to a Vec<u64> of big-endian blocks
/*
pub fn ascii_str_to_u64_blocks(s: &str) -> Vec<u64> {
    assert!(s.is_ascii(), "Only ASCII strings are supported!");
    // convert the string in a bytes array
    let bytes = s.as_bytes();
    // initialize the blocks vector
    let mut blocks = Vec::new();
    
    // iterate over 8 bytes chunks
    for chunk in bytes.chunks(8) {  // TODO: add padding
        let mut block = [0u8; 8];
        for i in 0..8 {
            block[i] = chunk[i];
        }
        // from_be_bytes is necessary for compatibility
        blocks.push(u64::from_be_bytes(block));
    }

    blocks
}

// utility function to convert a Vec<u64> of blocks into a String
pub fn vec_u64_blocks_to_ascii_str(blocks: &[u64]) -> String {
    // 1. convert the u64 array into an u8 array
    let mut bytes = Vec::new();
    for &block in blocks {
        bytes.extend_from_slice(&block.to_be_bytes());
    }

    String::from_utf8(bytes).expect("Invalid ASCII")
}

#[test]
fn test_conversions() {
    let plaintext = String::from("ABCDEFGH");
    let blocks = ascii_str_to_u64_blocks(&plaintext);
    assert!(plaintext == vec_u64_blocks_to_ascii_str(&blocks));
}
*/
