mod minifeistel64;
use minifeistel64::MiniFeistel64;
use cryptography_playground::{ascii_str_to_u64_blocks, vec_u64_blocks_to_ascii_str, BlockCipher};

fn main() {
    let cipher = MiniFeistel64::new(0x1234567890abcdef);
    let message = "ABCDEFGHabcdefgh";
    let plaintext = ascii_str_to_u64_blocks(message);
    
    let ciphertext = ecb_encrypt(&cipher, &plaintext);
    let decrypted = ecb_decrypt(&cipher, &ciphertext);

    println!("Got message: {}", vec_u64_blocks_to_ascii_str(&decrypted));
}

fn ecb_encrypt<C: BlockCipher>(cipher: &C, plain_blocks: &[C::Block]) -> Vec<C::Block> {
    plain_blocks.iter().map(|b| cipher.encrypt_block(*b)).collect()
}

fn ecb_decrypt<C: BlockCipher>(cipher: &C, cipher_blocks: &[C::Block]) -> Vec<C::Block> {
    cipher_blocks.iter().map(|b| cipher.decrypt_block(*b)).collect()
}

#[test]
fn test_minifeistel64_single_block() {
    let cipher = MiniFeistel64::new(0x1234567890abcdef);
    let message = "ABCDEFGH";
    let plaintext = ascii_str_to_u64_blocks(message)[0];
    let ciphertext = cipher.feistel_encrypt_block(plaintext);
    let decrypted = cipher.feistel_decrypt_block(ciphertext);
    
    println!("Message\t{}", message);
    println!("Plaintext\t0x{:X}", plaintext);
    println!("Ciphertext\t0x{:X}", ciphertext);
    println!("Decypted\t0x{:X}", decrypted);
    println!("Got message: {}", vec_u64_blocks_to_ascii_str(&vec![decrypted]));

    assert!(plaintext == decrypted);
}
