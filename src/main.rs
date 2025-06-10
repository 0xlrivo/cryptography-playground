mod ciphers; 
mod operation_modes;
use cryptography_playground::{BlockCipher};
use crate::{ciphers::des::des::DES};

fn main() {
    // define the cipher to use 
    let cipher = DES::new(0x133457799BBCDFF1);
    
    let ciphertext = cipher.encrypt_block(0x0123456789ABCDEF);
    println!("{:016X}", ciphertext);

    assert!(ciphertext == 0x85E813540F0AB405, "Non compliant");
}
