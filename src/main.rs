mod ciphers; 
mod operation_modes;
mod utils;
use ciphers::minifeistel64::MiniFeistel64;
use cryptography_playground::CipherOperationMode;
use crate::operation_modes::{cbc::CBC};

fn main() {
    // message that we want to encrypt
    let message = "Ciao mondo!!!!!!";
    println!("Plain text: {:?}", Vec::from(message));

    // define the cipher to use 
    let cipher = MiniFeistel64::new(0x1234567890abcdef);

    // encrypt it using CBC mode
    let cbc = CBC{
        iv: 0xFFFFFFFFFFFFFFFF
    };
    let ciphertext = cbc.encrypt(&cipher, message.as_bytes());
    println!("Ciphertext: {:?}", ciphertext);

    // decrypt it using CBC mode 
    let decrypted = cbc.decrypt(&cipher, ciphertext.as_slice());
    println!("Decrypted text: {:?}", decrypted);
    assert!(message.as_bytes() == decrypted, "Decryption failed");
    println!("Decrypted message: {}", String::from_utf8(decrypted).expect("invalid UTF-8"));
}
