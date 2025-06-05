mod ciphers; 
mod operation_modes;
mod utils;
use ciphers::minifeistel64::MiniFeistel64;
use cryptography_playground::CipherOperationMode;

use crate::operation_modes::ecb::ECB;

fn main() {
    // message that we want to encrypt
    let message = "Ciao mondo!!!!!!";
    println!("Plain text: {:?}", Vec::from(message));

    // define the cipher to use 
    let cipher = MiniFeistel64::new(0x1234567890abcdef);

    // encrypt it using ECB mode
    let ciphertext = ECB.encrypt(&cipher, message.as_bytes());
    println!("Ciphertext: {:?}", ciphertext);

    // decrypt it using ECB mode 
    let decrypted = ECB.decrypt(&cipher, ciphertext.as_slice());
    println!("Decrypted text: {:?}", decrypted);
    println!("Decrypted message: {}", String::from_utf8(decrypted).expect("invalid UTF-8"));
}
