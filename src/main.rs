use crate::ciphers::rsa::rsa::RSA;

mod ciphers; 
mod operation_modes;
mod utils;


fn main() {
    let message = 2u64;
    
    let cipher = RSA::new(14, 5, 11); 

    let ciphertext = cipher.encrypt_message(message);
    println!("CIPHERTEXT: {}", ciphertext);

    let decrypted = cipher.decrypt_message(ciphertext);
    println!("DECRYPTED: {}", decrypted);
    assert_eq!(decrypted, message);
}
