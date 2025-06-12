mod ciphers; 
mod operation_modes;
mod utils;

use cryptography_playground::{BlockCipher, CipherOperationMode};
use crate::{ciphers::des::des::DES, operation_modes::cbc::CBC};

fn main() {
    // message
    let message = "ABCDEFGH12345678AAAAAAAA";
    
    // DES cipher 
    let des = DES::new(0x133457799BBCDFF1);
    
    // CBC operation mode
    let cbc = CBC::<DES>{
        iv: 0xFF
    };

    // encryption
    let ciphertext = cbc.encrypt(&des, message.as_bytes());
    println!("Got ciphertext: {}", String::from_utf8_lossy(ciphertext.clone().as_slice()));

    // decryption
    let decrypted = cbc.decrypt(&des, ciphertext.as_slice());
    let result = String::from_utf8(decrypted).expect("Invalid UTF-8");
    println!("Got message: {}", result);
    assert_eq!(message, result, "wrong decryption");
}
