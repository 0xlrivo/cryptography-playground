use cryptography_playground::{BlockType, BlockCipher, CipherOperationMode};

pub struct ECB;

impl<C:BlockCipher> CipherOperationMode<C> for ECB {
    fn encrypt(&self, cipher: &C, plaintext: &[u8]) -> Vec<u8> {
        // assert that plaintext is a multiple of the cipher's block size
        assert!(
            plaintext.len() % C::Block::SIZE == 0, 
            "Plaintext must be a multiple of block size"
        );
        
        // .chunks() -> returns an iterator over plaintext splitted in [u8; C::BLOCK::SIZE]
        // .map() -> applies the encryption function to each block
        // .flatten() -> returns an iterator that merges toghether all the Vec<8> returned by the map()
        // .collect() -> turns such iterator into a collection of type Vec<u8>
        plaintext
            .chunks(C::Block::SIZE)
            .map(|chunk| {
                // convert the chunk (of type [u8; block_size]) to block_size (es: u64, u128)
                let plain_block = C::Block::from_bytes(chunk);
                // encrypts the block and converts it back to a Vec<u8>
                cipher.encrypt_block(plain_block).to_bytes()
            })
            .flatten()
            .collect()
    }

    fn decrypt(&self, cipher: &C, ciphertext: &[u8]) -> Vec<u8> {
        // assert that ciphertext is a multiple of cipher's block size
        assert!(
            ciphertext.len() % C::Block::SIZE == 0,
            "Ciphertext must be a multiple of block size"
        );
        
        ciphertext
            .chunks(C::Block::SIZE)
            .map(|chunk| {
                let cipher_block = C::Block::from_bytes(chunk);
                cipher.decrypt_block(cipher_block).to_bytes()
            })
            .flatten()
            .collect()
    }
}
