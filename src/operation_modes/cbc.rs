use cryptography_playground::{BlockType, BlockCipher, CipherOperationMode};

pub struct CBC<C: BlockCipher> {
    pub iv: C::Block
}

impl<C: BlockCipher> CipherOperationMode<C> for CBC<C> {
    fn encrypt(&self, cipher: &C, plaintext: &[u8]) -> Vec<u8> {
        // assert that plaintext is a multiple of the cipher's block size
        assert!(
            plaintext.len() % C::Block::SIZE == 0,
            "Plaintext must be a multiple of block size"
        );
        
        let mut out = Vec::new();
        let mut prev = self.iv;
        for (_, chunk) in plaintext.chunks(C::Block::SIZE).enumerate() {
            // reconstruct i-th block from the i-th chunk
            let plain_block = C::Block::from_bytes(chunk);
            // run the encryption function on plain_block XOR prev
            let cipher_block = cipher.encrypt_block(plain_block ^ prev); 
            // update prev
            prev = cipher_block;
            // update out
            out.append(&mut cipher_block.to_bytes());
        }

        out
    } 

    fn decrypt(&self, cipher: &C, ciphertext: &[u8]) -> Vec<u8> {
        // assert that ciphertext is a multiple of the cipher's block size
        assert!(
            ciphertext.len() % C::Block::SIZE == 0,
            "Plaintext must be a multiple of block size"
        );

        let mut out = Vec::new();
        let mut prev = self.iv;
        for (_, chunk) in ciphertext.chunks(C::Block::SIZE).enumerate() {
            // reconstruct i-th block from i-th chunk
            let cipher_block = C::Block::from_bytes(chunk);
            // run decryption function on it
            let plain_block = cipher.decrypt_block(cipher_block) ^ prev;
            // update prev
            prev = cipher_block;
            // update out
            out.append(&mut plain_block.to_bytes());
        }

        out
    }
}
