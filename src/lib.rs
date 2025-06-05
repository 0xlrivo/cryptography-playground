// general trait for a Block
// that abstracts away operations on u16,u32,u64,u128
pub trait BlockType: Copy + Sized {
    // byte size of the underlying type
    const SIZE: usize;

    // converts a bytes array into this block
    fn from_bytes(bytes: &[u8]) -> Self;

    // converts this block into an array of bytes
    fn to_bytes(&self) -> Vec<u8>;
}

impl BlockType for u64 {
    const SIZE: usize = 8;

    fn from_bytes(bytes: &[u8]) -> Self {
        assert!(bytes.len() == 8, "Not an u64");
        let mut tmp = [0u8; 8];
        tmp.copy_from_slice(bytes);
        u64::from_be_bytes(tmp)
    }

    fn to_bytes(&self) -> Vec<u8> {
        self.to_be_bytes().to_vec()
    }
}

// general trait for a BlockCipher
pub trait BlockCipher {
    // implementations can define the size (es: DES u64)
    type Block: BlockType;
    
    // takes a plain block and outputs a cipher block
    fn encrypt_block(&self, block: Self::Block) -> Self::Block;

    // takes a cipher block and outputs a plain block
    fn decrypt_block(&self, block: Self::Block) -> Self::Block;
}

// general trait for a Cipher Operation Mode (ECB, CBC, ...)
// that wraps a BlockCipher
pub trait CipherOperationMode<C: BlockCipher> {
    // encrypt some plaintext bytes using the provided cipher
    fn encrypt(&self, cipher: &C, plaintext: &[u8]) -> Vec<u8>;
    
    // decrypt some ciphertext bytes using the provided cipher
    fn decrypt(&self, cipher: &C, ciphertext: &[u8]) -> Vec<u8>;
}
