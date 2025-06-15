use num_bigint::BigUint;
use num_integer::{gcd, ExtendedGcd, Integer};

pub struct ElGamal {
    p: u64,
    g: u64,
    x: u64,
    h: u64
}

impl ElGamal {
    pub fn new(p: u64, g: u64, x: u64) -> Self {
        Self { p, g, x, h: mod_pow_bigint(g, x, p) } 
    }

    pub fn encrypt_message(&self, m: u64, k: u64) -> (u64, u64) {
        let c1 = mod_pow_bigint(self.g, k, self.p);
        let c2 = (m * mod_pow_bigint(self.h, k, self.p)) % self.p;
        (c1, c2)
    }

    pub fn decrypt_message(&self, c1: u64, c2: u64) -> u64 {
        let z = mod_pow_bigint(c1, self.x, self.p);
        let z_inverse = mod_inverse(z, self.p).unwrap();
        (c2 * z_inverse) % self.p
    }
}

// tryes to finds the inverse of a mod n 
fn mod_inverse(a: u64, n: u64) -> Option<u64> {
    // we use the extended_gcd() from the num_integer crate to find
    // the gcd and the Bézeut coefficients between a and n
    // Bézeut coefficients => a·x + n·y = gcd(a, n)
    let ExtendedGcd { gcd, x, y: _ } = (a as i64).extended_gcd(&(n as i64));
    
    // if the GCD(a,n) != than a has no inverse mod n
    if gcd != 1 {
        None
    } else {
        // Bézeut coefficients => a·x + n·y = gcd(a, n)
        // such that x is the inverse of a mod n
        let n = n as i64;
        Some(((x % n + n) % n) as u64)
    }
}

// performs base^exp mod n using a bigint crate,
// conventient because I don't need to worry about overflows
fn mod_pow_bigint(base: u64, exp: u64, n: u64) -> u64 {
    // convert the parameters into BigUint types
    let base = BigUint::from(base);
    let exp = BigUint::from(exp);
    let n = BigUint::from(n);
    
    // perform base^exp mod n using the BigUints
    let res = base.modpow(&exp, &n);
    
    // convert the result back to u64
    res.try_into().unwrap()
}

#[test]
fn test_el_gamal_basic() {
    let message: u64 = 5;
    let cipher = ElGamal::new(19, 3, 5);
    println!("PUB KEY: (h: {}, g: {}, p: {})", cipher.h, cipher.g, cipher.p);
    
    let (c1, c2) = cipher.encrypt_message(message, 3);
    println!("Ciphertext: ({}, {})", c1, c2);

    let decrypted = cipher.decrypt_message(c1, c2);
    println!("Decrypted: {}", decrypted);
    assert_eq!(message, decrypted);
}
