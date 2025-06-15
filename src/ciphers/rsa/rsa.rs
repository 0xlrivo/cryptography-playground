/*
*   Simplified (and unsecure) RSA implementation in pure Rust
*
*   NOTE: for simplcity we work with u64 which isn't enough to provide
*   actual security, but this is just a toy implementation so it's fine
*/

use num_bigint::BigUint;
use num_integer::{gcd, ExtendedGcd, Integer};
use rand::Rng;
use primes::is_prime;

pub struct RSA {
    n: u64,
    e: u64,     // public exponent
    d: u64      // private exponent
}

impl RSA {
    // initialize the cypher with the provided keypair
    pub fn new(n: u64, e: u64, d: u64) -> Self {
        Self { n, e, d }
    }

    // initialize the cypher by generating a new keypair
    pub fn gen_keypair() -> Self {
        // 1. generate a p in [2^16, 2^20]
        let p = gen_prime_number_range(1u64 << 16, 1u64 << 20);
        // 2. generate a q in [2^16, 2^20]
        let q = gen_prime_number_range(1u64 << 16, 1u64 << 20);
        
        // 3. compute n = p x q
        let n = p * q;

        // 4. compute phi(n)
        let phi_n = (p-1) * (q-1);

        // 5. chose e
        // commonly used value of 65537
        let e = 65537;
        // make sure it is coprime with phi
        assert_eq!(gcd(e, phi_n), 1, "e is not coprime with phi_n");

        // 6. chose d as e^-1 mod phi
        // panics if e has no inverse mod phi
        let d = mod_inverse(e, phi_n).unwrap();

        Self { n, e, d }
    }
    
    // outputs the cyphertext for the provided message
    pub fn encrypt_message(&self, m: u64) -> u64 {
        mod_pow_bigint(m, self.e, self.n)
    }

    pub fn decrypt_message(&self, c: u64) -> u64 {
        mod_pow_bigint(c, self.d, self.n)
    }
}

// utility function to generate a random prime number
// in a given range
fn gen_prime_number_range(low: u64, high: u64) -> u64 {
    // reference to a secure randomness generator
    let mut rng = rand::rng();
    
    loop {
        // generate an odd number within the range [low, high]
        // we can skip even numbers because they all have 2 as a factor
        let c = rng.random_range(low..=high) | 1;
        
        // make sure such number is prime using Sieve method
        // that enumerates every prime number in [2, sqrt(c)]
        // NOTE: simpler because I'm working with u64
        // but real 2048 bit RSA implementations use Miller-Rabin
        if is_prime(c) {
            return c;
        }
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
fn test_keypair_gen() {
    let cipher = RSA::gen_keypair();
    println!("PUB: (e: {}, n: {})", cipher.e, cipher.n);
    println!("PRIV: (d: {}, n: {})", cipher.d, cipher.n);

    let message = 2;
    let ciphertext = cipher.encrypt_message(message);
    println!("Ciphertext: {}", ciphertext);
    let decryped = cipher.decrypt_message(ciphertext);
    println!("Decrypted: {}", decryped);
    assert_eq!(message, decryped, "decryption failed");
}

#[test]
fn test_rsa_known_params() {
    const RSA_TEST_PAIRS: [(u64, u64, u64, u64, u64, u64); 9] = [
        // φ(n) = 40 (p=5, q=11, so n=55)
        (5, 11, 55, 40, 3, 27),   // 3×27 = 81 ≡ 1 mod 40
        (5, 11, 55, 40, 7, 23),   // 7×23 = 161 ≡ 1 mod 40
        (5, 11, 55, 40, 9, 9),    // 9×9 = 81 ≡ 1 mod 40
    
        // φ(n) = 60 (p=7, q=11, so n=77)
        (7, 11, 77, 60, 7, 43),   // 7×43 = 301 ≡ 1 mod 60
        (7, 11, 77, 60, 11, 11),  // 11×11 = 121 ≡ 1 mod 60
        (7, 11, 77, 60, 13, 37),  // 13×37 = 481 ≡ 1 mod 60
    
        // φ(n) = 120 (p=11, q=13, so n=143)
        (11, 13, 143, 120, 7, 103),  // 7×103 = 721 ≡ 1 mod 120
        (11, 13, 143, 120, 11, 11),  // 11×11 = 121 ≡ 1 mod 120
        (11, 13, 143, 120, 17, 113), // 17×113 = 1921 ≡ 1 mod 120
    ];
    
    let message = 2;
    for (_, _, n, _, e, d) in RSA_TEST_PAIRS {
        let cipher = RSA::new(n, e, d);
        let ciphertext = cipher.encrypt_message(message);
        println!("M={} with e={} n={} => {}", message, e, n, ciphertext);
        let decrypted = cipher.decrypt_message(ciphertext);
        assert_eq!(decrypted, message);
    }
}
