# RSA

This is an educational implementation of the RSA algorithm using 64 bit numbers.

⚠️ by only using 64 bit numbers it is easily breakable and MUST NOT be used in real applications.

## Parameters

| Parameter | Range              | Description                                              |
|-----------|--------------------|----------------------------------------------------------|
| p, q      | $[2^{16},2^{30}]$  | randomly chosen prime factors of N                       |
| n         | $~[2^{40},2^{60}]$ | obtained as $p\cdot q$                                   |
| e         | 65537              | public exponent, with a commonly used value              |
| d         | $e^{-1}modn$       | private exponent, computed as the inverse of $e\ mod\ n$ |

## Key Generation Process
1. Generates two random primes numbers $p$ and $q$ in the range $[2^{16},2^{30}]$
    - using the Sieve of Eratosthenes method to determine their primality (`is_prime()` function)
    - ⚠️ only effective with small numbers (production-grade RSA implementations use Miller-Rabin)
2. $n=p\cdot q$
3. Compute Euler's totient $\Phi(n)=(p-1)(q-1)$
4. Chose the public exponent $e=65537$
    - make sure that $gcd(e, \Phi(n)) = 1$, meaning they must be **coprime**
6. Compute the private exponent $d=e^{-1}\ mod\ n$
    - using the extended Euclide's algorithm from the `num-integers` crate

## Encryption
To encrypt a message $m$ with the public key $(e, n)$:
$$c=m^e\ mod\ n$$

## Decryption
To decrypt a ciphertext $c$ with the private key $(d, n)$:
$$m=c^d\ mod\ n$$

## Dependencies
- `rand`: secure randomness generator
- `primes`: implements the Sieve of Eratosthenes method to determine the primality of a given number
- `num-integer`: implements the extended Euclide's algorithms
- `num-bigint`: adds big integers support in Rust
