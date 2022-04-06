//#![deny(warnings)]
#![warn(missing_docs)]
//! RSA crypto library.

use num_bigint::BigUint;
use serde::{Deserialize, Serialize};

/// Number of bits in modulus, aka "RSA key width": 2048
pub const KEY_LENGTH_2048: usize = 2048;
/// Number of bits in modulus, aka "RSA key width": 3076
pub const KEY_LENGTH_3076: usize = 3076;
/// Number of bits in modulus, aka "RSA key width": 4096
pub const KEY_LENGTH_4096: usize = 4096;
/// Largest known Fermat prime (F_4). Used as public exponent.
const FERMAT_F4: u32 = 65537;

/// RSA private key
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Key {
    /// Modulus
    #[serde(with = "oyster::biguint_format")]
    pub n: BigUint,
    /// Public exponent
    #[serde(with = "oyster::biguint_format")]
    pub e: BigUint,
    /// Private exponent
    #[serde(with = "oyster::biguint_format")]
    pub d: BigUint,
    /// A prime
    #[serde(with = "oyster::biguint_format")]
    pub p: BigUint,
    /// A prime
    #[serde(with = "oyster::biguint_format")]
    pub q: BigUint,
    /// Some value
    #[serde(with = "oyster::biguint_format")]
    pub dp: BigUint,
    /// Some value
    #[serde(with = "oyster::biguint_format")]
    pub dq: BigUint,
    /// Some value
    #[serde(with = "oyster::biguint_format")]
    pub qinv: BigUint,
}

/// RSA public key
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicKey {
    /// Modulus
    #[serde(with = "oyster::biguint_format")]
    pub n: BigUint,
    /// Public exponent
    #[serde(with = "oyster::biguint_format")]
    pub e: BigUint,
}

impl PublicKey {
    /// New public key from private key
    pub fn from_private_key(key: &Key) -> Self {
        PublicKey {
            n: key.n.clone(),
            e: key.e.clone(),
        }
    }
}

/// New random private key
pub fn generate_key(key_bits_in_n: usize) -> Key {
    let e = BigUint::from(FERMAT_F4);
    loop {
        let (p, q) = generate_p_q_pair(key_bits_in_n);
        if let Ok(key) = generate_key_from_p_q_e(&p, &q, &e) {
            return key;
        }
    }
}

fn generate_key_from_p_q_e(p: &BigUint, q: &BigUint, e: &BigUint) -> Result<Key, String> {
    use num_integer::Integer;

    let n = compute_n(p, q);
    let lambda = compute_lambda_of_n(p, q); // carmichael-lambda: λ(n) = lcm(p-1, q-1)

    if lambda.is_multiple_of(e) {
        Err("lambda is multiple of e".to_string())
    } else if !(e < &lambda) {
        Err("e is smaller than lambda".to_string())
    } else {
        let d = compute_d(&e, &lambda);
        let dp = compute_dp(&d, &p);
        let dq = compute_dq(&d, &q);
        let qinv = compute_qinv(&p, &q);
        Ok(Key {
            n,
            e: e.clone(),
            d,
            p: p.clone(),
            q: q.clone(),
            dp,
            dq,
            qinv,
        })
    }
}

fn compute_n(p: &BigUint, q: &BigUint) -> BigUint {
    p * q
}

// carmichael-lambda: λ(n) = lcm(p-1, q-1)
fn compute_lambda_of_n(p: &BigUint, q: &BigUint) -> BigUint {
    use num_integer::Integer;
    use num_traits::One;
    let pm = p - BigUint::one();
    let qm = q - BigUint::one();
    pm.lcm(&qm)
}

fn compute_d(e: &BigUint, lambda: &BigUint) -> BigUint {
    use num_bigint::ToBigInt;
    use stingray::modinverse::Modinverse;
    let e = e.to_bigint().unwrap();
    let lambda = lambda.to_bigint().unwrap();
    e.modinverse(&lambda).to_biguint().unwrap()
}

fn compute_dp(d: &BigUint, p: &BigUint) -> BigUint {
    use num_integer::Integer;
    use num_traits::One;
    let pm = p - BigUint::one();
    d.mod_floor(&pm)
}

fn compute_dq(d: &BigUint, q: &BigUint) -> BigUint {
    use num_integer::Integer;
    use num_traits::One;
    let qm = q - BigUint::one();
    d.mod_floor(&qm)
}

fn compute_qinv(p: &BigUint, q: &BigUint) -> BigUint {
    use num_bigint::ToBigInt;
    use stingray::modinverse::Modinverse;
    let q = q.to_bigint().unwrap();
    let p = p.to_bigint().unwrap();
    q.modinverse(&p).to_biguint().unwrap()
}

fn generate_p_q_pair(key_bits_in_n: usize) -> (/*p: */ BigUint, /*q: */ BigUint) {
    loop {
        let p = generate_candidate_for_p_or_q(key_bits_in_n);
        let q = generate_candidate_for_p_or_q(key_bits_in_n);
        if is_p_q_pair_valid(&p, &q) {
            return (p, q);
        }
    }
}

/// Generates a vector of length [bytes_count]. It's meant to
/// be understood as big-endian. The content is all random bits
/// except for the two most significant bits which are always both 1 and
/// except for the least significant bit which is also always one.
/// Thus, if interpreted as a BigUint, the number will always be odd (least
/// significant bit always 1), and if two of these numbers are multiplied
/// the result will always have exactly the length of 2*8*bytes_count bits.
///
/// Panics if [bytes_count] < 1.
fn make_special_random_bytes(bytes_count: usize) -> Vec<u8> {
    use firescout::random::get_random_bytes;
    let mut bytes = get_random_bytes(bytes_count);
    bytes[0] = bytes[0] | 0xC0;
    bytes[bytes_count - 1] = bytes[bytes_count - 1] | 0x01;
    bytes
}

/// Convienence function that uses [make_special_random_bytes] and
/// turns result into a BigUint.
fn make_special_random_biguint(bytes_count: usize) -> BigUint {
    let bytes = make_special_random_bytes(bytes_count);
    return BigUint::from_bytes_be(&bytes);
}

fn generate_candidate_for_p_or_q(key_bits_in_n: usize) -> BigUint {
    use stingray::primes::IsProbablyPrimeMrt;
    const MRT_ROUNDS: u32 = 16;
    let candidate_bytes: usize = key_bits_in_n / 8 / 2;
    loop {
        let candidate = make_special_random_biguint(candidate_bytes);
        if candidate.is_probably_prime_mrt(MRT_ROUNDS) {
            return candidate;
        }
    }
}

fn is_p_q_pair_valid(p: &BigUint, q: &BigUint) -> bool {
    use stingray::log2::Log2;
    if p == q {
        return false;
    }
    let x = (p.log2() - q.log2()).abs();
    0.1 < x && x < 30.
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_wikipedia() {
        let p = BigUint::from(61u32);
        let q = BigUint::from(53u32);
        let e = BigUint::from(17u32);
        let key = generate_key_from_p_q_e(&p, &q, &e).unwrap();
        println!("{:?}", key);
    }

    #[test]
    fn key_random() {
        let key_length = KEY_LENGTH_2048;
        let key = generate_key(key_length);
        println!("{:?}", key);
        let v = key.n.to_radix_be(2);
        assert_eq!(v.len(), key_length);
    }

    #[test]
    fn candidate() {
        let key_length = KEY_LENGTH_2048;
        let candidate = generate_candidate_for_p_or_q(key_length);
        println!("{}", candidate);
    }

    #[test]
    fn machma() {
        let bytes_count = 128;
        let p = make_special_random_biguint(bytes_count);
        let q = make_special_random_biguint(bytes_count);
        let n = p * q;

        let v = n.to_radix_be(2);
        println!("{}", v.len());
    }
}
