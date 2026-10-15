# =============================================================================
# RSA IMPLEMENTATION — Consolidated Python Code
# Extracted from the bachelor thesis "RSA Cryptosystem and Cryptoanalysis"
# All code blocks preserved exactly as they appear in the thesis.
# =============================================================================


# -----------------------------------------------------------------------------
# SECTION 1 — Fast Encryption (Square-and-Multiply, Left-to-Right)
# Source: Chapter 3, Section "Fast Modular Exponentiation", subsection
#         "Fast Encryption" — Python Implementation
# -----------------------------------------------------------------------------

def fast_encrypt(m: int, e: int, n: int) -> int:
    """
    Compute m^e mod n using the square-and-multiply method.
    Equivalent to Python's built-in pow(m, e, n).
    """
    result = 1
    m = m % n
    while e > 0:
        if e % 2 == 1:           # current bit is 1 -> multiply
            result = (result * m) % n
        e >>= 1                  # shift to next bit
        m = (m * m) % n          # square the base
    return result

# Example: encrypt m=7 with public key (e=13, n=33)
ciphertext = fast_encrypt(7, 13, 33)
print(f"Ciphertext: {ciphertext}")   # Output: 13


# -----------------------------------------------------------------------------
# SECTION 2 — Fast Decryption (CRT / Garner's Method)
# Source: Chapter 3, Section "Fast Modular Exponentiation", subsection
#         "Fast Decryption" — Python Implementation
# -----------------------------------------------------------------------------

def mod_inverse(a: int, m: int) -> int:
    """Extended Euclidean algorithm to compute a^{-1} mod m."""
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist.")
    return x % m

def extended_gcd(a: int, b: int):
    if a == 0:
        return b, 0, 1
    g, x, y = extended_gcd(b % a, a)
    return g, y - (b // a) * x, x

def fast_decrypt_crt(c: int, p: int, q: int, d: int) -> int:
    """
    RSA decryption using the Chinese Remainder Theorem (Garner's method).
    Approximately 4x faster than direct pow(c, d, p*q).
    """
    n   = p * q
    d_p = d % (p - 1)                  # reduced exponent mod p
    d_q = d % (q - 1)                  # reduced exponent mod q
    q_inv = mod_inverse(q, p)          # CRT coefficient

    m_p = pow(c, d_p, p)               # half-size exponentiation mod p
    m_q = pow(c, d_q, q)               # half-size exponentiation mod q

    h = (q_inv * (m_p - m_q)) % p     # Garner recombination
    m = m_q + h * q                    # final plaintext

    return m % n

# ------------------------------------------------------------------
# Example: p=11, q=13, e=7, d=103, ciphertext c=6
p, q, d, c = 11, 13, 103, 6
plaintext = fast_decrypt_crt(c, p, q, d)
print(f"Decrypted: {plaintext}")       # Output: 73

# Verify against direct decryption
n = p * q
assert plaintext == pow(c, d, n), "CRT decryption mismatch!"
print("Verification passed.")


# -----------------------------------------------------------------------------
# SECTION 3 — Basic RSA Implementation (Textbook RSA)
# Source: Chapter 3, Section "RSA Conceptual Implementation"
# -----------------------------------------------------------------------------

import random

# ------------------ Miller-Rabin Primality Test ------------------
def is_prime(n, k=5):
    """Return True if n is probably prime (error probability 2^{-k})."""
    if n < 2:
        return False
    if n in (2, 3):
        return True
    if n % 2 == 0:
        return False

    # Write n-1 = d * 2^s
    d = n - 1
    s = 0
    while d % 2 == 0:
        d //= 2
        s += 1

    # Test k witnesses
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                break
        else:
            return False
    return True

def generate_prime(bits=8):
    """Generate a random prime of roughly 'bits' bits."""
    while True:
        p = random.getrandbits(bits)
        # ensure it is odd and large enough
        p |= (1 << bits - 1) | 1
        if is_prime(p):
            return p

# ------------------ Extended Euclidean Algorithm ------------------
def egcd(a, b):
    """Return (g, x, y) such that a*x + b*y = g = gcd(a, b)."""
    if a == 0:
        return (b, 0, 1)
    else:
        g, x1, y1 = egcd(b % a, a)
        return (g, y1 - (b // a) * x1, x1)

def modinv(a, m):
    """Return the modular inverse of a modulo m (assumes gcd(a,m)=1)."""
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Inverse does not exist")
    return x % m

# ------------------ Square‑and‑Multiply (Left‑to‑Right) ------------------
def square_and_multiply(base, exp, mod):
    """Return base^exp mod mod using binary exponentiation."""
    result = 1
    bits = bin(exp)[2:]   # e.g., '1011'
    for bit in bits:
        result = (result * result) % mod      # square
        if bit == '1':
            result = (result * base) % mod    # multiply
    return result

# ------------------ Garner's CRT for RSA Decryption ------------------
def rsa_decrypt_crt(c, p, q, d):
    """
    Fast RSA decryption using Garner's method.
    Assumes n = p*q, ed ≡ 1 mod φ(n).
    """
    d_p = d % (p - 1)
    d_q = d % (q - 1)
    q_inv = modinv(q, p)

    m_p = square_and_multiply(c, d_p, p)   # c^d_p mod p
    m_q = square_and_multiply(c, d_q, q)   # c^d_q mod q

    # Garner recombination
    h = (q_inv * (m_p - m_q)) % p
    m = m_q + h * q
    return m

# ------------------ RSA Key Generation ------------------
def generate_rsa_keys(bits=8):
    """Generate RSA keys. For demo only — uses small primes."""
    p = generate_prime(bits)
    q = generate_prime(bits)
    while q == p:
        q = generate_prime(bits)
    n = p * q
    phi = (p - 1) * (q - 1)

    # Choose e (usually 65537, here small for demo)
    e = 65537
    if phi % e == 0:
        e = 257
    d = modinv(e, phi)

    public_key = (e, n)
    private_key = (d, p, q)
    return public_key, private_key

# ------------------ Encryption ------------------
def encrypt(msg, public_key):
    """Encrypt a message (integer) using RSA public key (e, n)."""
    e, n = public_key
    return square_and_multiply(msg, e, n)

# ------------------ Decryption (with CRT) ------------------
def decrypt(cipher, private_key):
    """Decrypt ciphertext using CRT‑based fast decryption."""
    d, p, q = private_key
    return rsa_decrypt_crt(cipher, p, q, d)

# ------------------ Demonstration ------------------
if __name__ == "__main__":
    print("=== Basic RSA Implementation (Textbook RSA) ===\n")

    public_key, private_key = generate_rsa_keys(bits=8)
    e, n = public_key
    print(f"Public key:  (e = {e}, n = {n})")
    print(f"Private key: (d = {private_key[0]} kept secret, p = {private_key[1]}, q = {private_key[2]})")

    original = 42
    print(f"\nOriginal message: {original}")

    cipher = encrypt(original, public_key)
    print(f"Encrypted ciphertext: {cipher}")

    decrypted = decrypt(cipher, private_key)
    print(f"Decrypted plaintext:  {decrypted}")

    assert original == decrypted, "Decryption failed!"
    print("\n✓ Encryption / decryption successful.")


# -----------------------------------------------------------------------------
# SECTION 4 — Wiener Attack Implementation
# Source: Chapter 5, Section "Wiener's Attack", subsection
#         "Wiener Attack Implementation"
# -----------------------------------------------------------------------------

import math

def get_cf(num, den):
    cf = []
    while den != 0:
        q = num // den
        cf.append(q)
        num, den = den, num - q * den
    return cf

def gen_convs(cf):
    p0, p1 = 0, 1
    q0, q1 = 1, 0
    for a in cf:
        p = a * p1 + p0
        q = a * q1 + q0
        yield p, q
        p0, p1 = p1, p
        q0, q1 = q1, q

def wiener_attack(N, e):
    cf = get_cf(e, N)
    for k, d in gen_convs(cf):
        if k == 0:
            continue
        if (e * d - 1) % k != 0:
            continue
        phi = (e * d - 1) // k
        s = N - phi + 1
        disc = s * s - 4 * N
        if disc < 0:
            continue
        t = int(math.isqrt(disc))
        if t * t != disc:
            continue
        p = (s - t) // 2
        q = (s + t) // 2
        if p * q == N:
            return d, p, q
    return None

# Example usage
if __name__ == "__main__":
    N = 8927
    e = 2621
    res = wiener_attack(N, e)
    if res:
        d, p, q = res
        print(f"d = {d}, p = {p}, q = {q}")
    else:
        print("Attack failed")


# -----------------------------------------------------------------------------
# SECTION 5 — Simmons' Attack Implementation (Common Modulus Attack)
# Source: Chapter 5, Section "Homomorphic Attacks", subsection
#         "Common Modulus Attacks on RSA", subsubsection "A) Simmons' Attack"
# -----------------------------------------------------------------------------

import math
import random

def factorize_from_multiple(N, m):

    s = 0
    t = m
    while t % 2 == 0:
        t //= 2
        s += 1

    # Try random bases a
    for _ in range(20):  # enough attempts for high probability
        a = random.randrange(2, N)
        g = math.gcd(a, N)
        if g != 1:
            # a shares a factor with N  we already have a factor
            return g

        x = pow(a, t, N)

        if x == 1 or x == N-1:
            continue

        for _ in range(s):
            prev = x
            x = pow(x, 2, N)
            if x == 1:
                if prev != N-1:
                    return math.gcd(prev - 1, N)
                break
            if x == N-1:
                break

    raise ValueError("Failed to factor N; check that m is a multiple of phi(N)")

if __name__ == "__main__":
    N = 187
    m = 160   # = e*d - 1 (with e=7, d=23)
    factor = factorize_from_multiple(N, m)
    print(f"The first factor p = {factor}")
    print(f"The second factor q = {N // factor}")