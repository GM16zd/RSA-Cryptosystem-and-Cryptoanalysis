# RSA Cryptosystem: Deep Dive (Bachelor Thesis)

This repository contains my Bachelor thesis research on the **RSA cryptosystem**, exploring the protocol comprehensively from foundational arithmetic to advanced cryptanalysis and attacks. 

The project covers RSA from all angles, serving as a rigorous deep dive into how public-key cryptography works in theory and where it breaks down in practice.

---

## 📌 Repository Overview

* **Chapter 1: Historical Context & Motivation** – The Key Distribution Problem, Diffie-Hellman (1976), RSA at MIT (1977), and the secret prior discovery at GCHQ.
* **Chapter 2: Mathematical Foundations** – Modular arithmetic, rings, ideals, quotient rings, GCD & the Extended Euclidean Algorithm, Euler's totient, Fermat's Little Theorem, Chinese Remainder Theorem, and primality testing (AKS, Fermat, Miller-Rabin).
* **Chapter 3: The RSA Cryptosystem** – Key generation, encryption/decryption proofs, fast modular exponentiation (square-and-multiply), and digital signatures.
* **Chapter 4: The Security Foundation** – Direct attacks, integer factorization algorithms (Trial Division, Fermat's method, Pollard's $\rho$ and $p-1$), and sub-exponential methods.
* **Chapter 5: Cryptanalysis & Padding** – Wiener’s continued fraction attack, low public exponent attacks (Håstad, Franklin-Reiter), homomorphic attacks, padding schemes (OAEP), side-channel implementation attacks (timing, power, and fault analysis on RSA-CRT), and Bleichenbacher’s chosen ciphertext attack.

---

## 🛠️ Structure

📦 rsa-bachelor-thesis
 ┣ 📂 chapters/
 ┃ ┣ 📜 01_historical_context.tex 
 ┃ ┣ 📜 02_mathematical_foundations.tex
 ┃ ┣ 📜 03_rsa_cryptosystem.tex
 ┃ ┣ 📜 04_security_foundation.tex
 ┃ ┗ 📜 05_cryptanalysis_and_attacks.tex
 ┣ 📂 code/              
 ┣ 📜 bachelor_thesis.pdf  
 ┗ 📜 README.md           
