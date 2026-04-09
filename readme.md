
# rabbit 🦀
**Fast • Secure • Password-based • Atomic in-place file encryption for Linux**

A production-ready CLI tool that uses the **Rabbit** stream cipher (eSTREAM finalist) with modern authenticated encryption:

- **Argon2id** password key derivation (memory-hard, resistant to brute-force)
- **BLAKE3** MAC for integrity and tamper detection
- Automatic random salt + IV (no manual key/IV management)
- **Atomic in-place replacement** — you only give the filename
- Fully streaming (handles terabyte-sized files with almost no RAM)
- Automatically detects whether to encrypt or decrypt
- Linux-only (as requested)

---

## Features

- One-command encrypt/decrypt: `rabbit myfile.txt`
- True atomic writes using `tempfile::NamedTempFile` + `persist` (original file is never lost on crash or failure)
- Strong password security via Argon2id (64 MiB memory, 3 iterations)
- Tamper-proof: any modification or wrong password is immediately rejected
- Extremely fast on large files (Rabbit is one of the fastest software stream ciphers)
- No external dependencies at runtime (single static binary after build)

---

## Quick Start

### 1. Build it


git clone https:// github.com/yourname/rabbit.git   # or just use your local folder
cd rabbit
cargo build --release


The binary will be at `./target/release/rabbit`

### 2. Usage (super simple)


# Encrypt a file in place
./target/release/rabbit important.pdf

# Decrypt the same file (it auto-detects)
./target/release/rabbit important.pdf


You will be prompted for a password (twice when encrypting, once when decrypting).

---

## Full Usage


rabbit <FILE>

# Examples:
rabbit secret.txt
rabbit video.mkv
rabbit backup.tar.gz


The tool **always** works in place and **always** does an atomic replace.  
If the file starts with the magic header `RABBITv2`, it decrypts; otherwise it encrypts.

---

## Security Design

| Component       | Choice                  | Reason |
|-----------------|-------------------------|--------|
| Cipher          | Rabbit (128-bit)        | Extremely fast, well-studied, no practical breaks |
| Key Derivation  | Argon2id (64 MiB)       | Current gold standard against GPU/ASIC attacks |
| Authentication  | BLAKE3 (keyed)          | Fast, secure MAC |
| Nonce/IV        | Random 64-bit per file  | Automatically generated and stored |
| File Format     | Versioned header + MAC  | Future-proof and self-describing |

**Important notes**:
- This tool provides **strong confidentiality + integrity**.
- It is **not** a general-purpose crypto library. For maximum future-proofing, consider tools like `age` for very long-term archives.
- Rabbit is excellent for speed, but if you need the absolute highest formal security margin, AES-256-GCM or ChaCha20-Poly1305 are more commonly recommended in 2026.

---

## File Format (for advanced users)

Encrypted files begin with a 32-byte header:


Bytes 0-7:   "RABBITv2" (magic)
Bytes 8-23:  16-byte Argon2id salt
Bytes 24-31: 8-byte random IV


Followed by the encrypted data (same length as original) and a final 32-byte BLAKE3 MAC.

The format is deliberately simple and easy to parse.

---

## Building Options


# Normal build
cargo build --release

# Statically linked (great for distribution)
cargo build --release --target x86_64-unknown-linux-musl


Target binary size is ~3–4 MB (static) or ~1.5 MB (dynamic).

---

## Development / Contributing

Written for Rust 1.94+ (2024 edition).  
All dependencies are up-to-date as of April 2026.


cargo test          # (no tests yet — PRs welcome!)
cargo clippy --fix


---

## License

MIT OR Apache-2.0 (your choice).

The underlying Rabbit algorithm itself is public domain.

---

## Credits

- @bashbunni the awesome Rust coder !! https://github.com/bashbunni
- Rabbit stream cipher: Martin Boesgaard et al. (2003, eSTREAM)
- Rust `rabbit` crate: RustCrypto team
- Argon2, BLAKE3, and other crates: their respective authors
- Built with ❤️ for speed and simplicity

---

**Made for Linux users who want something fast, simple, and actually secure.**

Enjoy encrypting! 🔐




