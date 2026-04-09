use clap::Parser;
use rabbit::Rabbit;
use rabbit::cipher::{KeyIvInit, StreamCipher};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use rand::Rng;

// Enforce Linux-only
#[cfg(not(target_os = "linux"))]
compile_error!("rabbit is Linux-only.");

const MAGIC: &[u8; 8] = b"RABBITv2";
const HEADER_SIZE: usize = 32; // magic(8) + salt(16) + iv(8)
const MAC_SIZE: usize = 32;
const KEY_MATERIAL_LEN: usize = 48; // 16 bytes Rabbit + 32 bytes BLAKE3

#[derive(Parser)]
#[command(author, version, about = "Rabbit stream cipher — secure, password-based, atomic in-place", long_about = None)]
struct Cli {
    /// File to encrypt or decrypt in place (automatically detected)
    file: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    if !cli.file.is_file() {
        anyhow::bail!("Error: {} is not a file", cli.file.display());
    }

    // Peek at the start to decide encrypt or decrypt
    let mut f = File::open(&cli.file)?;
    let mut magic_buf = [0u8; 8];
    let is_encrypted = f.read_exact(&mut magic_buf).is_ok() && &magic_buf == MAGIC;

    if is_encrypted {
        println!("🔓 Decrypting {} in place (atomic)...", cli.file.display());
        decrypt_in_place(&cli.file)?;
        println!("✅ Decryption complete!");
    } else {
        println!("🔐 Encrypting {} in place (atomic)...", cli.file.display());
        encrypt_in_place(&cli.file)?;
        println!("✅ Encryption complete!");
    }

    Ok(())
}

fn encrypt_in_place(path: &PathBuf) -> anyhow::Result<()> {
    let password = rpassword::prompt_password("Enter password: ")?;
    let confirm = rpassword::prompt_password("Confirm password: ")?;
    if password != confirm {
        anyhow::bail!("Passwords do not match");
    }

    let mut rng = rand::thread_rng();
    let mut salt = [0u8; 16];
    let mut iv = [0u8; 8];
    rng.fill(&mut salt[..]);
    rng.fill(&mut iv[..]);

    let params = argon2::Params::new(65536, 3, 1, Some(KEY_MATERIAL_LEN))
        .map_err(|e| anyhow::anyhow!("Argon2 param error: {}", e))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key_material = [0u8; KEY_MATERIAL_LEN];
    argon2.hash_password_into(password.as_bytes(), &salt, &mut key_material)?;

    let enc_key = &key_material[0..16];
    let mac_key: [u8; 32] = key_material[16..48].try_into().unwrap();

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;

    // Write header
    let mut header = [0u8; HEADER_SIZE];
    header[0..8].copy_from_slice(MAGIC);
    header[8..24].copy_from_slice(&salt);
    header[24..32].copy_from_slice(&iv);
    temp.write_all(&header)?;

    let mut cipher = Rabbit::new_from_slices(enc_key, &iv)
        .expect("invalid key/iv length");

    let mut mac_hasher = blake3::Hasher::new_keyed(&mac_key);
    mac_hasher.update(&iv);

    let mut reader = File::open(path)?;
    let mut buffer = vec![0u8; 128 * 1024];

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        let chunk = &mut buffer[0..n];
        cipher.apply_keystream(chunk);
        mac_hasher.update(chunk);
        temp.write_all(chunk)?;
    }

    let mac = mac_hasher.finalize();
    temp.write_all(mac.as_bytes())?;
    temp.flush()?;

    // Atomic replace
    temp.persist(path)?;
    Ok(())
}

fn decrypt_in_place(path: &PathBuf) -> anyhow::Result<()> {
    let password = rpassword::prompt_password("Enter password: ")?;

    let mut file = File::open(path)?;
    let size = file.metadata()?.len();
    if size < (HEADER_SIZE + MAC_SIZE) as u64 {
        anyhow::bail!("File is too small to be a valid encrypted file");
    }

    let ciphertext_len = size - (HEADER_SIZE + MAC_SIZE) as u64;

    // Read header
    let mut header = [0u8; HEADER_SIZE];
    file.read_exact(&mut header)?;
    if &header[0..8] != MAGIC {
        anyhow::bail!("Invalid magic header");
    }
    let salt = &header[8..24];
    let iv = &header[24..32];

    let params = argon2::Params::new(65536, 3, 1, Some(KEY_MATERIAL_LEN))
        .map_err(|e| anyhow::anyhow!("Argon2 param error: {}", e))?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key_material = [0u8; KEY_MATERIAL_LEN];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key_material)?;

    let enc_key = &key_material[0..16];
    let mac_key: [u8; 32] = key_material[16..48].try_into().unwrap();

    let mut cipher = Rabbit::new_from_slices(enc_key, iv)
        .expect("invalid key/iv length");

    let mut mac_hasher = blake3::Hasher::new_keyed(&mac_key);
    mac_hasher.update(iv);

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let mut temp = tempfile::NamedTempFile::new_in(parent)?;

    let mut buffer = vec![0u8; 128 * 1024];
    let mut bytes_remaining = ciphertext_len as usize;

    while bytes_remaining > 0 {
        let to_read = std::cmp::min(buffer.len(), bytes_remaining);
        let n = file.read(&mut buffer[0..to_read])?;
        if n == 0 {
            break;
        }
        let chunk = &mut buffer[0..n];
        mac_hasher.update(chunk);
        cipher.apply_keystream(chunk);
        temp.write_all(chunk)?;
        bytes_remaining -= n;
    }

    // Read and verify MAC
    let mut stored_mac = [0u8; MAC_SIZE];
    file.read_exact(&mut stored_mac)?;
    let computed_mac = mac_hasher.finalize();

    if computed_mac.as_bytes() != &stored_mac {
        let _ = temp.close();
        anyhow::bail!("❌ MAC verification failed! Wrong password or file has been tampered with.");
    }

    temp.flush()?;
    temp.persist(path)?;
    Ok(())
}