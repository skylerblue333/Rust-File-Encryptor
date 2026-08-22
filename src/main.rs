use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use std::{env, fs, io, path::Path};

const NONCE_LEN: usize = 12;

fn encrypt_file(input: &Path, output: &Path, key: &[u8; 32]) -> io::Result<()> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let plaintext = fs::read(input)?;
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "encryption failed"))?;
    let mut encoded = nonce.to_vec();
    encoded.extend_from_slice(&ciphertext);
    write_new_file(output, &encoded)
}

fn decrypt_file(input: &Path, output: &Path, key: &[u8; 32]) -> io::Result<()> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let encoded = fs::read(input)?;
    if encoded.len() <= NONCE_LEN {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "encrypted file is truncated"));
    }
    let nonce = Nonce::from_slice(&encoded[..NONCE_LEN]);
    let plaintext = cipher
        .decrypt(nonce, &encoded[NONCE_LEN..])
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "authentication failed"))?;
    write_new_file(output, &plaintext)
}

fn write_new_file(path: &Path, data: &[u8]) -> io::Result<()> {
    if path.exists() {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "output already exists"));
    }
    fs::write(path, data)
}

fn parse_key(raw: &str) -> Result<[u8; 32], String> {
    if raw.len() != 64 {
        return Err("key must contain exactly 64 hexadecimal characters".to_owned());
    }
    let mut key = [0u8; 32];
    for (index, pair) in raw.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(pair).map_err(|_| "key is not valid UTF-8".to_owned())?;
        key[index] = u8::from_str_radix(text, 16).map_err(|_| "key must be hexadecimal".to_owned())?;
    }
    Ok(key)
}

fn usage() -> &'static str {
    "Usage: file-encryptor <encrypt|decrypt> <input> <output>\nReads FILE_ENCRYPTOR_KEY as 64 hexadecimal characters."
}

fn run(args: &[String]) -> Result<(), String> {
    if args.len() != 4 {
        return Err(usage().to_owned());
    }
    let key_text = env::var("FILE_ENCRYPTOR_KEY").map_err(|_| "FILE_ENCRYPTOR_KEY is required".to_owned())?;
    let key = parse_key(&key_text)?;
    let input = Path::new(&args[2]);
    let output = Path::new(&args[3]);
    if input == output {
        return Err("input and output paths must differ".to_owned());
    }
    match args[1].as_str() {
        "encrypt" => encrypt_file(input, output, &key).map_err(|error| error.to_string()),
        "decrypt" => decrypt_file(input, output, &key).map_err(|error| error.to_string()),
        _ => Err(usage().to_owned()),
    }
}

fn main() {
    if let Err(error) = run(&env::args().collect::<Vec<_>>()) {
        eprintln!("error: {error}");
        std::process::exit(2);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_path(suffix: &str) -> std::path::PathBuf {
        let id = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        std::env::temp_dir().join(format!("file-encryptor-{id}-{suffix}"))
    }

    #[test]
    fn round_trip_preserves_bytes() {
        let input = temp_path("input");
        let encrypted = temp_path("encrypted");
        let output = temp_path("output");
        let key = [42u8; 32];
        fs::write(&input, b"secret data").unwrap();
        encrypt_file(&input, &encrypted, &key).unwrap();
        decrypt_file(&encrypted, &output, &key).unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"secret data");
        let _ = fs::remove_file(input);
        let _ = fs::remove_file(encrypted);
        let _ = fs::remove_file(output);
    }

    #[test]
    fn tampering_fails_authentication() {
        let input = temp_path("input");
        let encrypted = temp_path("encrypted");
        let output = temp_path("output");
        let key = [42u8; 32];
        fs::write(&input, b"secret data").unwrap();
        encrypt_file(&input, &encrypted, &key).unwrap();
        let mut bytes = fs::read(&encrypted).unwrap();
        *bytes.last_mut().unwrap() ^= 1;
        fs::write(&encrypted, bytes).unwrap();
        assert!(decrypt_file(&encrypted, &output, &key).is_err());
        let _ = fs::remove_file(input);
        let _ = fs::remove_file(encrypted);
        let _ = fs::remove_file(output);
    }

    #[test]
    fn key_parser_requires_32_bytes() {
        assert!(parse_key("00").is_err());
        assert!(parse_key(&"00".repeat(32)).is_ok());
    }
}
