use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce,
};
use std::{
    env, fs,
    fs::OpenOptions,
    io::{self, Write},
    path::Path,
};

const MAGIC: &[u8; 8] = b"SKYENC01";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
const MAX_INPUT_BYTES: u64 = 64 * 1024 * 1024;

fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
    let metadata = fs::metadata(path)?;
    if !metadata.is_file() {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "input must be a regular file"));
    }
    if metadata.len() > MAX_INPUT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("input exceeds {MAX_INPUT_BYTES} byte limit"),
        ));
    }
    fs::read(path)
}

fn encrypt_file(input: &Path, output: &Path, key: &[u8; 32]) -> io::Result<()> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let plaintext = read_bounded(input)?;
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "encryption failed"))?;

    let mut encoded = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
    encoded.extend_from_slice(MAGIC);
    encoded.extend_from_slice(&nonce);
    encoded.extend_from_slice(&ciphertext);
    write_new_file(output, &encoded)
}

fn decrypt_file(input: &Path, output: &Path, key: &[u8; 32]) -> io::Result<()> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let encoded = read_bounded(input)?;
    let minimum_len = MAGIC.len() + NONCE_LEN + TAG_LEN;
    if encoded.len() < minimum_len {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "encrypted file is truncated"));
    }
    if &encoded[..MAGIC.len()] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported encrypted file format",
        ));
    }

    let nonce_start = MAGIC.len();
    let nonce_end = nonce_start + NONCE_LEN;
    let nonce = Nonce::from_slice(&encoded[nonce_start..nonce_end]);
    let plaintext = cipher
        .decrypt(nonce, &encoded[nonce_end..])
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "authentication failed"))?;
    write_new_file(output, &plaintext)
}

fn write_new_file(path: &Path, data: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    if let Err(error) = file.write_all(data).and_then(|_| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(path);
        return Err(error);
    }
    Ok(())
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
    "Usage: file-encryptor <encrypt|decrypt> <input> <output>\nReads FILE_ENCRYPTOR_KEY as exactly 64 hexadecimal characters (32 bytes)."
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
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock must be after unix epoch")
            .as_nanos();
        std::env::temp_dir().join(format!("file-encryptor-{id}-{suffix}"))
    }

    fn cleanup(paths: &[&Path]) {
        for path in paths {
            let _ = fs::remove_file(path);
        }
    }

    #[test]
    fn round_trip_preserves_bytes_and_writes_versioned_envelope() {
        let input = temp_path("input");
        let encrypted = temp_path("encrypted");
        let output = temp_path("output");
        let key = [42u8; 32];
        fs::write(&input, b"secret data").unwrap();

        encrypt_file(&input, &encrypted, &key).unwrap();
        let encoded = fs::read(&encrypted).unwrap();
        assert_eq!(&encoded[..MAGIC.len()], MAGIC);
        decrypt_file(&encrypted, &output, &key).unwrap();
        assert_eq!(fs::read(&output).unwrap(), b"secret data");

        cleanup(&[&input, &encrypted, &output]);
    }

    #[test]
    fn tampering_fails_authentication_without_creating_output() {
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
        assert!(!output.exists());

        cleanup(&[&input, &encrypted, &output]);
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let input = temp_path("input");
        let encrypted = temp_path("encrypted");
        let output = temp_path("output");
        fs::write(&input, b"secret data").unwrap();
        encrypt_file(&input, &encrypted, &[1u8; 32]).unwrap();
        assert!(decrypt_file(&encrypted, &output, &[2u8; 32]).is_err());
        assert!(!output.exists());
        cleanup(&[&input, &encrypted, &output]);
    }

    #[test]
    fn rejects_unknown_format_and_existing_output() {
        let input = temp_path("input");
        let output = temp_path("output");
        fs::write(&input, b"not-an-envelope").unwrap();
        fs::write(&output, b"preserve me").unwrap();
        assert!(decrypt_file(&input, &temp_path("unused"), &[1u8; 32]).is_err());
        assert!(write_new_file(&output, b"replacement").is_err());
        assert_eq!(fs::read(&output).unwrap(), b"preserve me");
        cleanup(&[&input, &output]);
    }

    #[test]
    fn key_parser_requires_exactly_32_hex_bytes() {
        assert!(parse_key("00").is_err());
        assert!(parse_key(&"gg".repeat(32)).is_err());
        assert!(parse_key(&"00".repeat(32)).is_ok());
    }
}
