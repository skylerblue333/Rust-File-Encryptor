use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key
};
use std::fs::File;
use std::io::{Read, Write};

fn encrypt_file(input_path: &str, output_path: &str, key: &[u8; 32]) -> Result<(), Box<dyn std::error::Error>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng); // 96-bits; unique per message
    
    let mut file = File::open(input_path)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;
    
    let ciphertext = cipher.encrypt(&nonce, data.as_ref()).map_err(|e| e.to_string())?;
    
    let mut out_file = File::create(output_path)?;
    out_file.write_all(&nonce)?;
    out_file.write_all(&ciphertext)?;
    
    Ok(())
}

fn main() {
    println!("File Encryptor CLI ready.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_encryption() {
        let key = [42u8; 32];
        let input = "test_in.txt";
        let output = "test_out.enc";
        
        fs::write(input, b"secret data").unwrap();
        
        assert!(encrypt_file(input, output, &key).is_ok());
        assert!(fs::metadata(output).is_ok());
        
        fs::remove_file(input).unwrap();
        fs::remove_file(output).unwrap();
    }
}
