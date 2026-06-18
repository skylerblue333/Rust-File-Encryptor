use std::env;
use std::fs;
use std::path::Path;

/// Simple XOR-based encryption for demonstration
/// In production, use AES-256-GCM via the `aes-gcm` crate
fn xor_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter()
        .enumerate()
        .map(|(i, byte)| byte ^ key[i % key.len()])
        .collect()
}

fn process_file(input_path: &str, output_path: &str, key: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Reading: {}", input_path);
    let data = fs::read(input_path)?;
    
    let processed = xor_encrypt(&data, key.as_bytes());
    
    fs::write(output_path, &processed)?;
    println!("Output written to: {}", output_path);
    println!("Processed {} bytes.", processed.len());
    
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() < 4 {
        eprintln!("Usage: {} <input_file> <output_file> <key>", args[0]);
        eprintln!("Example: {} secret.txt secret.enc mypassword", args[0]);
        std::process::exit(1);
    }
    
    let input = &args[1];
    let output = &args[2];
    let key = &args[3];
    
    match process_file(input, output, key) {
        Ok(_) => println!("Success!"),
        Err(e) => eprintln!("Error: {}", e),
    }
}
