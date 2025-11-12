use sha3::{Sha3_256, Digest};
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::fs::File;
use std::env;
use std::process;

fn calculate_file_hash(path: PathBuf) -> Result<String, io::Error> {
    let mut file = File::open(&path)?;
    let mut hasher = Sha3_256::new();

    // Use a more reasonable buffer size to avoid excessive memory allocation.
    // 1MB is a good balance for I/O performance.
    const BUFFER_SIZE: usize = 1 * 256 * 1024;
    let mut buffer = vec![0; BUFFER_SIZE];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 { break; }
        hasher.update(&buffer[..n]);
    }

    let hash_bytes = hasher.finalize();
    let hash_string = format!("{:x}", hash_bytes);

    Ok(hash_string)
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <path_to_file>", args[0]);
        process::exit(1);
    }

    match calculate_file_hash(args[1].clone().into()) {
        Ok(hash) => println!("{}", hash),
        Err(e) => {
            eprintln!("Error hashing file '{}': {}", args[1], e);
            process::exit(1);
        }
    }
}