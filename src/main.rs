mod office_crypto;
mod office_doc;

fn main() {
    let file = std::env::args().nth(1).unwrap();
    let password = std::env::args().nth(2).unwrap();

    let encrypted_keys = match office_doc::parse_doc(file.as_str()) {
        Ok(data) => data,
        Err(e) => {
            println!("Error parsing office doc: {}", e);
            std::process::exit(1);
        }
    };

    if encrypted_keys.len() == 0 {
        println!("Error: No encrypted keys found in document");
        std::process::exit(1);
    }

    if encrypted_keys.len() > 1 {
        println!("Warning: Found {} keys. Any match will count as success.",
                 encrypted_keys.len());
    }

    for key_info in &encrypted_keys {
        let block_keys = office_crypto::derive_keys(password.as_str(), key_info);
        match office_crypto::try_decrypt(&block_keys, key_info) {
            Ok(result) => {
                if result {
                    println!("Success!");
                    std::process::exit(0);
                }
            }
            Err(e) => println!("Error checking key: {}", e),
        }
    }

    println!("Fail!");
    std::process::exit(1);
}
