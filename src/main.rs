extern crate clap;

mod office_crypto;
mod office_doc;

use clap::{Arg, App};
use std::collections::HashSet;

fn main() {
    let args = App::new("office-crypto")
        .arg(Arg::with_name("input")
            .short("i")
            .long("input")
            .value_name("file")
            .help("Office document file")
            .required(true))
        .arg(Arg::with_name("password")
            .short("p")
            .long("password")
            .value_name("password")
            .help("Password to guess")
            .required(true))
        .get_matches();

    let file = args.value_of("input").unwrap();
    let password = args.value_of("password").unwrap();

    let key_infos = get_key_infos(file);
    for key_info in &key_infos {
        if try_single_pass(password, key_info) {
            println!("Success!");
            std::process::exit(0);
        }
    }

    println!("Fail!");
    std::process::exit(1);
}

fn get_key_infos(file: &str) -> HashSet<office_doc::EncryptedKeyInfo> {
    let encrypted_keys = match office_doc::parse_doc(file) {
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

    encrypted_keys
}

fn try_single_pass(password: &str, key_info: &office_doc::EncryptedKeyInfo) -> bool {
    let block_keys = office_crypto::derive_keys(password, key_info);
    match office_crypto::try_decrypt(&block_keys, key_info) {
        Ok(result) => return result,
        Err(e) => println!("Error checking key: {}", e),
    }

    false
}
