extern crate clap;

mod office_crypto;
mod office_doc;

use clap::{Arg, App};
use std::collections::HashSet;
use std::fs::File;
use std::io::Read;

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
            .help("Password to guess"))
        .arg(Arg::with_name("password-file")
            .long("password-file")
            .value_name("password-file")
            .help("File containing list of passwords to guess"))
        .get_matches();

    let file = args.value_of("input").unwrap();
    let key_infos = get_key_infos(file);

    if let Some(password) = args.value_of("password") {
        for key_info in &key_infos {
            if try_single_pass(password, key_info) {
                println!("Success!");
                std::process::exit(0);
            }
        }
    } else if let Some(password_file) = args.value_of("password-file") {
        match get_passwords(password_file) {
            Err(e) => {
                println!("Error reading password file: {}", e);
                std::process::exit(1);
            }
            Ok(passwords) => {
                for key_info in &key_infos {
                    if try_many_passwords(&passwords, key_info) {
                        println!("Success!");
                        std::process::exit(0);
                    }
                }
            }
        }
    } else {
        println!("Must specify password or password-file. Run with --help for details.");
        std::process::exit(1);
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

fn get_passwords(file: &str) -> Result<Vec<String>, std::io::Error> {
    let mut file = try!(File::open(file));
    let mut contents = String::new();
    try!(file.read_to_string(&mut contents));

    let lines: Vec<String> =
        contents.split('\n').map(|l| String::from(l.trim())).filter(|l| l.len() > 0).collect();
    Ok(lines)
}

fn try_single_pass(password: &str, key_info: &office_doc::EncryptedKeyInfo) -> bool {
    let block_keys = office_crypto::derive_keys(password, key_info);
    match office_crypto::try_decrypt(&block_keys, key_info) {
        Ok(result) => return result,
        Err(e) => println!("Error checking key: {}", e),
    }

    false
}

fn try_many_passwords(passwords: &Vec<String>, key_info: &office_doc::EncryptedKeyInfo) -> bool {
    for password in passwords {
        if try_single_pass(password, key_info) {
            return true;
        }
    }

    false
}
