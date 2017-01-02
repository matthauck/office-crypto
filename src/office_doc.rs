extern crate rustc_serialize;
extern crate xml;

use self::rustc_serialize::base64::FromBase64;
use self::xml::Element;
use std::fs::File;
use std::io::Read;
use std::collections::HashSet;

#[derive(Hash, Eq, PartialEq, Clone)]
pub struct EncryptedKeyInfo {
    pub salt: Vec<u8>,
    pub encrypted_verifier_hash_input: Vec<u8>,
    pub encrypted_verifier_hash_value: Vec<u8>,
    pub spin_count: u32,
    pub key_bits: u32,
}


// If we wanted to be fancy, we could write a parser for the MS Compound File Binary (CFB) format,
// but for our purposes, just finding the right XML blobs is good enough!
pub fn parse_doc(path: &str) -> Result<HashSet<EncryptedKeyInfo>, String> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) => return Err(format!("Error opening path: {}", e)),
    };

    let mut contents = Vec::new();
    match file.read_to_end(&mut contents) {
        Ok(_) => {}
        Err(e) => return Err(format!("Error reading file: {}", e)),
    }

    let mut keys: HashSet<EncryptedKeyInfo> = HashSet::new();

    let start_str = "<p:encryptedKey ";
    let mut last_start_index = 0;
    loop {
        if last_start_index + start_str.len() >= contents.len() {
            break;
        }

        let maybe_start_bytes = contents[last_start_index..(last_start_index + start_str.len())]
            .to_vec();
        let maybe_start_str = match String::from_utf8(maybe_start_bytes) {
            Ok(s) => s,
            Err(_) => {
                last_start_index += 1;
                continue;
            }
        };

        if maybe_start_str == start_str {
            let mut last_end_index = last_start_index;
            while last_end_index < contents.len() {
                if contents[last_end_index] == b'>' {
                    let xml_bytes = contents[last_start_index..(last_end_index + 1)].to_vec();
                    match String::from_utf8(xml_bytes) {
                        Ok(s) => {
                            // remove the namespace to make the parser happy.
                            let xml = s.replace("p:", "");
                            let element: Element = match xml.parse() {
                                Ok(el) => el,
                                Err(e) => {
                                    println!("Error parsing xml: {}", e);
                                    continue;
                                }
                            };
                            keys.insert(parse_key(element));
                            break;
                        }
                        Err(e) => {
                            println!("Error getting xml: {}", e);
                        }
                    };
                }
                last_end_index += 1;
            }
            last_start_index += last_end_index + 1;
        } else {
            last_start_index += 1;
        }
    }

    return Ok(keys);
}

fn parse_key(element: Element) -> EncryptedKeyInfo {
    let get_base64 = |attr: &str| {
        element.attributes
            .get(&(String::from(attr), None))
            .unwrap_or(&String::new())
            .from_base64()
            .unwrap_or(vec![])
    };

    let get_int = |attr: &str| {
        element.attributes
            .get(&(String::from(attr), None))
            .unwrap_or(&String::new())
            .parse::<u32>()
            .unwrap_or(0)
    };

    EncryptedKeyInfo {
        salt: get_base64("saltValue"),
        encrypted_verifier_hash_input: get_base64("encryptedVerifierHashInput"),
        encrypted_verifier_hash_value: get_base64("encryptedVerifierHashValue"),
        spin_count: get_int("spinCount"),
        key_bits: get_int("keyBits"),
    }
}
