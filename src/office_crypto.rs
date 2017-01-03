extern crate crypto;
extern crate ring;

use office_doc::EncryptedKeyInfo;

// https://msdn.microsoft.com/en-us/library/dd950165(v=office.12).aspx
const BLOCK_KEY_VERIFIER_HASH_INPUT: [u8; 8] = [0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79];
const BLOCK_KEY_VERIFIER_HASH_VALUE: [u8; 8] = [0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e];

#[derive(Hash, Eq, PartialEq)]
pub struct BlockKeys {
    pub hash_input_key: Vec<u8>,
    pub hash_value_key: Vec<u8>,
}

pub fn try_decrypt(block_keys: &BlockKeys, key_info: &EncryptedKeyInfo) -> Result<bool, String> {
    let verifier_hash_input = try!(decrypt_and_truncate(&key_info.encrypted_verifier_hash_input, &block_keys.hash_input_key, &key_info));
    let verifier_hash_value = try!(decrypt_and_truncate(&key_info.encrypted_verifier_hash_value, &block_keys.hash_value_key, &key_info));

    let mut ctx = new_hash(&key_info.hash_algorithm);
    ctx.update(verifier_hash_input.as_slice());
    let verifier_hash_input_hash = ctx.finish();

    return Ok(verifier_hash_input_hash.as_ref() == verifier_hash_value.as_slice());
}

pub fn derive_keys(password: &str, key_info: &EncryptedKeyInfo) -> BlockKeys {
    let pass_hash = hash_pass(&password,
                              &key_info.salt,
                              key_info.spin_count,
                              &key_info.hash_algorithm);

    BlockKeys {
        hash_input_key: derive_key(&pass_hash,
                                   &BLOCK_KEY_VERIFIER_HASH_INPUT,
                                   key_info.key_bits,
                                   &key_info.hash_algorithm),

        hash_value_key: derive_key(&pass_hash,
                                   &BLOCK_KEY_VERIFIER_HASH_VALUE,
                                   key_info.key_bits,
                                   &key_info.hash_algorithm),
    }
}

fn new_hash(hash_algorithm: &String) -> ring::digest::Context {
    if hash_algorithm == "SHA512" {
        ring::digest::Context::new(&ring::digest::SHA512)
    } else if hash_algorithm == "SHA384" {
        ring::digest::Context::new(&ring::digest::SHA384)
    } else if hash_algorithm == "SHA256" {
        ring::digest::Context::new(&ring::digest::SHA256)
    } else if hash_algorithm == "SHA1" {
        ring::digest::Context::new(&ring::digest::SHA1)
    } else {
        panic!("Unknown hash algorithm: {}", hash_algorithm);
    }
}

fn hash_pass(pass: &str, salt: &Vec<u8>, count: u32, hash_algorithm: &String) -> Vec<u8> {
    let mut pass_bytes1: Vec<u8> = Vec::new();
    pass_bytes1.extend_from_slice(&pass.as_bytes());

    let mut pass_bytes2: Vec<u8> = Vec::new();
    for b in &pass_bytes1 {
        pass_bytes2.push(*b);
        pass_bytes2.push(0);
    }

    let mut ctx = new_hash(hash_algorithm);

    ctx.update(salt.as_slice());
    ctx.update(pass_bytes2.as_slice());

    let mut hash: Vec<u8> = Vec::new();
    hash.extend_from_slice(ctx.finish().as_ref());

    for i in 0..(count) {
        let i_str = vec![((i >> 0) & 0x000000FF) as u8,
                         ((i >> 8) & 0x000000FF) as u8,
                         ((i >> 16) & 0x000000FF) as u8,
                         ((i >> 24) & 0x000000FF) as u8];

        let mut ctx = new_hash(hash_algorithm);
        ctx.update(i_str.as_slice());
        ctx.update(hash.as_slice());

        hash.clear();
        hash.extend_from_slice(ctx.finish().as_ref());
    }

    hash
}

fn derive_key(base_hash: &[u8],
              block_key: &[u8],
              key_bits: u32,
              hash_algorithm: &String)
              -> Vec<u8> {
    let mut ctx = new_hash(hash_algorithm);
    ctx.update(base_hash);
    ctx.update(block_key);

    let mut key: Vec<u8> = Vec::new();
    key.extend_from_slice(ctx.finish().as_ref());

    let key_bytes = (key_bits / 8) as usize;
    if key.len() > key_bytes {
        key.truncate(key_bytes);
    } else {
        while key.len() < key_bytes {
            key.push(0x36);
        }
    }

    key
}

fn decrypt_and_truncate(encrypted_data: &[u8], block_key: &[u8], key_info: &EncryptedKeyInfo) -> Result<Vec<u8>, String> {
    let mut value = match decrypt(encrypted_data, block_key, &key_info.salt, &key_info.key_bits) {
        Ok(data) => data,
        Err(e) => return Err(format!("Error decrypting data: {:?}", e)),
    };
    value.truncate(key_info.hash_size as usize);

    Ok(value)
}

fn decrypt(encrypted_data: &[u8],
           key: &[u8],
           iv: &[u8],
           key_bits: &u32)
           -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
    use self::crypto::{buffer, aes, blockmodes};
    use self::crypto::buffer::{ReadBuffer, WriteBuffer, BufferResult};

    let key_size;
    if *key_bits == 256 {
        key_size = aes::KeySize::KeySize256;
    } else if *key_bits == 128 {
        key_size = aes::KeySize::KeySize128;
    } else {
        panic!("Unknown key size: {}", key_bits);
    }

    let mut decryptor = aes::cbc_decryptor(key_size, key, iv, blockmodes::NoPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = try!(decryptor.decrypt(&mut read_buffer, &mut write_buffer, true));
        final_result.extend(write_buffer.take_read_buffer().take_remaining().iter().map(|&i| i));
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}
