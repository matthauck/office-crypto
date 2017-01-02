extern crate crypto;
extern crate ring;

use office_doc;

// https://msdn.microsoft.com/en-us/library/dd950165(v=office.12).aspx
const BLOCK_KEY_VERIFIER_HASH_INPUT: [u8; 8] = [0xfe, 0xa7, 0xd2, 0x76, 0x3b, 0x4b, 0x9e, 0x79];
const BLOCK_KEY_VERIFIER_HASH_VALUE: [u8; 8] = [0xd7, 0xaa, 0x0f, 0x6d, 0x30, 0x61, 0x34, 0x4e];

pub fn verify(password: &str, key_info: &office_doc::EncryptedKeyInfo) -> Result<bool, String> {
    let pass_hash = hash_pass(&password, &key_info.salt, key_info.spin_count);

    let hash_input_key = derive_key(&pass_hash,
                                    &BLOCK_KEY_VERIFIER_HASH_INPUT,
                                    key_info.key_bits);
    let hash_value_key = derive_key(&pass_hash,
                                    &BLOCK_KEY_VERIFIER_HASH_VALUE,
                                    key_info.key_bits);

    let verifier_hash_input = match decrypt(&key_info.encrypted_verifier_hash_input,
                                            &hash_input_key,
                                            &key_info.salt) {
        Ok(data) => data,
        Err(e) => return Err(format!("Error decrypting encrypted_verifier_hash_input, {:?}", e)),
    };

    let verifier_hash_input_hash = ring::digest::digest(&ring::digest::SHA512,
                                                        verifier_hash_input.as_slice());
    let verifier_hash = match decrypt(&key_info.encrypted_verifier_hash_value,
                                      &hash_value_key,
                                      &key_info.salt) {
        Ok(data) => data,
        Err(e) => {
            return Err(format!("Error decrypting encrypted_verifier_hash_value: {:?}", e));
        }
    };

    return Ok(verifier_hash_input_hash.as_ref() == verifier_hash.as_slice());
}

fn hash_pass(pass: &str, salt: &Vec<u8>, count: u32) -> Vec<u8> {
    let mut pass_bytes1: Vec<u8> = Vec::new();
    pass_bytes1.extend_from_slice(&pass.as_bytes());

    let mut pass_bytes2: Vec<u8> = Vec::new();
    for b in &pass_bytes1 {
        pass_bytes2.push(*b);
        pass_bytes2.push(0);
    }

    let mut ctx = ring::digest::Context::new(&ring::digest::SHA512);

    ctx.update(salt.as_slice());
    ctx.update(pass_bytes2.as_slice());

    let mut hash: Vec<u8> = Vec::new();
    hash.extend_from_slice(ctx.finish().as_ref());

    for i in 0..(count) {
        let i_str = vec![((i >> 0) & 0x000000FF) as u8,
                         ((i >> 8) & 0x000000FF) as u8,
                         ((i >> 16) & 0x000000FF) as u8,
                         ((i >> 24) & 0x000000FF) as u8];

        let mut ctx = ring::digest::Context::new(&ring::digest::SHA512);
        ctx.update(i_str.as_slice());
        ctx.update(hash.as_slice());

        hash.clear();
        hash.extend_from_slice(ctx.finish().as_ref());
    }

    hash
}

fn derive_key(base_hash: &[u8], block_key: &[u8], key_bits: u32) -> Vec<u8> {
    let mut ctx = ring::digest::Context::new(&ring::digest::SHA512);
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

fn decrypt(encrypted_data: &[u8],
           key: &[u8],
           iv: &[u8])
           -> Result<Vec<u8>, crypto::symmetriccipher::SymmetricCipherError> {
    use self::crypto::{buffer, aes, blockmodes};
    use self::crypto::buffer::{ReadBuffer, WriteBuffer, BufferResult};

    let mut decryptor =
        aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, blockmodes::NoPadding);

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
