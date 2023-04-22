use anyhow::{Ok, Result};
use std::{fs::File, io::Write, path::Path, process};

pub fn file_exists(path: &str) -> bool {
    Path::new(path).exists()
}

pub fn exit_1() {
    process::exit(1);
}

pub fn write_file(path: &str, content: &str) -> Result<()> {
    let mut file = File::create(path)?;
    file.write_all(content.as_bytes())?;

    Ok(())
}

pub fn write_bytes_to_file(path: &str, content: Vec<u8>) -> Result<()> {
    let mut file = File::create(path)?;
    file.write_all(&content)?;
    Ok(())
}

pub fn vec_to_string(vec: &[u8]) -> String {
    let mut s = String::new();
    for byte in vec {
        s.push(*byte as char);
    }
    s
}

pub fn string_to_vec(s: &str) -> Vec<u8> {
    let mut v = Vec::new();
    for c in s.chars() {
        v.push(c as u8);
    }
    v
}

pub fn vec_to_hex_string(vec: &[u8]) -> String {
    let hex_chars: Vec<String> = vec.iter().map(|b| format!("{:02x}", b)).collect();
    hex_chars.join("")
}

pub fn hex_string_to_vec(hex_string: &str) -> Vec<u8> {
    let mut vec = Vec::new();
    let mut hex_chars = hex_string.chars().peekable();
    while let Some(c1) = hex_chars.next() {
        if let Some(c2) = hex_chars.next() {
            if let std::result::Result::Ok(byte) = u8::from_str_radix(&format!("{}{}", c1, c2), 16)
            {
                vec.push(byte);
            } else {
                break;
            }
        } else {
            break;
        }
    }
    vec
}
