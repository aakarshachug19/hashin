use anyhow::{anyhow, Result};

use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::{BufReader, Write},
    path::Path,
};

use crate::{utils::write_file, HashAlgorithm};

pub fn file_exists(path: &str) -> bool {
    Path::new(path).exists()
}

pub struct DB {
    hashes: HashMap<String, HashMap<String, String>>,
}

const DB_FOLDER_NAME: &str = "./db";
const ALGORITHMS: [&str; 7] = [
    HashAlgorithm::MD5_STR,
    HashAlgorithm::SHA2_STR,
    HashAlgorithm::SHA_512_STR,
    HashAlgorithm::RIPEMD_160_STR,
    HashAlgorithm::RIPEMD_320_STR,
    HashAlgorithm::BLAKE_2S_256_STR,
    HashAlgorithm::BLAKE_2B_512_STR,
];

impl DB {
    pub fn new() -> Result<DB, anyhow::Error> {
        if !Path::new(DB_FOLDER_NAME).exists() {
            fs::create_dir(DB_FOLDER_NAME)?;
        }

        let mut hashes: HashMap<String, HashMap<String, String>> = HashMap::new();

        for algo in ALGORITHMS.iter() {
            let p = format!("./db/{}.json", algo);

            if !file_exists(p.as_str()) {
                let mut file = OpenOptions::new().write(true).create(true).open(&p)?;
                file.write_all("{}".as_bytes())?;
            }

            hashes.insert(algo.to_owned().to_owned(), read_json_file(&p)?);
        }

        Ok(DB { hashes })
    }

    pub fn set(&mut self, algo: &str, key: &str, value: &str) -> Result<(), anyhow::Error> {
        let hash = self
            .hashes
            .get_mut(algo)
            .ok_or_else(|| anyhow!("Unsupported algorithm: {}", algo))?;

        hash.insert(key.to_owned(), value.to_owned());
        let json_string = serde_json::to_string(hash)?;
        let file_path = format!("{}/{}.json", DB_FOLDER_NAME, algo);
        write_file(&file_path, &json_string)?;

        Ok(())
    }

    pub fn get(&self, algo: &str, key: &str) -> Result<&String, anyhow::Error> {
        let hash = self
            .hashes
            .get(algo)
            .ok_or_else(|| anyhow!("Unsupported algorithm: {}", algo))?;

        hash.get(key).ok_or_else(|| anyhow!("Hash not found"))
    }
}

fn read_json_file(path: &str) -> anyhow::Result<HashMap<String, String>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let words: HashMap<String, String> = serde_json::from_reader(reader)?;

    Ok(words)
}
