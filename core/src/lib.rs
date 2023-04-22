//! This crate gives us some basic tools for creating a rainbow table.
use crossbeam_channel::Sender;

use db::DB;
use digest::Digest;
use itertools::Itertools;
use md5::Md5;
use passwords::PasswordGenerator;
use rayon::prelude::{IntoParallelIterator, ParallelBridge, ParallelIterator};
use sha2::Sha256;
use std::io::{BufRead, BufReader, Write};
use std::thread::JoinHandle;
use std::{fs::File, io::BufWriter, num::NonZeroUsize};
use tracing::trace;
use utils::{hex_string_to_vec, vec_to_hex_string, write_file};
mod errors;
use anyhow::{Ok, Result};
use blake2::{Blake2b512, Blake2s256};
use ripemd::{Ripemd160, Ripemd320};
use sha2::Sha512;

pub mod db;
pub mod passwords;
pub mod utils;

pub fn hash_input<D: Digest>(algo: HashAlgorithm, input: &str) -> Result<Vec<u8>, anyhow::Error> {
    let mut rainbow_table_db = DB::new()?;

    match algo {
        HashAlgorithm::Md5 => {
            if let std::result::Result::Ok(val) =
                rainbow_table_db.get(HashAlgorithm::MD5_STR, input)
            {
                return Ok(hex_string_to_vec(val));
            }
        }
        HashAlgorithm::Sha2 => {
            if let std::result::Result::Ok(val) =
                rainbow_table_db.get(HashAlgorithm::SHA2_STR, input)
            {
                return Ok(hex_string_to_vec(val));
            }
        }
        HashAlgorithm::Sha512 => {
            if let std::result::Result::Ok(val) =
                rainbow_table_db.get(HashAlgorithm::SHA_512_STR, input)
            {
                return Ok(hex_string_to_vec(val));
            }
        }
        HashAlgorithm::Ripemd160 => {
            if let std::result::Result::Ok(val) =
                rainbow_table_db.get(HashAlgorithm::RIPEMD_160_STR, input)
            {
                return Ok(hex_string_to_vec(val));
            }
        }
        HashAlgorithm::Ripemd320 => {
            if let std::result::Result::Ok(val) =
                rainbow_table_db.get(HashAlgorithm::RIPEMD_320_STR, input)
            {
                return Ok(hex_string_to_vec(val));
            }
        }
        HashAlgorithm::Blake2s256 => {
            if let std::result::Result::Ok(val) =
                rainbow_table_db.get(HashAlgorithm::BLAKE_2S_256_STR, input)
            {
                return Ok(hex_string_to_vec(val));
            }
        }
        HashAlgorithm::Blake2b512 => {
            if let std::result::Result::Ok(val) =
                rainbow_table_db.get(HashAlgorithm::BLAKE_2B_512_STR, input)
            {
                return Ok(hex_string_to_vec(val));
            }
        }
    }

    let output: Vec<u8> = D::new()
        .chain_update(input.as_bytes())
        .finalize()
        .as_slice()
        .into();

    match algo {
        HashAlgorithm::Md5 => rainbow_table_db.set(
            HashAlgorithm::MD5_STR,
            input,
            vec_to_hex_string(&output).as_str(),
        )?,
        HashAlgorithm::Sha2 => rainbow_table_db.set(
            HashAlgorithm::SHA2_STR,
            input,
            vec_to_hex_string(&output).as_str(),
        )?,
        HashAlgorithm::Sha512 => rainbow_table_db.set(
            HashAlgorithm::SHA_512_STR,
            input,
            vec_to_hex_string(&output).as_str(),
        )?,
        HashAlgorithm::Ripemd160 => rainbow_table_db.set(
            HashAlgorithm::RIPEMD_160_STR,
            input,
            vec_to_hex_string(&output).as_str(),
        )?,
        HashAlgorithm::Ripemd320 => rainbow_table_db.set(
            HashAlgorithm::RIPEMD_320_STR,
            input,
            vec_to_hex_string(&output).as_str(),
        )?,
        HashAlgorithm::Blake2s256 => rainbow_table_db.set(
            HashAlgorithm::BLAKE_2S_256_STR,
            input,
            vec_to_hex_string(&output).as_str(),
        )?,
        HashAlgorithm::Blake2b512 => rainbow_table_db.set(
            HashAlgorithm::BLAKE_2B_512_STR,
            input,
            vec_to_hex_string(&output).as_str(),
        )?,
    }

    Ok(output)
}

#[derive(Debug, Clone, Copy)]
pub enum HashAlgorithm {
    /// md5 hasher
    Md5,

    /// sha2 hasher
    Sha2,

    Sha512,

    Ripemd160,

    Ripemd320,
    Blake2b512,
    Blake2s256,
}

impl HashAlgorithm {
    pub const SHA2_STR: &'static str = "sha2";
    pub const MD5_STR: &'static str = "md5";
    pub const SHA_512_STR: &'static str = "sha512";
    pub const RIPEMD_160_STR: &'static str = "ripemd160";
    pub const RIPEMD_320_STR: &'static str = "ripemd320";
    pub const BLAKE_2B_512_STR: &'static str = "blake2b512";
    pub const BLAKE_2S_256_STR: &'static str = "blake2s256";
}

pub fn add(left: usize, right: usize) -> usize {
    left + right
}

pub enum ProgressEvent {
    /// We have a new input that needs to be hashed
    NewInput,

    /// We have completed an md5 hash of an input
    InputMd5Hashed,

    /// We have received N new inputs that need to be hashed
    NewInputs(u64),
}

/// Use rayon to do our parallelism
pub fn compute_with_rayon(
    generator: PasswordGenerator,
    num_threads: NonZeroUsize,
    progress_sender: Sender<ProgressEvent>,
    algorithm: HashAlgorithm,
) -> Result<()> {
    rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads.into())
        .build_global()?;

    let compute = |password: String| -> Result<()> {
        progress_sender.send(ProgressEvent::NewInput)?;
        let _x = match algorithm {
            HashAlgorithm::Md5 => hash_input::<Md5>(HashAlgorithm::Md5, &password),
            HashAlgorithm::Sha2 => hash_input::<Sha256>(HashAlgorithm::Sha2, &password),
            HashAlgorithm::Sha512 => {
                hash_input::<Sha512>(HashAlgorithm::Sha512, &password)
            }
            HashAlgorithm::Ripemd160 => {
                hash_input::<Ripemd160>(HashAlgorithm::Ripemd160, &password)
            }
            HashAlgorithm::Ripemd320 => {
                hash_input::<Ripemd320>(HashAlgorithm::Ripemd320, &password)
            }
            HashAlgorithm::Blake2b512 => {
                hash_input::<Blake2b512>(HashAlgorithm::Blake2b512, &password)
            }
            HashAlgorithm::Blake2s256 => {
                hash_input::<Blake2s256>(HashAlgorithm::Blake2s256, &password)
            }
        };
        
        // we want to increment the progress bar here
        progress_sender.send(ProgressEvent::InputMd5Hashed)?;
        Ok(())
    };

    let generator = generator.par_bridge();

    generator.into_par_iter().try_for_each(compute)?;

    Ok(())
}

/// Save generated passwords to disk
pub fn save_passwords_to_disk(
    file_path: &str,
    generator: PasswordGenerator,
    progress_sender: Option<Sender<ProgressEvent>>,
) -> Result<()> {
    let mut content = String::from("");

    for password in generator {
        if let Some(ps) = &progress_sender {
            ps.send(ProgressEvent::NewInput)?;
        }

        content.push_str(&password);
        content.push('\n');

        if let Some(ps) = &progress_sender {
            ps.send(ProgressEvent::InputMd5Hashed)?;
        }
    }

    write_file(file_path, content.as_str())?;

    Ok(())
}

/// Computes hashes of passwords stored in a file and write them to disk.
pub fn compute_from_file(
    in_path: &str,
    out_path: &str,
    num_threads: NonZeroUsize,
    progress_sender: Option<Sender<ProgressEvent>>,
    chunk_size: usize,
    algorithm: HashAlgorithm,
) -> Result<()> {
    let f_in = File::open(in_path)?;
    let f_in = BufReader::new(f_in);

    let f_out = File::create(out_path)?;
    let mut f_out = BufWriter::new(f_out);

    // We are going to spawn N threads pased in command line (or wahtever)
    // set up a multicomsumer channel
    // for each input,. main thread sends the input on the channel
    // whatever thread is available, receives the input, then hashes it
    let (plain_text_tx, plain_text_rx) = crossbeam_channel::unbounded();

    // all this looping etc., needs to be happening in a separate thread.

    let p = progress_sender.clone();
    std::thread::spawn(move || -> Result<()> {
        let progress_sender = p;

        f_in.lines()
            .chunks(chunk_size)
            .into_iter()
            .try_for_each(|password_chunk| {
                let passwords = password_chunk
                    .filter_map(|v| {
                        if let std::result::Result::Ok(password) = v {
                            Some(password)
                        } else {
                            None
                        }
                    })
                    .collect::<Vec<_>>();

                if let Some(progress_sender) = &progress_sender {
                    let len = passwords.len().try_into()?;
                    progress_sender.send(ProgressEvent::NewInputs(len))?;
                }

                plain_text_tx.send(passwords)?;

                Ok(())
            })?;

        Ok(())
    });

    // channel to send hashed passords to a thread for writing to disk
    let (md5_tx, md5_rx) = crossbeam_channel::unbounded();

    // spawn N threads to compute the md5s
    let handles = start_compute_threads(
        num_threads,
        plain_text_rx,
        md5_tx,
        progress_sender,
        algorithm,
    );

    // now we need a thread that will receive the hashed passwords and write them to disk.
    // this thread will receive any hashed passwords and then write them to disk
    let h = std::thread::spawn(move || {
        while let std::result::Result::Ok(hashed_password) = md5_rx.recv() {
            // we have gotten a hashed password
            // now we need to write it to disk
            f_out.write_all(&hashed_password).unwrap();
        }
        trace!("flushing output file");
        f_out.flush().unwrap();
    });

    // wait for the compute threads to finish.
    for h in handles {
        h.join().unwrap();
    }

    // wait for the file write thread to finish
    h.join().unwrap();

    Ok(())
}

fn start_compute_threads(
    num_threads: NonZeroUsize,
    plain_text_rx: crossbeam_channel::Receiver<Vec<String>>,
    md5_tx: Sender<Vec<u8>>,
    progress_sender: Option<Sender<ProgressEvent>>,
    algorithm: HashAlgorithm,
) -> Vec<JoinHandle<()>> {
    let mut handles = Vec::new();
    for i in 0..num_threads.into() {
        let plain_text_rx = plain_text_rx.clone();
        let md5_tx = md5_tx.clone();
        let progress_sender = progress_sender.clone();
        let h = std::thread::spawn(move || {
            while let std::result::Result::Ok(passwords) = plain_text_rx.recv() {
                for password in passwords {
                    let hashed_password = match algorithm {
                        HashAlgorithm::Md5 => hash_input::<Md5>(HashAlgorithm::Md5, &password),
                        HashAlgorithm::Sha2 => hash_input::<Sha256>(HashAlgorithm::Sha2, &password),
                        HashAlgorithm::Sha512 => {
                            hash_input::<Sha512>(HashAlgorithm::Sha512, &password)
                        }
                        HashAlgorithm::Ripemd160 => {
                            hash_input::<Ripemd160>(HashAlgorithm::Ripemd160, &password)
                        }
                        HashAlgorithm::Ripemd320 => {
                            hash_input::<Ripemd320>(HashAlgorithm::Ripemd320, &password)
                        }
                        HashAlgorithm::Blake2b512 => {
                            hash_input::<Blake2b512>(HashAlgorithm::Blake2b512, &password)
                        }
                        HashAlgorithm::Blake2s256 => {
                            hash_input::<Blake2s256>(HashAlgorithm::Blake2s256, &password)
                        }
                    };

                    trace!("{:?}", hashed_password);
                    md5_tx.send(hashed_password.unwrap()).unwrap();

                    if let Some(progress_sender) = &progress_sender {
                        // we want to increment the progress bar here
                        progress_sender.send(ProgressEvent::InputMd5Hashed).unwrap();
                    }
                }
            }
            trace!("Thread {} had finished.", i);
        });

        handles.push(h);
    }

    handles
}

/// Computes an md5 hash for each password generated by
/// a [`PasswordGenerator`].
///
pub fn compute_with_threads_with_password_generator(
    generator: PasswordGenerator,
    num_threads: NonZeroUsize,
    progress_sender: Sender<ProgressEvent>,
    algorithm: HashAlgorithm,
) {
    // We are going to spawn N threads pased in command line (or wahtever)
    // set up a multicomsumer channel
    // for each input,. main thread sends the input on the channel
    // whatever thread is available, receives the input, then hashes it
    let (tx, rx) = crossbeam_channel::unbounded();

    // all this looping etc., needs to be happening in a separate thread.

    let p = progress_sender.clone();
    std::thread::spawn(move || {
        let progress_sender = p;
        for passwords in &generator.into_iter().chunks(10_000) {
            // report that we have one more string to hash
            // or, because we know the length of inputs before hand
            // we could set it at once.
            // https://docs.rs/indicatif/latest/indicatif/struct.ProgressBar.html#method.inc_length
            // for 0..passwords.
            let passwords = passwords.collect::<Vec<_>>();

            for _i in 0..passwords.len() {
                progress_sender.send(ProgressEvent::NewInput).unwrap();
            }
            // progress_sender
            //     .send(ProgressEvent::NewInputs(
            //         passwords.len().try_into().unwrap(),
            //     ))
            //     .unwrap();

            // send the input onto the channel
            tx.send(passwords).unwrap();
        }
    });

    let mut handles = Vec::new();

    // spawn 4 threads
    for _i in 0..num_threads.into() {
        let rx = rx.clone();
        let progress_sender = progress_sender.clone();
        let h = std::thread::spawn(move || {
            while let std::result::Result::Ok(passwords) = rx.recv() {
                for password in passwords {
                    let _x = match algorithm {
                        HashAlgorithm::Md5 => hash_input::<Md5>(HashAlgorithm::Md5, &password),
                        HashAlgorithm::Sha2 => hash_input::<Sha256>(HashAlgorithm::Sha2, &password),
                        HashAlgorithm::Sha512 => {
                            hash_input::<Sha512>(HashAlgorithm::Sha512, &password)
                        }
                        HashAlgorithm::Ripemd160 => {
                            hash_input::<Ripemd160>(HashAlgorithm::Ripemd160, &password)
                        }
                        HashAlgorithm::Ripemd320 => {
                            hash_input::<Ripemd320>(HashAlgorithm::Ripemd320, &password)
                        }
                        HashAlgorithm::Blake2b512 => {
                            hash_input::<Blake2b512>(HashAlgorithm::Blake2b512, &password)
                        }
                        HashAlgorithm::Blake2s256 => {
                            hash_input::<Blake2s256>(HashAlgorithm::Blake2s256, &password)
                        }
                    };

                    // we want to increment the progress bar here
                    progress_sender.send(ProgressEvent::InputMd5Hashed).unwrap();
                }

                // thread::sleep(Duration::from_millis(1_000));
            }
        });

        handles.push(h);
    }

    for h in handles {
        h.join().unwrap();
    }
}

/// DO WE REALLY WANT TO KEEP THIS FUNCTION?
///
/// Computes an md5 for each of the strings in input
/// Sends progress events to a listener.
pub fn compute_with_threads(
    inputs: Vec<String>,
    num_threads: NonZeroUsize,
    progress_sender: Sender<ProgressEvent>,
    algorithm: HashAlgorithm,
) {
    // We are going to spawn N threads pased in command line (or wahtever)
    // set up a multicomsumer channel
    // for each input,. main thread sends the input on the channel
    // whatever thread is available, receives the input, then hashes it
    let (tx, rx) = crossbeam_channel::unbounded();

    // all this looping etc., needs to be happening in a separate thread.

    let p = progress_sender.clone();
    std::thread::spawn(move || {
        let progress_sender = p;
        for input in inputs {
            // report that we have one more string to hash
            // or, because we know the length of inputs before hand
            // we could set it at once.
            // https://docs.rs/indicatif/latest/indicatif/struct.ProgressBar.html#method.inc_length
            progress_sender.send(ProgressEvent::NewInput).unwrap();

            // send the input onto the channel
            tx.send(input).unwrap();
        }
    });

    let mut handles = Vec::new();

    // spawn 4 threads
    for _i in 0..num_threads.into() {
        let rx = rx.clone();
        let progress_sender = progress_sender.clone();
        let h = std::thread::spawn(move || {
            while let std::result::Result::Ok(input) = rx.recv() {
                let _x = match algorithm {
                    HashAlgorithm::Md5 => hash_input::<Md5>(HashAlgorithm::Md5, &input),
                    HashAlgorithm::Sha2 => hash_input::<Sha256>(HashAlgorithm::Sha2, &input),
                    HashAlgorithm::Sha512 => {
                        hash_input::<Sha512>(HashAlgorithm::Sha512, &input)
                    }
                    HashAlgorithm::Ripemd160 => {
                        hash_input::<Ripemd160>(HashAlgorithm::Ripemd160, &input)
                    }
                    HashAlgorithm::Ripemd320 => {
                        hash_input::<Ripemd320>(HashAlgorithm::Ripemd320, &input)
                    }
                    HashAlgorithm::Blake2b512 => {
                        hash_input::<Blake2b512>(HashAlgorithm::Blake2b512, &input)
                    }
                    HashAlgorithm::Blake2s256 => {
                        hash_input::<Blake2s256>(HashAlgorithm::Blake2s256, &input)
                    }
                };

                // we want to increment the progress bar here
                progress_sender.send(ProgressEvent::InputMd5Hashed).unwrap();
                // thread::sleep(Duration::from_millis(1_000));
                // println!("{i} - {:?}", x)
            }
        });

        handles.push(h);
    }

    for h in handles {
        h.join().unwrap();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn simple_test() {
        let x = hash_input::<Md5>(HashAlgorithm::Md5, "some other hello world");
        assert_eq!(x.unwrap(), hex!("d195275423cb8ae7ad67ba821eae6c9d"));

        let x = hash_input::<Sha512>(HashAlgorithm::Sha512, "some other hello world");
        assert_eq!(x.unwrap(), hex!("f51a9075b911e281a673f2c138a46636671b7980dd49f2ce989823823219a9bd76f661cd764ce7c39939b0de06750949d29752d46409ed3bc0280ae502900f18"));

        let x = hash_input::<Ripemd160>(HashAlgorithm::Ripemd160, "Hello world!");
        assert_eq!(x.unwrap(), hex!("7f772647d88750add82d8e1a7a3e5c0902a346a3"));

        let x = hash_input::<Ripemd320>(HashAlgorithm::Ripemd320, "Hello world!");

        assert_eq!(
            x.unwrap(),
            hex!(
                "f1c1c231d301abcf2d7daae0269ff3e7bc68e623ad723aa068d316b056d26b7d1bb6f0cc0f28336d"
            )
        );

        let x = hash_input::<Blake2b512>(HashAlgorithm::Blake2b512,"Hello world!");
        assert_eq!(x.unwrap(), hex!("0389abc5ab1e8e170e95aff19d341ecbf88b83a12dd657291ec1254108ea97352c2ff5116902b9fe4021bfe5a6a4372b0f7c9fc2d7dd810c29f85511d1e04c59"));

        let x = hash_input::<Blake2s256>(HashAlgorithm::Blake2s256,"Hello world!");

        assert_eq!(
            x.unwrap(),
            hex!("c63813a8f804abece06213a46acd04a2d738c8e7a58fbf94bfe066a9c7f89197")
        );
    }
}
