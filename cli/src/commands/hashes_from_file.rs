use crate::errors::HashFileError;
use anyhow::Result;
use clap::{Args, ValueEnum};
use crossbeam_channel::{Receiver, Sender};
use hashassin_core::{utils::file_exists, HashAlgorithm, ProgressEvent};
use indicatif::{ProgressBar, ProgressDrawTarget, ProgressStyle};
use std::num::NonZeroUsize;

use crate::new_bar_extended;

const PROGRESS_BAR_TEMPLATE: &str =
    "[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {linear_per_sec} [{linear_eta}] {msg}";
const PROGRESS_BAR_CHARS: &str = "##-";

#[derive(Args, Debug)]
pub(crate) struct HashesFromFileOpts {
    /// Path to file to write passwords.
    #[clap(long)]
    in_path: String,

    /// Number of threads to use to compute md5s
    #[clap(long, default_value = "4")]
    threads: NonZeroUsize,

    /// Show progress?
    #[clap(long)]
    progress: bool,

    /// Number of md5s to read in before sending to a worker thread.
    #[clap(long, default_value = "1000")]
    chunk_size: usize,

    /// Output file to write md5s to
    #[clap(long)]
    out_path: String,

    /// What hashing algorithm to use.
    #[clap(long, value_enum)]
    algorithm: CliAlgorithm,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
pub enum CliAlgorithm {
    /// Md5
    Md5,

    /// Sha256
    Sha2,
    Sha512,

    Ripemd160,

    Ripemd320,
    Blake2b512,
    Blake2s256,
}

fn update_progress(
    progress_bar: &ProgressBar,
    receiver: Option<Receiver<ProgressEvent>>,
) -> Result<(), HashFileError> {
    let receiver = match receiver {
        Some(r) => r,
        None => return Err(HashFileError::ReceiverError),
    };

    while let Ok(event) = receiver.recv() {
        match event {
            ProgressEvent::NewInput => progress_bar.inc_length(1),
            ProgressEvent::InputMd5Hashed => progress_bar.inc(1),
            ProgressEvent::NewInputs(n) => progress_bar.inc_length(n),
        }
    }

    Ok(())
}

pub(crate) fn hashes_from_file(opts: &HashesFromFileOpts) -> Result<(), HashFileError> {
    let in_path = opts.in_path.clone();
    let num_threads = opts.threads;
    let chunk_size = opts.chunk_size;
    let out_path = opts.out_path.clone();

    if !file_exists(&in_path) {
        return Err(HashFileError::FileDoesNotExistError(in_path));
    }

    let algorithm = match opts.algorithm {
        CliAlgorithm::Md5 => HashAlgorithm::Md5,
        CliAlgorithm::Sha2 => HashAlgorithm::Sha2,
        CliAlgorithm::Sha512 => HashAlgorithm::Sha512,
        CliAlgorithm::Ripemd160 => HashAlgorithm::Ripemd160,
        CliAlgorithm::Ripemd320 => HashAlgorithm::Ripemd320,
        CliAlgorithm::Blake2b512 => HashAlgorithm::Blake2b512,
        CliAlgorithm::Blake2s256 => HashAlgorithm::Blake2s256,
    };

    let (h, progress_receiver) =
        if let Some((progress_sender, progress_receiver)) = pb_channel(opts) {
            let h = std::thread::spawn(move || {
                hashassin_core::compute_from_file(
                    &in_path,
                    &out_path,
                    num_threads,
                    Some(progress_sender),
                    chunk_size,
                    algorithm,
                );
            });

            (h, Some(progress_receiver))
        } else {
            let h = std::thread::spawn(move || {
                hashassin_core::compute_from_file(
                    &in_path,
                    &out_path,
                    num_threads,
                    None,
                    chunk_size,
                    algorithm,
                );
            });

            (h, None)
        };

    if opts.progress {
        let pb = ProgressBar::new(0);
        pb.set_style(
            new_bar_extended()
                .template(PROGRESS_BAR_TEMPLATE)
                .unwrap_or(ProgressStyle::default_bar())
                .progress_chars(PROGRESS_BAR_CHARS),
        );

        pb.set_draw_target(ProgressDrawTarget::stderr_with_hz(4));

        update_progress(&pb, progress_receiver)?;

        pb.finish();
    }

    //TODO handle this unwrap
    h.join().unwrap();

    Ok(())
}

fn pb_channel(
    opts: &HashesFromFileOpts,
) -> Option<(Sender<ProgressEvent>, Receiver<ProgressEvent>)> {
    if opts.progress {
        Some(crossbeam_channel::unbounded())
    } else {
        None
    }
}
