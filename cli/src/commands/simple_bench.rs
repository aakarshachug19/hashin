use anyhow::{anyhow, Result};
use clap::Args;
use hashassin_core::{
    passwords::{CharSet, PasswordGenerator},
    ProgressEvent, HashAlgorithm,
};
use indicatif::{ProgressBar, ProgressDrawTarget};
use std::num::NonZeroUsize;

use crate::new_bar_extended;

use super::CliAlgorithm;

#[derive(Args, Debug)]
pub(crate) struct SimpleBenchOpts {
    // The string to input
    // #[clap(long)]
    // input: String,
    /// Comma separated list of inputs.
    #[clap(long, env = "INPUTS", use_value_delimiter = true)]
    inputs: Option<Vec<String>>,

    /// The number of threads to use for computing hashes
    #[clap(long, default_value = "4", env = "NUM_THREADS")]
    threads: NonZeroUsize,

    /// Should we collect() results from the password generator instead of using it as an iterator?
    #[clap(long)]
    collect: bool,

    /// Use rayon
    #[clap(long, conflicts_with = "collect")]
    rayon: bool,

    /// Minimum password length
    #[clap(long, default_value = "1")]
    min_length: NonZeroUsize,

    /// Max password length
    #[clap(long, default_value = "4")]
    max_length: NonZeroUsize,

    /// What hashing algorithm to use.
    #[clap(long, value_enum, default_value = "md5")]
    algorithm: CliAlgorithm,
}

pub(crate) fn simple_bench(opts: &SimpleBenchOpts) -> Result<()> {
    let num_threads = opts.threads;

    let (tx, progress_receiver) = crossbeam_channel::unbounded();

    let mut handles = Vec::new();

    // we will fill the progress bar as data comes in.
    let pb = ProgressBar::new(0);
    // ProgressBar::new(0);

    let algorithm = match opts.algorithm {
        CliAlgorithm::Md5 => HashAlgorithm::Md5,
        CliAlgorithm::Sha2 => HashAlgorithm::Sha2,
        CliAlgorithm::Sha512 => HashAlgorithm::Sha512,
        CliAlgorithm::Ripemd160 => HashAlgorithm::Ripemd160,
        CliAlgorithm::Ripemd320 => HashAlgorithm::Ripemd320,
        CliAlgorithm::Blake2b512 => HashAlgorithm::Blake2b512,
        CliAlgorithm::Blake2s256 => HashAlgorithm::Blake2s256,
    };

    // the inputs were passed via cli
    if opts.inputs.is_some() {
        let passwords = opts.inputs.clone().unwrap();
        // pb = ProgressBar::new(passwords.len().try_into()?);

        let h = std::thread::spawn(move || {
            hashassin_core::compute_with_threads(passwords, num_threads, tx,algorithm);
        });

        handles.push(h);
    } else {
        // we will be using our generator
        let generator = PasswordGenerator::new(
            opts.min_length.into(),
            opts.max_length.into(),
            CharSet::LowerAlpha | CharSet::Numeric | CharSet::UpperAlpha,
        )
        .map_err(|_| anyhow!("error when creating new password generator"))?;

        // we have an option to `collect()` things from the generator.
        // this will (theoretically) allow us to isolate any performance
        // issues related to the generator itself.
        let h = if opts.collect {
            let passwords = generator.collect::<Vec<_>>();
            std::thread::spawn(move || {
                hashassin_core::compute_with_threads(passwords, num_threads, tx,algorithm);
            })
        } else if opts.rayon {
            std::thread::spawn(move || {
                hashassin_core::compute_with_rayon(generator, num_threads, tx,algorithm);
            })
        } else {
            std::thread::spawn(move || {
                hashassin_core::compute_with_threads_with_password_generator(
                    generator,
                    num_threads,
                    tx,
                    algorithm
                );
            })
        };

        handles.push(h);
    }

    pb.set_style(new_bar_extended().template(
            "[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {linear_per_sec} [{linear_eta}] {msg}"
        )
        .unwrap()
        .progress_chars("##-"),
    );

    pb.set_draw_target(ProgressDrawTarget::stderr_with_hz(4));

    while let Ok(event) = progress_receiver.recv() {
        match event {
            ProgressEvent::NewInput => pb.inc_length(1),
            ProgressEvent::InputMd5Hashed => pb.inc(1),
            ProgressEvent::NewInputs(n) => pb.inc_length(n),
        }
    }

    for handle in handles {
        handle.join().unwrap();
    }

    pb.finish();

    Ok(())
}
