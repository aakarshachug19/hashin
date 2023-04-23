//! A command line interface for various gigafizz related operations.

use crate::commands::{gen_passwords, hashes_from_file, simple_bench};
use anyhow::Result;
use clap::{Parser, Subcommand};
use commands::{GenPasswordsOpts, HashesFromFileOpts, SimpleBenchOpts};
use dotenvy::dotenv;
use indicatif::{FormattedDuration, HumanBytes, HumanFloatCount, ProgressState, ProgressStyle};
use tracing::trace;
use std::net::{TcpListener, TcpStream};
mod commands;
mod errors;

#[derive(Parser, Debug)]
#[clap(version)]
struct Opts {
    #[clap(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Run simple benchmarkable stuff
    SimpleBench(SimpleBenchOpts),

    /// Generate passwords and write to file
    GenPasswords(GenPasswordsOpts),

    /// Generate hashes from passwords in a file
    HashesFromFile(HashesFromFileOpts),
}

fn main() -> Result<()> {
    // read in any environment variables set in a .env file
    dotenv().ok();

    // initialize a logger
    tracing_subscriber::fmt::init();

    let opts = Opts::parse();

    trace!("opts: {:?}", opts);

    match opts.command {
        Command::SimpleBench(opts) => simple_bench(&opts)?,
        Command::GenPasswords(opts) => gen_passwords(&opts)?,
        Command::HashesFromFile(opts) => hashes_from_file(&opts)?,
    }

    Ok(())
}


fn handle_connection(stream: &mut TcpStream) -> std::io::Result<()> {
    // TODO: Implement handling of incoming requests
    Ok(())
}

/// Allow for [`ProgressBar`] to output linear estimates instead of just the past N steps.
/// This is relevant for pbs that we don't know the length before hand or that there are
/// a bunch of individual steps.
pub(crate) fn add_keys_to_style(style: ProgressStyle) -> ProgressStyle {
    style
        .with_key(
            "linear_per_sec",
            Box::new(|state: &ProgressState, w: &mut dyn std::fmt::Write| {
                let linear_per_sec = match (state.pos(), state.elapsed().as_secs()) {
                    (_, 0) => "0".to_string(),
                    (pos, elapsed) => {
                        format!("{:#}", HumanFloatCount(pos as f64 / elapsed as f64))
                    }
                };

                write!(w, "{linear_per_sec}/s").unwrap()
            }),
        )
        .with_key(
            "linear_eta",
            Box::new(|state: &ProgressState, w: &mut dyn std::fmt::Write| {
                let linear_eta = match (state.pos(), state.len()) {
                    (0, _) => "-".to_string(),
                    (_, None) => "-".to_string(),
                    (pos, Some(len)) => {
                        format!(
                            "{:#}",
                            FormattedDuration(std::time::Duration::from_secs(
                                state.elapsed().as_secs() * (len - pos) / pos
                            ))
                        )
                    }
                };
                write!(w, "{linear_eta}").unwrap()
            }),
        )
        .with_key(
            "linear_bytes_per_sec",
            Box::new(|state: &ProgressState, w: &mut dyn std::fmt::Write| {
                let linear_bytes_per_sec = match (state.pos(), state.elapsed().as_secs()) {
                    (_, 0) => "0".to_string(),
                    (pos, elapsed) => format!("{:#}", HumanBytes(pos / elapsed)),
                };
                write!(w, "{linear_bytes_per_sec}/s").unwrap()
            }),
        )
}

pub(crate) fn new_bar_extended() -> ProgressStyle {
    add_keys_to_style(ProgressStyle::default_bar())
}
