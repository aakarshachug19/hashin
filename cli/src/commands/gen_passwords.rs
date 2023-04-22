use anyhow::Result;
use clap::Args;
use hashassin_core::passwords::{CharSet, PasswordGenerator};
use hashassin_core::save_passwords_to_disk;

#[derive(Args, Debug)]
pub(crate) struct GenPasswordsOpts {
    /// Path to file to write passwords.
    #[clap(long)]
    out_path: String,

    /// Minimum number of characters generated passwords should be
    #[clap(long, default_value = "4")]
    min_chars: usize,

    /// Maximum number of characters generated passwords should be
    #[clap(long, default_value = "4")]
    max_chars: usize,
}

pub(crate) fn gen_passwords(opts: &GenPasswordsOpts) -> Result<()> {
    let generator = PasswordGenerator::new(
        opts.min_chars,
        opts.max_chars,
        CharSet::LowerAlpha | CharSet::Numeric | CharSet::UpperAlpha,
    )?;

    save_passwords_to_disk(&opts.out_path, generator, None)?;

    Ok(())
}
