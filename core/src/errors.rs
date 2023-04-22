use thiserror::Error;

#[derive(Error, Debug)]
pub enum GenPasswordsError {
    #[error("Minimum length cannot be greater than Maximum length, Received Min: {0}, Max: {1}")]
    MinGreaterThanMaxError(usize, usize),
    #[error("Minimum length cannot be 0")]
    InvalidMinLengthError(usize),
}
