use thiserror::Error;

#[derive(Error, Debug)]
pub enum HashFileError {
    #[error("The file does not exist in the given path: {0}")]
    FileDoesNotExistError(String),
    #[error("Receiver error")]
    ReceiverError,
}
