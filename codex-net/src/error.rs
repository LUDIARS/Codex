use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetError {
    #[error("io: {0}")]
    Io(String),
    #[error("frame too large: {0} > {1} bytes")]
    FrameTooLarge(usize, usize),
    #[error("incomplete frame: expected {expected}, got {got}")]
    Incomplete { expected: usize, got: usize },
    #[error("postcard decode: {0}")]
    Decode(String),
    #[error("postcard encode: {0}")]
    Encode(String),
}
