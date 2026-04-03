use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReceiptError {
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("receipt chain broken: expected parent {expected}, got {actual}")]
    ChainBroken { expected: String, actual: String },

    #[error("receipt chain is empty")]
    EmptyChain,

    #[error("duplicate receipt: {0}")]
    Duplicate(String),
}
