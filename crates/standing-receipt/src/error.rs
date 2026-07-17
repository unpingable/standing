use thiserror::Error;

#[derive(Debug, Error)]
pub enum ReceiptError {
    #[error("serialization failed: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("receipt chain broken: expected parent {expected}, got {actual}")]
    ChainBroken { expected: String, actual: String },

    #[error("receipt subject mismatch: expected {expected}, got {actual}")]
    SubjectMismatch { expected: String, actual: String },

    #[error("receipt chain is empty")]
    EmptyChain,

    #[error("duplicate receipt: {0}")]
    Duplicate(String),

    #[error("unsupported receipt schema_version: {got} (this build supports {supported})")]
    UnsupportedSchemaVersion { got: u32, supported: u32 },

    #[error("receipt digest mismatch: body hashes to {actual}, but receipt claims {expected}")]
    DigestMismatch { expected: String, actual: String },
}
