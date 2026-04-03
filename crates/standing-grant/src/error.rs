use thiserror::Error;

#[derive(Debug, Error)]
pub enum GrantError {
    #[error("invalid transition: cannot go from {from} to {to}")]
    InvalidTransition { from: String, to: String },

    #[error("grant expired at {expired_at}")]
    Expired { expired_at: String },

    #[error("grant already in terminal state: {0}")]
    Terminal(String),

    #[error("receipt error: {0}")]
    Receipt(#[from] standing_receipt::ReceiptError),
}
