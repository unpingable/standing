use thiserror::Error;

#[derive(Debug, Error)]
pub enum GrantError {
    #[error("invalid transition: cannot go from {from} to {to}")]
    InvalidTransition { from: String, to: String },

    #[error("grant expired at {expired_at}")]
    Expired { expired_at: String },

    #[error("grant already in terminal state: {0}")]
    Terminal(String),

    // -- assertion-lease (Phase 4b) --------------------------------------
    #[error("assertion lease not yet valid (not_before {not_before})")]
    NotYetValid { not_before: String },

    #[error("assertion lease window is incoherent (not_before is not before expires_at)")]
    WindowIncoherent,

    #[error("assertion out of lease scope: {axis}")]
    OutOfScope { axis: String },

    #[error("assertion lease use budget exhausted (max_uses {max_uses})")]
    BudgetExhausted { max_uses: u64 },

    #[error(
        "cannot issue an assertion lease with no genesis installed; \
             issuance requires a prior settlement-witness (see docs/genesis-receipt.md)"
    )]
    NoGenesis,

    #[error("assertion speaker {0} cannot authorize its own lease")]
    AssertionSelfGrant(String),

    #[error("receipt error: {0}")]
    Receipt(#[from] standing_receipt::ReceiptError),
}
