//! Receipt kernel for standing.
//!
//! A receipt is a content-addressed, immutable witness to something that happened:
//! a grant issued, a policy decision made, a grant used, revoked, or expired.
//!
//! Receipts form chains: each receipt optionally references a parent, creating
//! a verifiable sequence of events for a given grant lifecycle.
//!
//! Format: canonical JSON (keys sorted) + SHA-256 digest. WLP-compatible.
//! No signatures yet — hash is mandatory, signatures are future work.

mod canonical;
mod error;
mod receipt;
mod chain;

pub use canonical::canonical_json;
pub use error::ReceiptError;
pub use receipt::{Receipt, ReceiptBuilder, ReceiptKind};
pub use chain::ReceiptChain;
