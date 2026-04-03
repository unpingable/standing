//! Grant lifecycle model for standing.
//!
//! A grant is a scoped, time-limited entitlement: actor X may do action Y
//! on target Z until time T. Every state transition produces a receipt.

mod error;
mod grant;
mod lifecycle;

pub use error::GrantError;
pub use grant::{Grant, GrantRequest, GrantScope};
pub use lifecycle::{GrantState, GrantMachine};
