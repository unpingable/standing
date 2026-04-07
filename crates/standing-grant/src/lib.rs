//! Grant lifecycle model for standing.
//!
//! A grant is a scoped, time-limited entitlement: actor X may do action Y
//! on target Z until time T. Every state transition produces a receipt.

pub mod auth;
mod error;
mod grant;
mod lifecycle;
pub mod principal;

pub use error::GrantError;
pub use grant::{Grant, GrantRequest, GrantScope};
pub use lifecycle::{GrantState, GrantMachine};
pub use principal::{ActorContext, Principal, PrincipalRole};
