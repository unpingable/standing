//! Grant lifecycle model for standing.
//!
//! A grant is a scoped, time-limited entitlement: actor X may do action Y
//! on target Z until time T. Every state transition produces a receipt.

pub mod assertion;
mod assertion_lifecycle;
pub mod auth;
mod error;
mod grant;
mod lifecycle;
pub mod principal;

pub use assertion::{
    ASSERTION_MADE_VERSION, AssertCoverage, AssertionGrant, AssertionGrantRequest,
    AssertionGrantState, AssertionScope, PROOF_VERSION, RequestProof, WindowState,
    assertion_covers, subject_scope_matches,
};
pub use assertion_lifecycle::AssertionGrantMachine;
pub use error::GrantError;
pub use grant::{Grant, GrantRequest, GrantScope};
pub use lifecycle::{GrantMachine, GrantState};
pub use principal::{ActorContext, Principal, PrincipalRole};
