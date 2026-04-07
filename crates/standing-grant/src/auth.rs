use crate::lifecycle::GrantState;
use crate::principal::PrincipalRole;

/// Authorization matrix entry: which roles may perform which transitions.
///
/// This is the entire authorization policy for grant lifecycle transitions,
/// expressed as data. If a (from, to, role) triple isn't in this table,
/// the transition is not authorized.
struct AuthEntry {
    from: GrantState,
    to: GrantState,
    allowed_roles: &'static [PrincipalRole],
}

const AUTH_MATRIX: &[AuthEntry] = &[
    // Issued → Active: subject only (workload begins using its grant)
    AuthEntry {
        from: GrantState::Issued,
        to: GrantState::Active,
        allowed_roles: &[PrincipalRole::Subject],
    },
    // Active → Used: subject only (workload records use of grant)
    AuthEntry {
        from: GrantState::Active,
        to: GrantState::Used,
        allowed_roles: &[PrincipalRole::Subject],
    },
    // Issued → Revoked: admin or subject (self-revoke allowed)
    AuthEntry {
        from: GrantState::Issued,
        to: GrantState::Revoked,
        allowed_roles: &[PrincipalRole::Admin, PrincipalRole::Subject],
    },
    // Active → Revoked: admin or subject
    AuthEntry {
        from: GrantState::Active,
        to: GrantState::Revoked,
        allowed_roles: &[PrincipalRole::Admin, PrincipalRole::Subject],
    },
    // Issued → Expired: system only
    AuthEntry {
        from: GrantState::Issued,
        to: GrantState::Expired,
        allowed_roles: &[PrincipalRole::System],
    },
    // Active → Expired: system only
    AuthEntry {
        from: GrantState::Active,
        to: GrantState::Expired,
        allowed_roles: &[PrincipalRole::System],
    },
    // Issued → Abandoned: system only
    AuthEntry {
        from: GrantState::Issued,
        to: GrantState::Abandoned,
        allowed_roles: &[PrincipalRole::System],
    },
    // Active → Abandoned: system only
    AuthEntry {
        from: GrantState::Active,
        to: GrantState::Abandoned,
        allowed_roles: &[PrincipalRole::System],
    },
    // Requested → Issued: admin only (policy engine acts as admin)
    AuthEntry {
        from: GrantState::Requested,
        to: GrantState::Issued,
        allowed_roles: &[PrincipalRole::Admin],
    },
    // Requested → Denied: admin only
    AuthEntry {
        from: GrantState::Requested,
        to: GrantState::Denied,
        allowed_roles: &[PrincipalRole::Admin],
    },
];

/// Check if the given role is authorized to perform the transition.
///
/// Returns true if the (from, to, role) triple is in the auth matrix.
/// Returns false otherwise — fail closed.
pub fn is_authorized(from: &GrantState, to: &GrantState, role: PrincipalRole) -> bool {
    AUTH_MATRIX.iter().any(|entry| {
        &entry.from == from && &entry.to == to && entry.allowed_roles.contains(&role)
    })
}

/// Returns the allowed roles for a given transition, or empty if the
/// transition itself is not in the matrix.
pub fn allowed_roles(from: &GrantState, to: &GrantState) -> Vec<PrincipalRole> {
    AUTH_MATRIX
        .iter()
        .filter(|entry| &entry.from == from && &entry.to == to)
        .flat_map(|entry| entry.allowed_roles.iter().copied())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subject_can_activate() {
        assert!(is_authorized(
            &GrantState::Issued,
            &GrantState::Active,
            PrincipalRole::Subject,
        ));
    }

    #[test]
    fn admin_cannot_activate() {
        assert!(!is_authorized(
            &GrantState::Issued,
            &GrantState::Active,
            PrincipalRole::Admin,
        ));
    }

    #[test]
    fn subject_can_use() {
        assert!(is_authorized(
            &GrantState::Active,
            &GrantState::Used,
            PrincipalRole::Subject,
        ));
    }

    #[test]
    fn admin_can_revoke() {
        assert!(is_authorized(
            &GrantState::Active,
            &GrantState::Revoked,
            PrincipalRole::Admin,
        ));
    }

    #[test]
    fn subject_can_self_revoke() {
        assert!(is_authorized(
            &GrantState::Active,
            &GrantState::Revoked,
            PrincipalRole::Subject,
        ));
    }

    #[test]
    fn system_can_expire() {
        assert!(is_authorized(
            &GrantState::Issued,
            &GrantState::Expired,
            PrincipalRole::System,
        ));
    }

    #[test]
    fn subject_cannot_expire() {
        assert!(!is_authorized(
            &GrantState::Issued,
            &GrantState::Expired,
            PrincipalRole::Subject,
        ));
    }

    #[test]
    fn nobody_can_transition_from_terminal() {
        assert!(!is_authorized(
            &GrantState::Used,
            &GrantState::Active,
            PrincipalRole::Subject,
        ));
        assert!(!is_authorized(
            &GrantState::Revoked,
            &GrantState::Active,
            PrincipalRole::Admin,
        ));
    }

    #[test]
    fn admin_can_issue() {
        assert!(is_authorized(
            &GrantState::Requested,
            &GrantState::Issued,
            PrincipalRole::Admin,
        ));
    }

    #[test]
    fn all_adjacencies_have_auth_entries() {
        // Every edge in the adjacency graph should have at least one
        // authorized role in the auth matrix.
        let states = [
            GrantState::Requested,
            GrantState::Issued,
            GrantState::Active,
        ];
        for from in &states {
            for to in from.allowed_transitions() {
                let roles = allowed_roles(from, to);
                assert!(
                    !roles.is_empty(),
                    "transition {:?} → {:?} has no authorized roles",
                    from,
                    to,
                );
            }
        }
    }
}
