use crate::error::ReceiptError;
use crate::receipt::Receipt;

/// An ordered chain of receipts for a single subject (e.g., a grant lifecycle).
///
/// Invariants:
/// - Each receipt (after the first) must reference the previous receipt's digest as parent.
/// - No duplicate digests.
/// - The chain is append-only.
#[derive(Debug, Clone)]
pub struct ReceiptChain {
    subject: String,
    receipts: Vec<Receipt>,
}

impl ReceiptChain {
    /// Create a new chain starting with the given receipt.
    pub fn new(first: Receipt) -> Self {
        let subject = first.subject.clone();
        Self {
            subject,
            receipts: vec![first],
        }
    }

    /// Append a receipt to the chain.
    ///
    /// Fails if:
    /// - The receipt's parent_digest doesn't match the current tip's digest
    /// - The receipt's digest is already in the chain
    pub fn append(&mut self, receipt: Receipt) -> Result<(), ReceiptError> {
        let tip = self.tip();

        // Verify chain linkage
        match &receipt.parent_digest {
            Some(parent) if parent == &tip.digest => {}
            Some(parent) => {
                return Err(ReceiptError::ChainBroken {
                    expected: tip.digest.clone(),
                    actual: parent.clone(),
                });
            }
            None => {
                return Err(ReceiptError::ChainBroken {
                    expected: tip.digest.clone(),
                    actual: "(none)".to_string(),
                });
            }
        }

        // Check for duplicates
        if self.receipts.iter().any(|r| r.digest == receipt.digest) {
            return Err(ReceiptError::Duplicate(receipt.digest));
        }

        self.receipts.push(receipt);
        Ok(())
    }

    /// The most recent receipt in the chain.
    pub fn tip(&self) -> &Receipt {
        self.receipts.last().expect("chain is never empty")
    }

    /// The subject this chain tracks.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// All receipts in order.
    pub fn receipts(&self) -> &[Receipt] {
        &self.receipts
    }

    /// Number of receipts in the chain.
    pub fn len(&self) -> usize {
        self.receipts.len()
    }

    /// Verify the entire chain's integrity: each receipt's parent_digest
    /// matches the previous receipt's digest.
    pub fn verify(&self) -> Result<(), ReceiptError> {
        for window in self.receipts.windows(2) {
            let prev = &window[0];
            let curr = &window[1];
            match &curr.parent_digest {
                Some(parent) if parent == &prev.digest => {}
                Some(parent) => {
                    return Err(ReceiptError::ChainBroken {
                        expected: prev.digest.clone(),
                        actual: parent.clone(),
                    });
                }
                None => {
                    return Err(ReceiptError::ChainBroken {
                        expected: prev.digest.clone(),
                        actual: "(none)".to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receipt::{ReceiptBuilder, ReceiptKind};

    fn build_chain() -> ReceiptChain {
        let r1 = ReceiptBuilder::new(ReceiptKind::GrantRequested, "bot", "g1")
            .build()
            .unwrap();
        let mut chain = ReceiptChain::new(r1);

        let r2 = ReceiptBuilder::new(ReceiptKind::GrantIssued, "issuer", "g1")
            .parent_digest(chain.tip().digest.clone())
            .build()
            .unwrap();
        chain.append(r2).unwrap();

        let r3 = ReceiptBuilder::new(ReceiptKind::GrantActivated, "bot", "g1")
            .parent_digest(chain.tip().digest.clone())
            .build()
            .unwrap();
        chain.append(r3).unwrap();

        chain
    }

    #[test]
    fn chain_builds_and_verifies() {
        let chain = build_chain();
        assert_eq!(chain.len(), 3);
        chain.verify().unwrap();
    }

    #[test]
    fn broken_chain_rejected() {
        let r1 = ReceiptBuilder::new(ReceiptKind::GrantRequested, "bot", "g1")
            .build()
            .unwrap();
        let mut chain = ReceiptChain::new(r1);

        // Wrong parent
        let bad = ReceiptBuilder::new(ReceiptKind::GrantIssued, "issuer", "g1")
            .parent_digest("wrong-digest")
            .build()
            .unwrap();

        assert!(chain.append(bad).is_err());
    }

    #[test]
    fn missing_parent_rejected() {
        let r1 = ReceiptBuilder::new(ReceiptKind::GrantRequested, "bot", "g1")
            .build()
            .unwrap();
        let mut chain = ReceiptChain::new(r1);

        // No parent at all
        let bad = ReceiptBuilder::new(ReceiptKind::GrantIssued, "issuer", "g1")
            .build()
            .unwrap();

        assert!(chain.append(bad).is_err());
    }
}
