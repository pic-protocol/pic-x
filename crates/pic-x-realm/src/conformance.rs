//! Does the workload that proposes this transition satisfy the checkpoint's execution contract?
//!
//! Proof of Relationship establishes *who* the workload is and *which key* it controls. On its own
//! that is a weaker statement than it looks: it says an accepted issuer vouched for a workload, not
//! that the workload is one this lineage may run on. The articles are explicit that the two are
//! separate — "PoR alone does not prove runtime behavior or execution-contract conformance" — and
//! leave the conformance check to the deployment.
//!
//! This realm requires it. The claims the Holder disclosed are matched against the
//! `execution_contract` of the checkpoint being advanced:
//!
//! * every contract entry the presentation speaks about must **agree** — a disclosed
//!   `department: marketing` against a contract demanding `sensitive-documents` is a rejection;
//! * the presentation must speak about **at least one** contract entry — a credential that
//!   discloses nothing the contract constrains proves nothing about conformance, and accepting it
//!   would make selective disclosure decorative.
//!
//! Contract entries the presentation says nothing about are not treated as violations: a contract
//! carries execution constraints that are not workload attributes at all (`purpose`, `currency` in
//! the reference examples), and demanding a claim for each would make those contracts unusable.

use pic::continuity::artifacts::{PicPcaPayload, PicTransitionPayload};
use pic::continuity::authority::indexed::{IndexedAuthorityMap, TupleValue};
use pic::continuity::trust::SettlementPolicy;
use serde_json::Value;

use crate::por::SdJwtPorValidator;

/// Matches the claims of the accepted Proof of Relationship against the checkpoint's contract.
pub(crate) struct ContractConformance<'a> {
    /// The validator that accepted the presentation; it holds what was disclosed.
    pub(crate) por: &'a SdJwtPorValidator<'a>,
}

/// Why a transition failed conformance, for the record and the caller.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Mismatch {
    /// A disclosed claim contradicts a contract entry.
    Contradicts {
        key: String,
        required: String,
        disclosed: String,
    },
    /// Nothing the presentation disclosed touches the contract.
    SaysNothing,
}

impl ContractConformance<'_> {
    /// `Ok(())` when the disclosed claims satisfy the contract.
    pub(crate) fn check(
        claims: &serde_json::Map<String, Value>,
        contract: &IndexedAuthorityMap,
    ) -> Result<(), Mismatch> {
        let mut spoken_about = 0_usize;

        for (key, value) in contract.execution_contract.values() {
            match value {
                // `key = value`: the claim, when disclosed, must carry that exact value.
                TupleValue::Text(required) => {
                    let Some(disclosed) = claims.get(key) else {
                        continue;
                    };
                    spoken_about += 1;
                    if !matches_text(disclosed, required) {
                        return Err(Mismatch::Contradicts {
                            key: key.clone(),
                            required: required.clone(),
                            disclosed: render(disclosed),
                        });
                    }
                }
                // `key:member = true`: the denormalized form of a collection membership. The claim
                // is the part before the colon, and it must contain the member.
                TupleValue::Membership(_) => {
                    let Some((name, member)) = key.split_once(':') else {
                        continue;
                    };
                    let Some(disclosed) = claims.get(name) else {
                        continue;
                    };
                    spoken_about += 1;
                    if !contains_member(disclosed, member) {
                        return Err(Mismatch::Contradicts {
                            key: name.to_owned(),
                            required: member.to_owned(),
                            disclosed: render(disclosed),
                        });
                    }
                }
            }
        }

        if spoken_about == 0 {
            return Err(Mismatch::SaysNothing);
        }

        Ok(())
    }
}

impl SettlementPolicy for ContractConformance<'_> {
    fn conformance(&self, checkpoint: &PicPcaPayload, _transition: &PicTransitionPayload) -> bool {
        self.reason(checkpoint).is_ok()
    }
}

impl ContractConformance<'_> {
    /// The conformance outcome, with the reason a rejection can be recorded and returned.
    pub(crate) fn reason(&self, checkpoint: &PicPcaPayload) -> Result<(), Mismatch> {
        // No accepted presentation means nothing was proven about this workload.
        let Some(accepted) = self.por.accepted() else {
            return Err(Mismatch::SaysNothing);
        };

        Self::check(&accepted.claims, &checkpoint.context_of_authority)
    }
}

fn matches_text(disclosed: &Value, required: &str) -> bool {
    match disclosed {
        Value::String(value) => value == required,
        // A disclosed collection satisfies a scalar constraint by containing it.
        Value::Array(values) => values.iter().any(|item| item.as_str() == Some(required)),
        _ => false,
    }
}

fn contains_member(disclosed: &Value, member: &str) -> bool {
    match disclosed {
        Value::String(value) => value == member,
        Value::Array(values) => values.iter().any(|item| item.as_str() == Some(member)),
        _ => false,
    }
}

fn render(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    }
}

impl std::fmt::Display for Mismatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Mismatch::Contradicts {
                key,
                required,
                disclosed,
            } => write!(
                formatter,
                "the execution contract requires `{key}` = `{required}`, the Proof of Relationship \
                 disclosed `{disclosed}`"
            ),
            Mismatch::SaysNothing => write!(
                formatter,
                "the Proof of Relationship discloses nothing the execution contract constrains"
            ),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "a failing assertion is the point"
)]
mod tests {
    use super::*;
    use pic::continuity::authority::{AuthorityValue, Invariant, LogicalAuthority};
    use std::collections::BTreeMap;

    /// The walkthrough contract: corporation ACME, department sensitive-documents.
    fn contract(pairs: &[(&str, AuthorityValue)]) -> IndexedAuthorityMap {
        let mut map = BTreeMap::new();
        for (key, value) in pairs {
            map.insert((*key).to_owned(), value.clone());
        }
        IndexedAuthorityMap::from_logical(&LogicalAuthority::new(
            None,
            vec![Invariant::new("storage:save", "save", "storage", "*")],
            map,
        ))
        .unwrap()
    }

    fn walkthrough() -> IndexedAuthorityMap {
        contract(&[
            ("corporation", AuthorityValue::One("ACME".into())),
            (
                "department",
                AuthorityValue::One("sensitive-documents".into()),
            ),
        ])
    }

    fn disclosing(pairs: &[(&str, Value)]) -> serde_json::Map<String, Value> {
        let mut claims = serde_json::Map::new();
        for (key, value) in pairs {
            claims.insert((*key).to_owned(), value.clone());
        }
        claims
    }

    fn check(
        claims: &serde_json::Map<String, Value>,
        contract: &IndexedAuthorityMap,
    ) -> Result<(), Mismatch> {
        ContractConformance::check(claims, contract)
    }

    #[test]
    fn a_workload_of_the_right_department_passes() {
        let por = disclosing(&[
            ("corporation", Value::String("ACME".into())),
            ("department", Value::String("sensitive-documents".into())),
            // Claims the contract says nothing about are simply not consulted.
            ("workload_role", Value::String("document-reader".into())),
        ]);
        assert_eq!(check(&por, &walkthrough()), Ok(()));
    }

    #[test]
    fn a_workload_of_another_department_is_rejected() {
        let por = disclosing(&[
            ("corporation", Value::String("ACME".into())),
            ("department", Value::String("marketing".into())),
        ]);
        assert_eq!(
            check(&por, &walkthrough()),
            Err(Mismatch::Contradicts {
                key: "department".into(),
                required: "sensitive-documents".into(),
                disclosed: "marketing".into(),
            })
        );
    }

    #[test]
    fn a_presentation_that_touches_nothing_in_the_contract_is_rejected() {
        // Attested, well-formed, and silent about everything the lineage constrains: accepting it
        // would make the disclosure decorative.
        let por = disclosing(&[("workload_role", Value::String("document-reader".into()))]);
        assert_eq!(check(&por, &walkthrough()), Err(Mismatch::SaysNothing));
    }

    #[test]
    fn agreeing_on_one_entry_is_enough_when_the_others_are_not_workload_attributes() {
        // The token/artifact article's contract: purpose and currency are execution constraints,
        // not attributes any workload credential would carry.
        let execution = contract(&[
            ("purpose", AuthorityValue::One("payment-approval".into())),
            ("currency", AuthorityValue::One("EUR".into())),
            ("corporation", AuthorityValue::One("ACME".into())),
        ]);
        let por = disclosing(&[("corporation", Value::String("ACME".into()))]);
        assert_eq!(check(&por, &execution), Ok(()));
    }

    #[test]
    fn a_collection_constraint_is_satisfied_by_membership() {
        // `departments: [engineering, operations]` denormalizes to two membership entries.
        let execution = contract(&[(
            "departments",
            AuthorityValue::Many(vec!["engineering".into(), "operations".into()]),
        )]);

        let member = disclosing(&[(
            "departments",
            Value::Array(vec![Value::String("engineering".into())]),
        )]);
        assert!(matches!(
            check(&member, &execution),
            Err(Mismatch::Contradicts { .. })
        ));

        // Both memberships are required, so the workload must carry both.
        let both = disclosing(&[(
            "departments",
            Value::Array(vec![
                Value::String("engineering".into()),
                Value::String("operations".into()),
            ]),
        )]);
        assert_eq!(check(&both, &execution), Ok(()));
    }

    #[test]
    fn a_non_string_claim_never_satisfies_a_constraint() {
        let por = disclosing(&[
            ("corporation", Value::Bool(true)),
            ("department", Value::String("sensitive-documents".into())),
        ]);
        assert!(matches!(
            check(&por, &walkthrough()),
            Err(Mismatch::Contradicts { .. })
        ));
    }
}
