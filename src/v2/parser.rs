use crate::errors::CVSSError;
use crate::v2::metrics::CVSSv2Metric::*;
use crate::v2::metrics::*;

use std::collections::HashSet;

use pest::Parser;

#[derive(Parser)]
#[grammar = "v2/cvss_v2.pest"]
struct VectorParser;

pub(crate) fn parse(s: &str) -> Result<Vec<CVSSv2Metric>, CVSSError> {
    let parse_tree = VectorParser::parse(Rule::cvss_vector, s)
        .map_err(|_| CVSSError::ParsingError)?
        .next()
        .ok_or(CVSSError::ParsingError)?;

    let mut vector: HashSet<CVSSv2Metric> = HashSet::new();
    let mut unmet_mandatory_requirements = 5;

    for entry in parse_tree.into_inner() {
        match entry.as_rule() {
            Rule::access_vector => {
                unmet_mandatory_requirements -= 1;

                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::network => vector.insert(AccessVector(AV::N)),
                    Rule::adjacent => vector.insert(AccessVector(AV::A)),
                    Rule::local => vector.insert(AccessVector(AV::L)),
                    _ => unreachable!(),
                }
            }
            Rule::access_complexity => {
                unmet_mandatory_requirements -= 1;

                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::high => vector.insert(AccessComplexity(AC::H)),
                    Rule::medium => vector.insert(AccessComplexity(AC::M)),
                    Rule::low => vector.insert(AccessComplexity(AC::L)),
                    _ => unreachable!(),
                }
            }
            Rule::authentication => {
                unmet_mandatory_requirements -= 1;
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::multiple => vector.insert(Authentication(AU::M)),
                    Rule::single => vector.insert(Authentication(AU::S)),
                    Rule::none => vector.insert(Authentication(AU::N)),
                    _ => unreachable!(),
                }
            }
            Rule::confidentiality => {
                unmet_mandatory_requirements -= 1;
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::none => vector.insert(Confidentiality(C::N)),
                    Rule::partial => vector.insert(Confidentiality(C::P)),
                    Rule::complete => vector.insert(Confidentiality(C::C)),
                    _ => unreachable!(),
                }
            }
            Rule::integrity => {
                unmet_mandatory_requirements -= 1;
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::none => vector.insert(Integrity(I::N)),
                    Rule::partial => vector.insert(Integrity(I::P)),
                    Rule::complete => vector.insert(Integrity(I::C)),
                    _ => unreachable!(),
                }
            }
            Rule::availability => match entry.into_inner().next().unwrap().as_rule() {
                Rule::none => vector.insert(Availability(A::N)),
                Rule::partial => vector.insert(Availability(A::P)),
                Rule::complete => vector.insert(Availability(A::C)),
                _ => unreachable!(),
            },
            Rule::exploitability => match entry.into_inner().next().unwrap().as_rule() {
                Rule::unproven => vector.insert(Exploitability(E::U)),
                Rule::proof_of_concept => vector.insert(Exploitability(E::POC)),
                Rule::functional => vector.insert(Exploitability(E::F)),
                Rule::high => vector.insert(Exploitability(E::H)),
                Rule::not_defined => vector.insert(Exploitability(E::ND)),
                _ => unreachable!(),
            },
            Rule::remediation_level => match entry.into_inner().next().unwrap().as_rule() {
                Rule::official_fix => vector.insert(RemediationLevel(RL::OF)),
                Rule::temporary_fix => vector.insert(RemediationLevel(RL::TF)),
                Rule::workaround => vector.insert(RemediationLevel(RL::W)),
                Rule::unavailable => vector.insert(RemediationLevel(RL::U)),
                _ => unreachable!(),
            },
            Rule::report_confidence => match entry.into_inner().next().unwrap().as_rule() {
                Rule::unconfirmed => vector.insert(ReportConfidence(RC::UC)),
                Rule::uncorroborated => vector.insert(ReportConfidence(RC::UR)),
                Rule::confirmed => vector.insert(ReportConfidence(RC::C)),
                Rule::not_defined => vector.insert(ReportConfidence(RC::ND)),
                _ => unreachable!(),
            },
            Rule::collateral_damage_potential => match entry.into_inner().next().unwrap().as_rule()
            {
                Rule::none => vector.insert(CollateralDamagePotential(CDP::N)),
                Rule::low => vector.insert(CollateralDamagePotential(CDP::L)),
                Rule::low_medium => vector.insert(CollateralDamagePotential(CDP::LM)),
                Rule::medium_high => vector.insert(CollateralDamagePotential(CDP::MH)),
                Rule::high => vector.insert(CollateralDamagePotential(CDP::H)),
                Rule::not_defined => vector.insert(CollateralDamagePotential(CDP::ND)),
                _ => unreachable!(),
            },
            Rule::target_distribution => match entry.into_inner().next().unwrap().as_rule() {
                Rule::low => vector.insert(TargetDistribution(TD::L)),
                Rule::medium => vector.insert(TargetDistribution(TD::M)),
                Rule::high => vector.insert(TargetDistribution(TD::H)),
                Rule::not_defined => vector.insert(TargetDistribution(TD::ND)),
                _ => unreachable!(),
            },
            Rule::confidentiality_requirement => match entry.into_inner().next().unwrap().as_rule()
            {
                Rule::low => vector.insert(ConfidentialityRequirement(CR::L)),
                Rule::medium => vector.insert(ConfidentialityRequirement(CR::M)),
                Rule::high => vector.insert(ConfidentialityRequirement(CR::H)),
                Rule::not_defined => vector.insert(ConfidentialityRequirement(CR::ND)),
                _ => unreachable!(),
            },
            Rule::integrity_requirement => match entry.into_inner().next().unwrap().as_rule() {
                Rule::low => vector.insert(IntegrityRequirement(IR::L)),
                Rule::medium => vector.insert(IntegrityRequirement(IR::M)),
                Rule::high => vector.insert(IntegrityRequirement(IR::H)),
                Rule::not_defined => vector.insert(IntegrityRequirement(IR::ND)),
                _ => unreachable!(),
            },
            Rule::availability_requirement => match entry.into_inner().next().unwrap().as_rule() {
                Rule::low => vector.insert(AvailabilityRequirement(AR::L)),
                Rule::medium => vector.insert(AvailabilityRequirement(AR::M)),
                Rule::high => vector.insert(AvailabilityRequirement(AR::H)),
                Rule::not_defined => vector.insert(AvailabilityRequirement(AR::ND)),
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
        .then_some(())
        .ok_or(CVSSError::DuplicateMetrics)?;
    }
    let mut vector = Vec::from_iter(vector);
    vector.sort();
    (unmet_mandatory_requirements == 0)
        .then_some(Ok(vector))
        .ok_or(CVSSError::ParsingError)?
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_can_parse_cvss_v2_base() {
        let result = parse("AV:L/AC:H/Au:N/C:C/I:C/A:C");
        assert!(result.is_ok());
        if let Ok(vector) = result {
            assert!(vector[0] == AccessVector(AV::L));
            assert!(vector[1] == AccessComplexity(AC::H));
            assert!(vector[2] == Authentication(AU::N));
            assert!(vector[3] == Confidentiality(C::C));
            assert!(vector[4] == Integrity(I::C));
            assert!(vector[5] == Availability(A::C));
        }
    }

    #[test]
    fn test_can_parse_cvss_v2_full() {
        let input = "AV:A/AC:M/Au:S/C:P/I:C/A:P/E:POC/RL:W/RC:UR/CDP:MH/TD:M/CR:M/IR:M/AR:M";
        let result = parse(input);
        assert!(result.is_ok());
        if let Ok(vector) = result {
            assert!(vector[0] == AccessVector(AV::L));
            assert!(vector[1] == AccessComplexity(AC::H));
            assert!(vector[2] == Authentication(AU::N));
            assert!(vector[3] == Confidentiality(C::C));
            assert!(vector[4] == Integrity(I::C));
            assert!(vector[5] == Availability(A::C));
            assert!(vector[6] == Exploitability(E::POC));
            assert!(vector[7] == RemediationLevel(RL::W));
            assert!(vector[8] == ReportConfidence(RC::UR));
            assert!(vector[9] == CollateralDamagePotential(CDP::MH));
            assert!(vector[10] == TargetDistribution(TD::M));
            assert!(vector[11] == ConfidentialityRequirement(CR::M));
            assert!(vector[12] == IntegrityRequirement(IR::M));
            assert!(vector[13] == AvailabilityRequirement(AR::M));
        }
    }

    #[test]
    fn test_wont_accept_invalid_input() {
        let input = "AV:AA/E:POR:WR:RCP:HT:M/CR:/IR:M/AR:M";
        let result = parse(input);
        matches!(result, Err(CVSSError::ParsingError));
    }

    #[test]
    fn test_wont_allow_repeat_metrics() {
        let input = "AV:L/AC:H/Au:N/Au:N/C:C/I:C/A:C";
        let result = parse(input);
        matches!(result, Err(CVSSError::DuplicateMetrics));
    }

    #[test]
    fn test_can_detect_missing_mandatory_fields() {
        let result = parse("AV:L/AC:H/C:C/I:C/A:C");
        assert!(result.is_err());
        matches!(result, Err(CVSSError::ParsingError));
    }
}
