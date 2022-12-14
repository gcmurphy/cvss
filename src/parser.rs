use crate::errors::CVSSError;
use crate::CVSSv3Metric::*;
use crate::*;
use pest::Parser;
use std::collections::HashSet;

#[derive(Parser)]
#[grammar = "cvss_v3.pest"]
struct CVSSParser;

pub(crate) fn parse(s: &str) -> Result<(Version, Vec<CVSSv3Metric>), CVSSError> {
    let parse_tree = CVSSParser::parse(Rule::cvss_vector, s)
        .map_err(|_| CVSSError::ParsingError)?
        .next()
        .unwrap();
    let mut version: Option<Version> = None;
    let mut vector: HashSet<CVSSv3Metric> = HashSet::new();

    for entry in parse_tree.into_inner() {
        match entry.as_rule() {
            Rule::cvss_version => {
                let v = entry.into_inner().next().unwrap();
                match v.as_rule() {
                    Rule::cvss_v3 => version = Some(Version::V3),
                    Rule::cvss_v31 => version = Some(Version::V31),
                    _ => unreachable!(),
                }
            }
            Rule::attack_vector => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::network => vector.insert(AttackVector(AV::N)),
                    Rule::adjacent => vector.insert(AttackVector(AV::A)),
                    Rule::local => vector.insert(AttackVector(AV::L)),
                    Rule::physical => vector.insert(AttackVector(AV::P)),
                    _ => unreachable!(),
                }
                .then_some(())
                .ok_or(CVSSError::DuplicateMetrics)?;
            }
            Rule::attack_complexity => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::low => vector.insert(AttackComplexity(AC::L)),
                    Rule::high => vector.insert(AttackComplexity(AC::H)),
                    _ => unreachable!(),
                }
                .then_some(())
                .ok_or(CVSSError::DuplicateMetrics)?;
            }

            Rule::privileges_required => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::none => vector.insert(PrivilegesRequired(PR::N)),
                    Rule::low => vector.insert(PrivilegesRequired(PR::L)),
                    Rule::high => vector.insert(PrivilegesRequired(PR::H)),
                    _ => unreachable!(),
                }
                .then_some(())
                .ok_or(CVSSError::DuplicateMetrics)?;
            }
            Rule::user_interaction => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::none => vector.insert(UserInteraction(UI::N)),
                    Rule::required => vector.insert(UserInteraction(UI::R)),
                    _ => unreachable!(),
                }
                .then_some(())
                .ok_or(CVSSError::DuplicateMetrics)?;
            }
            Rule::scope => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::unchanged => vector.insert(Scope(S::U)),
                    Rule::changed => vector.insert(Scope(S::C)),
                    _ => unreachable!(),
                }
                .then_some(())
                .ok_or(CVSSError::DuplicateMetrics)?;
            }
            Rule::confidentiality => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::high => vector.insert(Confidentiality(C::H)),
                    Rule::low => vector.insert(Confidentiality(C::L)),
                    Rule::none => vector.insert(Confidentiality(C::N)),
                    _ => unreachable!(),
                }
                .then_some(())
                .ok_or(CVSSError::DuplicateMetrics)?;
            }
            Rule::integrity => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::high => vector.insert(Integrity(I::H)),
                    Rule::low => vector.insert(Integrity(I::L)),
                    Rule::none => vector.insert(Integrity(I::N)),
                    _ => unreachable!(),
                }
                .then_some(())
                .ok_or(CVSSError::DuplicateMetrics)?;
            }
            Rule::availability => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::high => vector.insert(Availability(A::H)),
                    Rule::low => vector.insert(Availability(A::L)),
                    Rule::none => vector.insert(Availability(A::N)),
                    _ => unreachable!(),
                }
                .then_some(())
                .ok_or(CVSSError::DuplicateMetrics)?;
            }
            Rule::exploit_maturity => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::not_defined => vector.insert(ExploitMaturity(E::X)),
                    Rule::high => vector.insert(ExploitMaturity(E::H)),
                    Rule::functional => vector.insert(ExploitMaturity(E::F)),
                    Rule::proof_of_concept => vector.insert(ExploitMaturity(E::P)),
                    Rule::unproven => vector.insert(ExploitMaturity(E::U)),
                    _ => unreachable!(),
                }
                .then_some(())
                .ok_or(CVSSError::DuplicateMetrics)?;
            }
            Rule::remediation_level => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::not_defined => vector.insert(RemediationLevel(RL::X)),
                    Rule::unavailable => vector.insert(RemediationLevel(RL::U)),
                    Rule::workaround => vector.insert(RemediationLevel(RL::W)),
                    Rule::temporary_fix => vector.insert(RemediationLevel(RL::T)),
                    Rule::official_fix => vector.insert(RemediationLevel(RL::O)),
                    _ => unreachable!(),
                }
                .then_some(())
                .ok_or(CVSSError::DuplicateMetrics)?;
            }
            Rule::report_confidence => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::not_defined => vector.insert(ReportConfidence(RC::X)),
                    Rule::confirmed => vector.insert(ReportConfidence(RC::C)),
                    Rule::reasonable => vector.insert(ReportConfidence(RC::R)),
                    Rule::unknown => vector.insert(ReportConfidence(RC::U)),
                    _ => unreachable!(),
                }
                .then_some(())
                .ok_or(CVSSError::DuplicateMetrics)?;
            }

            Rule::confidentiality_requirement => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::high => vector.insert(ConfidentialityRequirement(CR::H)),
                    Rule::medium => vector.insert(ConfidentialityRequirement(CR::M)),
                    Rule::low => vector.insert(ConfidentialityRequirement(CR::L)),
                    Rule::not_defined => vector.insert(ConfidentialityRequirement(CR::X)),
                    _ => unreachable!(),
                }
                .then_some(())
                .ok_or(CVSSError::DuplicateMetrics)?;
            }
            Rule::integrity_requirement => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::high => vector.insert(IntegrityRequirement(IR::H)),
                    Rule::medium => vector.insert(IntegrityRequirement(IR::M)),
                    Rule::low => vector.insert(IntegrityRequirement(IR::L)),
                    Rule::not_defined => vector.insert(IntegrityRequirement(IR::X)),
                    _ => unreachable!(),
                }
                .then_some(())
                .ok_or(CVSSError::DuplicateMetrics)?;
            }
            Rule::availability_requirement => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::high => vector.insert(AvailabilityRequirement(AR::H)),
                    Rule::medium => vector.insert(AvailabilityRequirement(AR::M)),
                    Rule::low => vector.insert(AvailabilityRequirement(AR::L)),
                    Rule::not_defined => vector.insert(AvailabilityRequirement(AR::X)),
                    _ => unreachable!(),
                }
                .then_some(())
                .ok_or(CVSSError::DuplicateMetrics)?;
            }
            Rule::modified_attack_vector => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::network => vector.insert(ModifiedAttackVector(MAV::N)),
                    Rule::adjacent => vector.insert(ModifiedAttackVector(MAV::A)),
                    Rule::local => vector.insert(ModifiedAttackVector(MAV::L)),
                    Rule::physical => vector.insert(ModifiedAttackVector(MAV::P)),
                    _ => unreachable!(),
                }
                .then_some(())
                .ok_or(CVSSError::DuplicateMetrics)?;
            }
            Rule::modified_attack_complexity => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::high => vector.insert(ModifiedAttackComplexity(MAC::H)),
                    Rule::low => vector.insert(ModifiedAttackComplexity(MAC::L)),
                    Rule::not_defined => vector.insert(ModifiedAttackComplexity(MAC::X)),
                    _ => unreachable!(),
                }
                .then_some(())
                .ok_or(CVSSError::DuplicateMetrics)?;
            }
            Rule::modified_privileges_required => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::high => vector.insert(ModifiedPrivilegesRequired(MPR::H)),
                    Rule::low => vector.insert(ModifiedPrivilegesRequired(MPR::L)),
                    Rule::none => vector.insert(ModifiedPrivilegesRequired(MPR::N)),
                    Rule::not_defined => vector.insert(ModifiedPrivilegesRequired(MPR::X)),
                    _ => unreachable!(),
                }
                .then_some(())
                .ok_or(CVSSError::DuplicateMetrics)?;
            }
            Rule::modified_user_interaction => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::none => vector.insert(ModifiedUserInteraction(MUI::N)),
                    Rule::required => vector.insert(ModifiedUserInteraction(MUI::R)),
                    Rule::not_defined => vector.insert(ModifiedUserInteraction(MUI::X)),
                    _ => unreachable!(),
                }
                .then_some(())
                .ok_or(CVSSError::DuplicateMetrics)?;
            }
            Rule::modified_scope => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::unchanged => vector.insert(ModifiedScope(MS::U)),
                    Rule::changed => vector.insert(ModifiedScope(MS::C)),
                    Rule::not_defined => vector.insert(ModifiedScope(MS::X)),
                    _ => unreachable!(),
                }
                .then_some(())
                .ok_or(CVSSError::DuplicateMetrics)?;
            }
            Rule::modified_confidentiality => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::high => vector.insert(ModifiedConfidentiality(MC::H)),
                    Rule::low => vector.insert(ModifiedConfidentiality(MC::L)),
                    Rule::none => vector.insert(ModifiedConfidentiality(MC::N)),
                    Rule::not_defined => vector.insert(ModifiedConfidentiality(MC::X)),
                    _ => unreachable!(),
                }
                .then_some(())
                .ok_or(CVSSError::DuplicateMetrics)?;
            }
            Rule::modified_integrity => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::high => vector.insert(ModifiedIntegrity(MI::H)),
                    Rule::low => vector.insert(ModifiedIntegrity(MI::L)),
                    Rule::none => vector.insert(ModifiedIntegrity(MI::N)),
                    Rule::not_defined => vector.insert(ModifiedIntegrity(MI::X)),
                    _ => unreachable!(),
                }
                .then_some(())
                .ok_or(CVSSError::DuplicateMetrics)?;
            }
            Rule::modified_availability => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::high => vector.insert(ModifiedAvailability(MA::H)),
                    Rule::low => vector.insert(ModifiedAvailability(MA::L)),
                    Rule::none => vector.insert(ModifiedAvailability(MA::N)),
                    Rule::not_defined => vector.insert(ModifiedAvailability(MA::X)),
                    _ => unreachable!(),
                }
                .then_some(())
                .ok_or(CVSSError::DuplicateMetrics)?;
            }

            _ => unreachable!(),
        }
    }

    let mut vector = Vec::from_iter(vector);
    vector.sort();
    Ok((version.ok_or(CVSSError::ParsingError)?, vector))
}
