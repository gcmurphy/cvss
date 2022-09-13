#[macro_use]
extern crate anyhow;
extern crate derivative;
extern crate pest;
#[macro_use]
extern crate pest_derive;

use anyhow::{Context, Error, Result};
use derivative::Derivative;
use derive_more::Display;
use pest::Parser;
use std::collections::HashSet;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

#[derive(Clone, Display, Debug)]
pub enum SeverityRating {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl TryFrom<f64> for SeverityRating {
    type Error = Error;

    fn try_from(score: f64) -> Result<Self, Self::Error> {
        use SeverityRating::*;
        match score {
            x if x == 0.0 => Ok(None),
            x if x >= 0.1 && x <= 3.9 => Ok(Low),
            x if x >= 4.0 && x <= 6.9 => Ok(Medium),
            x if x >= 7.0 && x <= 8.9 => Ok(High),
            x if x >= 9.0 && x <= 10.0 => Ok(Critical),
            _ => Err(anyhow!("invalid CVSSv3 score")),
        }
    }
}

#[derive(Parser)]
#[grammar = "cvss_v3.pest"]
pub struct CVSSv3Parser;

// Attack Vector
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AV {
    N,
    A,
    L,
    P,
}
impl AV {
    const fn value(&self) -> f64 {
        use AV::*;
        match self {
            N => 0.85,
            A => 0.62,
            L => 0.55,
            P => 0.2,
        }
    }
}

// Attack Complexity
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AC {
    L,
    H,
}

impl AC {
    const fn value(&self) -> f64 {
        use AC::*;
        match self {
            L => 0.77,
            H => 0.44,
        }
    }
}

// Privileges Required
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum PR {
    N,
    L,
    H,
}

impl PR {
    const fn value(&self) -> f64 {
        use PR::*;
        match self {
            N => 0.85,
            L => 0.62,
            H => 0.27,
        }
    }
    const fn scoped_value(&self, scope: &S) -> f64 {
        match scope {
            S::U => self.value(),
            S::C => match self {
                PR::L => 0.68,
                PR::H => 0.5,
                _ => self.value(),
            },
        }
    }
}

// User Interaction
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum UI {
    N,
    R,
}

impl UI {
    const fn value(&self) -> f64 {
        use UI::*;
        match self {
            N => 0.85,
            R => 0.62,
        }
    }
}

// Scope
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum S {
    U,
    C,
}

impl S {
    const fn value(&self) -> f64 {
        use S::*;
        match self {
            U => 6.42,
            C => 7.52,
        }
    }
}

// Confidentiality
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum C {
    H,
    L,
    N,
}

impl C {
    const fn value(&self) -> f64 {
        use C::*;
        match self {
            H => 0.56,
            L => 0.22,
            N => 0.0,
        }
    }
}

// Integrity
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum I {
    H,
    L,
    N,
}
impl I {
    const fn value(&self) -> f64 {
        use I::*;
        match self {
            H => 0.56,
            L => 0.22,
            N => 0.0,
        }
    }
}

// Availability
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum A {
    H,
    L,
    N,
}
impl A {
    const fn value(&self) -> f64 {
        use A::*;
        match self {
            H => 0.56,
            L => 0.22,
            N => 0.0,
        }
    }
}

// Exploit code maturity
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum E {
    X,
    H,
    F,
    P,
    U,
}
impl E {
    const fn value(&self) -> f64 {
        use E::*;
        match self {
            X => 1.0,
            H => 1.0,
            F => 0.97,
            P => 0.94,
            U => 0.91,
        }
    }
}

// Remediation Level
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RL {
    X,
    U,
    W,
    T,
    O,
}

impl RL {
    const fn value(&self) -> f64 {
        use RL::*;
        match self {
            X => 1.0,
            U => 1.0,
            W => 0.97,
            T => 0.96,
            O => 0.95,
        }
    }
}

// Report Confidence
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RC {
    X,
    C,
    R,
    U,
}

impl RC {
    const fn value(&self) -> f64 {
        use RC::*;
        match self {
            X => 1.0,
            C => 1.0,
            R => 0.96,
            U => 0.92,
        }
    }
}

// Confidentiality Requirement
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CR {
    X,
    H,
    M,
    L,
}

impl CR {
    const fn value(&self) -> f64 {
        use CR::*;
        match self {
            X => 1.0,
            H => 1.5,
            M => 1.0,
            L => 0.5,
        }
    }
}

// Integrity Requirement
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum IR {
    X,
    H,
    M,
    L,
}
impl IR {
    const fn value(&self) -> f64 {
        use IR::*;
        match self {
            X => 1.0,
            H => 1.5,
            M => 1.0,
            L => 0.5,
        }
    }
}

// Availability Requirement
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AR {
    X,
    H,
    M,
    L,
}
impl AR {
    const fn value(&self) -> f64 {
        use AR::*;
        match self {
            X => 1.0,
            H => 1.5,
            M => 1.0,
            L => 0.5,
        }
    }
}

// Modified Attack Vector
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MAV {
    N,
    A,
    L,
    P,
}
impl MAV {
    const fn value(&self) -> f64 {
        use MAV::*;
        match self {
            N => 0.85,
            A => 0.62,
            L => 0.55,
            P => 0.2,
        }
    }
}

// Modified Attack Complexity
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MAC {
    X,
    L,
    H,
}

impl MAC {
    const fn value(&self) -> f64 {
        use MAC::*;
        match self {
            X => 1.0,
            L => 0.77,
            H => 0.44,
        }
    }
}

// Modified Privileges Required
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MPR {
    X,
    N,
    L,
    H,
}

impl MPR {
    const fn value(&self) -> f64 {
        use MPR::*;
        match self {
            X => 1.0,
            N => 0.85,
            L => 0.62,
            H => 0.27,
        }
    }

    const fn scoped_value(&self, scope: &MS) -> f64 {
        use MPR::*;
        match scope {
            MS::U | MS::X => self.value(),
            MS::C => match self {
                L => 0.68,
                H => 0.5,
                _ => self.value(),
            },
        }
    }
}

// Modified User Interaction
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MUI {
    X,
    N,
    R,
}

impl MUI {
    const fn value(&self) -> f64 {
        use MUI::*;
        match self {
            X => 1.0,
            N => 0.85,
            R => 0.62,
        }
    }
}

// Modified Scope
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MS {
    X,
    U,
    C,
}

impl MS {
    const fn value(&self) -> f64 {
        use MS::*;
        match self {
            U | X => 6.42,
            C => 7.52,
        }
    }
}

// Modified Confidentiality
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MC {
    X,
    N,
    L,
    H,
}
impl MC {
    const fn value(&self) -> f64 {
        use MC::*;
        match self {
            H => 0.56,
            L => 0.22,
            N => 0.0,
            X => 0.0,
        }
    }
}

// Modified Integrity
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MI {
    X,
    N,
    L,
    H,
}
impl MI {
    const fn value(&self) -> f64 {
        use MI::*;
        match self {
            H => 0.56,
            L => 0.22,
            N => 0.0,
            X => 0.0,
        }
    }
}

// Modified Availability
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum MA {
    X,
    N,
    L,
    H,
}
impl MA {
    const fn value(&self) -> f64 {
        use MA::*;
        match self {
            H => 0.56,
            L => 0.22,
            N => 0.0,
            X => 0.0,
        }
    }
}

#[derive(Clone, Derivative, Display, Debug, Eq, Ord, PartialOrd)]
#[derivative(Hash, PartialEq)]
pub enum CVSSv3Metric {
    #[display(fmt = "AV:{}", _0)]
    AttackVector(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        AV,
    ),

    #[display(fmt = "AC:{}", _0)]
    AttackComplexity(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        AC,
    ),

    #[display(fmt = "PR:{}", _0)]
    PrivilegesRequired(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        PR,
    ),

    #[display(fmt = "UI:{}", _0)]
    UserInteraction(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        UI,
    ),

    #[display(fmt = "S:{}", _0)]
    Scope(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        S,
    ),

    #[display(fmt = "C:{}", _0)]
    Confidentiality(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        C,
    ),

    #[display(fmt = "I:{}", _0)]
    Integrity(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        I,
    ),

    #[display(fmt = "A:{}", _0)]
    Availability(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        A,
    ),

    #[display(fmt = "E:{}", _0)]
    ExploitMaturity(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        E,
    ),

    #[display(fmt = "RL:{}", _0)]
    RemediationLevel(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        RL,
    ),

    #[display(fmt = "RC:{}", _0)]
    ReportConfidence(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        RC,
    ),

    #[display(fmt = "CR:{}", _0)]
    ConfidentialityRequirement(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        CR,
    ),

    #[display(fmt = "IR:{}", _0)]
    IntegrityRequirement(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        IR,
    ),

    #[display(fmt = "AR:{}", _0)]
    AvailabilityRequirement(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        AR,
    ),

    #[display(fmt = "MAV:{}", _0)]
    ModifiedAttackVector(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        MAV,
    ),

    #[display(fmt = "MAC:{}", _0)]
    ModifiedAttackComplexity(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        MAC,
    ),

    #[display(fmt = "MPR:{}", _0)]
    ModifiedPrivilegesRequired(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        MPR,
    ),

    #[display(fmt = "MUI:{}", _0)]
    ModifiedUserInteraction(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        MUI,
    ),

    #[display(fmt = "MS:{}", _0)]
    ModifiedScope(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        MS,
    ),

    #[display(fmt = "MC:{}", _0)]
    ModifiedConfidentiality(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        MC,
    ),

    #[display(fmt = "MI:{}", _0)]
    ModifiedIntegrity(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        MI,
    ),

    #[display(fmt = "MA:{}", _0)]
    ModifiedAvailability(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        MA,
    ),
}
impl CVSSv3Metric {
    const fn value(&self) -> f64 {
        use CVSSv3Metric::*;
        match self {
            AttackVector(x) => x.value(),
            AttackComplexity(x) => x.value(),
            PrivilegesRequired(x) => x.value(),
            UserInteraction(x) => x.value(),
            Confidentiality(x) => x.value(),
            Integrity(x) => x.value(),
            Availability(x) => x.value(),
            ExploitMaturity(x) => x.value(),
            RemediationLevel(x) => x.value(),
            ReportConfidence(x) => x.value(),
            ConfidentialityRequirement(x) => x.value(),
            IntegrityRequirement(x) => x.value(),
            AvailabilityRequirement(x) => x.value(),
            ModifiedAttackVector(x) => x.value(),
            ModifiedAttackComplexity(x) => x.value(),
            ModifiedPrivilegesRequired(x) => x.value(),
            ModifiedUserInteraction(x) => x.value(),
            ModifiedConfidentiality(x) => x.value(),
            ModifiedIntegrity(x) => x.value(),
            ModifiedAvailability(x) => x.value(),
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Display, Debug)]
pub enum Version {
    #[display(fmt = "CVSS:3.0")]
    V3,
    #[display(fmt = "CVSS:3.1")]
    V31,
}

#[derive(Debug)]
pub struct Vector(Vec<CVSSv3Metric>);
impl fmt::Display for Vector {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let vals = &self.0;
        let strs: Vec<String> = vals.into_iter().map(|x| x.to_string()).collect();
        write!(f, "{}", strs.join("/"))
    }
}

#[derive(Debug)]
pub struct CVSSv3(pub Version, pub Vector);
impl fmt::Display for CVSSv3 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}/{}", self.0, self.1)
    }
}

impl IntoIterator for CVSSv3 {
    type Item = CVSSv3Metric;
    type IntoIter = <Vec<CVSSv3Metric> as IntoIterator>::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.1.0.into_iter()
    }
}

impl Deref for CVSSv3 {
    type Target = [CVSSv3Metric];
    fn deref(&self) -> &[CVSSv3Metric] {
        &self.1.0[..]
    }
}

impl FromStr for CVSSv3 {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use CVSSv3Metric::*;

        let parse_tree = CVSSv3Parser::parse(Rule::cvss_vector, s)?.next().unwrap();
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
                    .context("multiple AV values detected")?;
                }
                Rule::attack_complexity => {
                    match entry.into_inner().next().unwrap().as_rule() {
                        Rule::low => vector.insert(AttackComplexity(AC::L)),
                        Rule::high => vector.insert(AttackComplexity(AC::H)),
                        _ => unreachable!(),
                    }
                    .then_some(())
                    .context("multiple AC values detected")?;
                }

                Rule::privileges_required => {
                    match entry.into_inner().next().unwrap().as_rule() {
                        Rule::none => vector.insert(PrivilegesRequired(PR::N)),
                        Rule::low => vector.insert(PrivilegesRequired(PR::L)),
                        Rule::high => vector.insert(PrivilegesRequired(PR::H)),
                        _ => unreachable!(),
                    }
                    .then_some(())
                    .context("multiple PR values detected")?;
                }
                Rule::user_interaction => {
                    match entry.into_inner().next().unwrap().as_rule() {
                        Rule::none => vector.insert(UserInteraction(UI::N)),
                        Rule::required => vector.insert(UserInteraction(UI::R)),
                        _ => unreachable!(),
                    }
                    .then_some(())
                    .context("multiple UI values detected")?;
                }
                Rule::scope => {
                    match entry.into_inner().next().unwrap().as_rule() {
                        Rule::unchanged => vector.insert(Scope(S::U)),
                        Rule::changed => vector.insert(Scope(S::C)),
                        _ => unreachable!(),
                    }
                    .then_some(())
                    .context("multiple S values detected")?;
                }
                Rule::confidentiality => {
                    match entry.into_inner().next().unwrap().as_rule() {
                        Rule::high => vector.insert(Confidentiality(C::H)),
                        Rule::low => vector.insert(Confidentiality(C::L)),
                        Rule::none => vector.insert(Confidentiality(C::N)),
                        _ => unreachable!(),
                    }
                    .then_some(())
                    .context("multiple C values detected")?;
                }
                Rule::integrity => {
                    match entry.into_inner().next().unwrap().as_rule() {
                        Rule::high => vector.insert(Integrity(I::H)),
                        Rule::low => vector.insert(Integrity(I::L)),
                        Rule::none => vector.insert(Integrity(I::N)),
                        _ => unreachable!(),
                    }
                    .then_some(())
                    .context("multiple I values detected")?;
                }
                Rule::availability => {
                    match entry.into_inner().next().unwrap().as_rule() {
                        Rule::high => vector.insert(Availability(A::H)),
                        Rule::low => vector.insert(Availability(A::L)),
                        Rule::none => vector.insert(Availability(A::N)),
                        _ => unreachable!(),
                    }
                    .then_some(())
                    .context("multiple A values detected")?;
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
                    .context("multiple E values detected")?;
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
                    .context("multiple RL values provided")?;
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
                    .context("multiple RC values provided")?;
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
                    .context("multiple CR values provided")?;
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
                    .context("multiple IR values provided")?;
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
                    .context("multiple AR values provided")?;
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
                    .context("multiple MAV values provided")?;
                }
                Rule::modified_attack_complexity => {
                    match entry.into_inner().next().unwrap().as_rule() {
                        Rule::high => vector.insert(ModifiedAttackComplexity(MAC::H)),
                        Rule::low => vector.insert(ModifiedAttackComplexity(MAC::L)),
                        Rule::not_defined => vector.insert(ModifiedAttackComplexity(MAC::X)),
                        _ => unreachable!(),
                    }
                    .then_some(())
                    .context("multiple MAC values provided")?;
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
                    .context("multiple MPR values provided")?;
                }
                Rule::modified_user_interaction => {
                    match entry.into_inner().next().unwrap().as_rule() {
                        Rule::none => vector.insert(ModifiedUserInteraction(MUI::N)),
                        Rule::required => vector.insert(ModifiedUserInteraction(MUI::R)),
                        Rule::not_defined => vector.insert(ModifiedUserInteraction(MUI::X)),
                        _ => unreachable!(),
                    }
                    .then_some(())
                    .context("multiple MUI values provided")?;
                }
                Rule::modified_scope => {
                    match entry.into_inner().next().unwrap().as_rule() {
                        Rule::unchanged => vector.insert(ModifiedScope(MS::U)),
                        Rule::changed => vector.insert(ModifiedScope(MS::C)),
                        Rule::not_defined => vector.insert(ModifiedScope(MS::X)),
                        _ => unreachable!(),
                    }
                    .then_some(())
                    .context("multiple MS values provided")?;
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
                    .context("multiple MC values provided")?;
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
                    .context("multiple MI values provided")?;
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
                    .context("multiple MA values provided")?;
                }

                _ => unreachable!(),
            }
        }

        let mut v = Vec::from_iter(vector);
        v.sort();
        Ok(CVSSv3(version.unwrap(), Vector(v)))
    }
}

impl CVSSv3 {
    pub fn base_score(&self) -> Result<f64> {
        use CVSSv3Metric::*;
        if let [av, ac, pr, ui, s, c, i, a, ..] = &self[..] {
            let iss: f64 = 1.0 - ((1.0 - c.value()) * (1.0 - i.value()) * (1.0 - a.value()));
            let impact = match s {
                Scope(scope @ S::C) => {
                    (scope.value() * (iss - 0.029) - 3.25 * (iss - 0.02)).powf(15.0)
                }
                Scope(scope @ S::U) => &scope.value() * iss,
                _ => unreachable!(),
            };

            if let (PrivilegesRequired(privileges_required), Scope(scope)) = (pr, s) {
                let exploitability: f64 = 8.22
                    * av.value()
                    * ac.value()
                    * ui.value()
                    * privileges_required.scoped_value(&scope);

                if impact <= 0.0 {
                    Ok(0.0)
                } else {
                    Ok(match s {
                        Scope(S::U) => roundup((impact + exploitability).min(10.0)),
                        Scope(S::C) => roundup((1.08 * (impact + exploitability)).min(10.0)),
                        _ => unreachable!(),
                    })
                }
            } else {
                Err(anyhow!("unable to calculate base score"))
            }
        } else {
            Err(anyhow!("unable to calculate base score"))
        }
    }

    pub fn temporal_score(&self) -> Result<f64> {
        let base_score = self.base_score()?;
        if let [e, rl, rc, ..] = &self[8..] {
            Ok(roundup(base_score * &e.value() * &rl.value() * &rc.value()))
        } else {
            Err(anyhow!("unable to calculate temporal score"))
        }
    }

    pub fn environmental_score(&self) -> Result<f64> {
        use CVSSv3Metric::*;

        if let [e, rl, rc, cr, ir, ar, mav, mac, mpr, mui, ms, mc, mi, ma] = &self[8..] {
            let miss: f64 = f64::min(
                1.0 - ((1.0 - cr.value() * mc.value())
                    * (1.0 - ir.value() * mi.value())
                    * (1.0 - ar.value() * ma.value())),
                0.915,
            );
            let modified_impact = match ms {
                ModifiedScope(scope @ MS::U) | ModifiedScope(scope @ MS::X) => scope.value() * miss,
                ModifiedScope(scope @ MS::C) => {
                    (scope.value() * (miss * 0.29) - 3.25 * (miss * 0.9731 - 0.02)).powf(13.0)
                }
                _ => unreachable!(),
            };

            if let (ModifiedPrivilegesRequired(privileges_required), ModifiedScope(scope)) =
                (mpr, ms)
            {
                let modified_exploitability = 8.22
                    * mav.value()
                    * mac.value()
                    * privileges_required.scoped_value(&scope)
                    * mui.value();
                if modified_impact <= 0.0 {
                    Ok(0.0)
                } else {
                    let temporal_product = &e.value() * &rl.value() * &rc.value();
                    let result = match ms {
                        ModifiedScope(MS::U) | ModifiedScope(MS::X) => roundup(
                            roundup((modified_impact + modified_exploitability).min(10.0))
                                * temporal_product,
                        ),

                        ModifiedScope(MS::C) => roundup(
                            roundup((1.08 * (modified_impact + modified_exploitability)).min(10.0))
                                * temporal_product,
                        ),

                        _ => unreachable!(),
                    };
                    Ok(result)
                }
            } else {
                Err(anyhow!("unable to calculate environmental score"))
            }
        } else {
            Err(anyhow!("unable to calculate environmental score"))
        }
    }

    pub fn severity(&self) -> Result<SeverityRating> {
        self.base_score()?.try_into()
    }
}

fn roundup(input: f64) -> f64 {
    let score = (input * 100_000.0) as u64;
    if score % 10000 == 0 {
        (score as f64) / 100_000.0
    } else {
        (((score as f64) / 10_000.0).floor() + 1.0) / 10.0
    }
}
