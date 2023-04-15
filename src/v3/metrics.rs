use derivative::Derivative;
use derive_more::Display;

// Attack Vector
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AV {
    N,
    A,
    L,
    P,
}
impl AV {
    pub const fn value(&self) -> f64 {
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
    pub const fn value(&self) -> f64 {
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
    pub const fn value(&self) -> f64 {
        use PR::*;
        match self {
            N => 0.85,
            L => 0.62,
            H => 0.27,
        }
    }
    pub const fn scoped_value(&self, scope: &S) -> f64 {
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
    pub const fn value(&self) -> f64 {
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
    pub const fn value(&self) -> f64 {
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
    pub const fn value(&self) -> f64 {
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
    pub const fn value(&self) -> f64 {
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
    pub const fn value(&self) -> f64 {
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
    pub const fn value(&self) -> f64 {
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
    pub const fn value(&self) -> f64 {
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
    pub const fn value(&self) -> f64 {
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
    pub const fn value(&self) -> f64 {
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
    pub const fn value(&self) -> f64 {
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
    pub const fn value(&self) -> f64 {
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
    pub const fn value(&self) -> f64 {
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
    pub const fn value(&self) -> f64 {
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
    pub const fn value(&self) -> f64 {
        use MPR::*;
        match self {
            X => 1.0,
            N => 0.85,
            L => 0.62,
            H => 0.27,
        }
    }

    pub const fn scoped_value(&self, scope: &MS) -> f64 {
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
    pub const fn value(&self) -> f64 {
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
    pub const fn value(&self) -> f64 {
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
    pub const fn value(&self) -> f64 {
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
    pub const fn value(&self) -> f64 {
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
    pub const fn value(&self) -> f64 {
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
    pub const fn value(&self) -> f64 {
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
