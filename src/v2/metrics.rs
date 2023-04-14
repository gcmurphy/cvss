use derivative::Derivative;
use derive_more::Display;

// Access Vector
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AV {
    N, // network
    A, // adjacent
    L, // local
}
impl AV {
    pub const fn value(&self) -> f64 {
        use AV::*;
        match self {
            N => 1.0,
            A => 0.646,
            L => 0.395,
        }
    }
}

// Access Complexity
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AC {
    H, // high
    M, // medium
    L, // low
}

impl AC {
    pub const fn value(&self) -> f64 {
        use AC::*;
        match self {
            H => 0.35,
            M => 0.61,
            L => 0.71,
        }
    }
}

// Authentication
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AU {
    M, // multiple
    S, // single
    N, // none
}

impl AU {
    pub const fn value(&self) -> f64 {
        use AU::*;
        match self {
            M => 0.45,
            S => 0.56,
            N => 0.704,
        }
    }
}

// Confidentiality
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum C {
    N, // none
    P, // partial
    C, // complete
}
impl C {
    pub const fn value(&self) -> f64 {
        use self::C::{C, N, P};
        match self {
            N => 0.0,
            P => 0.275,
            C => 0.660,
        }
    }
}

// Integrity
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum I {
    N, // none
    P, // partial
    C, // complete
}
impl I {
    pub const fn value(&self) -> f64 {
        use I::{C, N, P};
        match self {
            N => 0.0,
            P => 0.275,
            C => 0.660,
        }
    }
}

// Availability
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum A {
    N, // none
    P, // partial
    C, // complete
}
impl A {
    pub const fn value(&self) -> f64 {
        use A::{C, N, P};
        match self {
            N => 0.0,
            P => 0.275,
            C => 0.660,
        }
    }
}

// Exploitability
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum E {
    U,   // unproven
    POC, // proof of concept
    F,   // functional
    H,   // high
    ND,  // not defined
}

impl E {
    pub const fn value(&self) -> f64 {
        use E::*;
        match self {
            U => 0.85,
            POC => 0.9,
            F => 0.95,
            H => 1.0,
            ND => 1.0,
        }
    }
}

// Remediation level
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RL {
    OF, // official fix
    TF, // temporary fix
    W,  // workaround
    U,  // unavailable
    ND, // not defined
}

impl RL {
    pub const fn value(&self) -> f64 {
        use RL::*;
        match self {
            OF => 0.87,
            TF => 0.9,
            W => 0.95,
            U => 1.0,
            ND => 1.0,
        }
    }
}

// Report confidence
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RC {
    UC, // unconfirmed
    UR, // uncorroborated
    C,  // confirmed
    ND, // not defined
}
impl RC {
    pub const fn value(&self) -> f64 {
        use RC::*;
        match self {
            UC => 0.9,
            UR => 0.95,
            C => 1.0,
            ND => 1.0,
        }
    }
}

// Collateral damage potential
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CDP {
    N,  // none
    L,  // low
    LM, // low to medium
    MH, // medium to high
    H,  // high
    ND, // not defined
}

impl CDP {
    pub const fn value(&self) -> f64 {
        use CDP::*;
        match self {
            N => 0.0,
            L => 0.1,
            LM => 0.3,
            MH => 0.4,
            H => 0.5,
            ND => 0.0,
        }
    }
}

// Target distribution
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TD {
    N,  // none
    L,  // low
    M,  // medium
    H,  // high
    ND, // not defined
}

impl TD {
    pub const fn value(&self) -> f64 {
        use TD::*;
        match self {
            N => 0.0,
            L => 0.25,
            M => 0.75,
            H => 1.0,
            ND => 1.0,
        }
    }
}

// Confidentiality Requirement
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum CR {
    N,  // none
    L,  // low
    M,  // medium
    H,  // high
    ND, // not defined
}
impl CR {
    pub const fn value(&self) -> f64 {
        use CR::*;
        match self {
            N => 0.0,
            L => 0.5,
            M => 1.0,
            H => 1.51,
            ND => 1.0,
        }
    }
}

// Integrity Requirement
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum IR {
    N,  // none
    L,  // low
    M,  // medium
    H,  // high
    ND, // not defined
}

impl IR {
    pub const fn value(&self) -> f64 {
        use IR::*;
        match self {
            N => 0.0,
            L => 0.5,
            M => 1.0,
            H => 1.51,
            ND => 1.0,
        }
    }
}

// Availability Requirement
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AR {
    N,  // none
    L,  // low
    M,  // medium
    H,  // high
    ND, // not defined
}

impl AR {
    pub const fn value(&self) -> f64 {
        use AR::*;
        match self {
            N => 0.0,
            L => 0.5,
            M => 1.0,
            H => 1.51,
            ND => 1.0,
        }
    }
}

#[derive(Clone, Derivative, Display, Debug, Eq, Ord, PartialOrd)]
#[derivative(Hash, PartialEq)]
pub enum CVSSv2Metric {
    #[display(fmt = "AV:{}", _0)]
    AccessVector(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        AV,
    ),
    #[display(fmt = "AC:{}", _0)]
    AccessComplexity(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        AC,
    ),

    #[display(fmt = "AU:{}", _0)]
    Authentication(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        AU,
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
    Exploitability(
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

    #[display(fmt = "CDP:{}", _0)]
    CollateralDamagePotential(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        CDP,
    ),

    #[display(fmt = "TD:{}", _0)]
    TargetDistribution(
        #[derivative(Hash = "ignore")]
        #[derivative(PartialEq = "ignore")]
        TD,
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
}

impl CVSSv2Metric {
    pub const fn value(&self) -> f64 {
        use CVSSv2Metric::*;
        match self {
            AccessVector(x) => x.value(),
            AccessComplexity(x) => x.value(),
            Authentication(x) => x.value(),
            Confidentiality(x) => x.value(),
            Integrity(x) => x.value(),
            Availability(x) => x.value(),
            Exploitability(x) => x.value(),
            RemediationLevel(x) => x.value(),
            ReportConfidence(x) => x.value(),
            CollateralDamagePotential(x) => x.value(),
            TargetDistribution(x) => x.value(),
            ConfidentialityRequirement(x) => x.value(),
            IntegrityRequirement(x) => x.value(),
            AvailabilityRequirement(x) => x.value(),
        }
    }
}
