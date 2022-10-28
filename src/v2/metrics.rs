use derivative::Derivative;
use derive_more::Display;

// Access Vector
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AV {
    N, // network
    A, // adjacent
    L, // local
}

// Access Complexity
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AC {
    H, // high
    M, // medium
    L, // low
}

// Authentication
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum AU {
    M, // multiple
    S, // single
    N, // none
}

// Confidentiality
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum C {
    N, // none
    P, // partial
    C, // complete
}

// Integrity
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum I {
    N, // none
    P, // partial
    C, // complete
}

// Availability
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum A {
    N, // none
    P, // partial
    C, // complete
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

// Remediation level
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RL {
    OF, // official fix
    TF, // temporary fix
    W,  // workaround
    U,  // unavailable
    ND, // not defined
}

// Report confidence
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum RC {
    UC, // unconfirmed
    UR, // uncorroborated
    C,  // confirmed
    ND, // not defined
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

// Target distribution
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum TD {
    N,  // none
    L,  // low
    M,  // medium
    H,  // high
    ND, // not defined
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

// Integrity Requirement
#[derive(Clone, Display, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum IR {
    N,  // none
    L,  // low
    M,  // medium
    H,  // high
    ND, // not defined
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
