use thiserror::Error;

#[derive(Error, Debug)]
#[non_exhaustive]
pub enum CVSSError {
    #[error("score not within expected range 0.0 -> 10.0")]
    InvalidScore,

    #[error("invalid cvss v3 vector string")]
    ParsingError,

    #[error("duplicate CVSS metrics detected in vector string")]
    DuplicateMetrics,

    #[error("unable to compute base score based on provided metrics")]
    IncompleteBaseScore,

    #[error("unable to compute temporal score based on provided metrics")]
    IncompleteTemporalScore,

    #[error("unable to compute temporal score based on provided metrics")]
    IncompleteEnvironmentalScore,
}
