use crate::errors::CVSSError;
use derive_more::Display;

// These are the NVD vulnerability severity ratings for CVSS v2
//
// https://nvd.nist.gov/vuln-metrics/cvss
//
#[derive(Clone, Display, Debug, PartialEq)]
pub enum SeverityRating {
    Low,
    Medium,
    High,
}

impl TryFrom<f64> for SeverityRating {
    type Error = CVSSError;

    fn try_from(score: f64) -> Result<Self, Self::Error> {
        use SeverityRating::*;
        match score {
            x if (0.0..=3.9).contains(&x) => Ok(Low),
            x if (4.0..=6.9).contains(&x) => Ok(Medium),
            x if (7.0..=10.0).contains(&x) => Ok(High),
            _ => Err(CVSSError::InvalidScore),
        }
    }
}
