use crate::errors::CVSSError;
use derive_more::Display;

#[derive(Clone, Display, Debug)]
pub enum SeverityRating {
    None,
    Low,
    Medium,
    High,
    Critical,
}

impl TryFrom<f64> for SeverityRating {
    type Error = CVSSError;

    fn try_from(score: f64) -> Result<Self, Self::Error> {
        use SeverityRating::*;
        match score {
            x if x == 0.0 => Ok(None),
            x if x >= 0.1 && x <= 3.9 => Ok(Low),
            x if x >= 4.0 && x <= 6.9 => Ok(Medium),
            x if x >= 7.0 && x <= 8.9 => Ok(High),
            x if x >= 9.0 && x <= 10.0 => Ok(Critical),
            _ => Err(CVSSError::InvalidScore),
        }
    }
}
