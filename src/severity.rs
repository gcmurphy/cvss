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
            x if (0.1..=3.9).contains(&x) => Ok(Low),
            x if (4.0..=6.9).contains(&x) => Ok(Medium),
            x if (7.0..=8.9).contains(&x) => Ok(High),
            x if (9.0..=10.0).contains(&x) => Ok(Critical),
            _ => Err(CVSSError::InvalidScore),
        }
    }
}
