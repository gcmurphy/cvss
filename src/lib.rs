#[macro_use]
extern crate pest_derive;

pub mod errors;
pub(crate) mod normalize;
pub mod severity;
pub mod v2;
pub mod v3;

use crate::severity::SeverityRating;
use derive_more::Display;
use std::str::FromStr;

#[derive(Clone, Display, Debug)]
pub enum CVSS {
    V2(v2::CVSSv2),
    V3(v3::CVSSv3),
}

impl CVSS {
    pub fn base_score(&self) -> Result<f64, errors::CVSSError> {
        match self {
            CVSS::V2(v2) => v2.base_score(),
            CVSS::V3(v3) => v3.base_score(),
        }
    }

    pub fn temporal_score(&self) -> Result<f64, errors::CVSSError> {
        match self {
            CVSS::V2(v2) => v2.temporal_score(),
            CVSS::V3(v3) => v3.temporal_score(),
        }
    }

    pub fn environmental_score(&self) -> Result<f64, errors::CVSSError> {
        match self {
            CVSS::V2(v2) => v2.environmental_score(),
            CVSS::V3(v3) => v3.environmental_score(),
        }
    }
}

impl TryFrom<&CVSS> for SeverityRating {
    type Error = errors::CVSSError;

    fn try_from(cvss: &CVSS) -> Result<Self, Self::Error> {
        use SeverityRating::*;
        match cvss {
            CVSS::V2(v2) => {
                let score = v2.base_score()?;
                match score {
                    x if (0.0..=3.9).contains(&x) => Ok(Low),
                    x if (4.0..=6.9).contains(&x) => Ok(Medium),
                    x if (7.0..=10.0).contains(&x) => Ok(High),
                    _ => Err(errors::CVSSError::InvalidScore),
                }
            }
            CVSS::V3(v3) => {
                let score = v3.base_score()?;
                match score {
                    x if x == 0.0 => Ok(None),
                    x if (0.1..=3.9).contains(&x) => Ok(Low),
                    x if (4.0..=6.9).contains(&x) => Ok(Medium),
                    x if (7.0..=8.9).contains(&x) => Ok(High),
                    x if (9.0..=10.0).contains(&x) => Ok(Critical),
                    _ => Err(errors::CVSSError::InvalidScore),
                }
            }
        }
    }
}

impl FromStr for CVSS {
    type Err = errors::CVSSError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match v3::parser::try_parse(s) {
            Ok(v3) => Ok(CVSS::V3(v3)),
            Err(_) => match v2::parser::try_parse(s) {
                Ok(v2) => Ok(CVSS::V2(v2)),
                Err(e) => Err(e),
            },
        }
    }
}
