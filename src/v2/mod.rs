extern crate derivative;
extern crate pest;
extern crate pest_derive;
use crate::errors::CVSSError;
use crate::normalize::round_to_1_decimal;
use crate::v2::metrics::CVSSv2Metric;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

pub mod metrics;
mod parser;

#[derive(Clone, Debug)]
pub struct CVSSv2(pub Vec<metrics::CVSSv2Metric>);

impl fmt::Display for CVSSv2 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let vals = &self.0;
        let strs: Vec<String> = vals.iter().map(|x| x.to_string()).collect();
        write!(f, "{}", strs.join("/"))
    }
}

impl Deref for CVSSv2 {
    type Target = [CVSSv2Metric];
    fn deref(&self) -> &[CVSSv2Metric] {
        &self.0[..]
    }
}

impl FromStr for CVSSv2 {
    type Err = CVSSError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let metrics = parser::parse(s)?;
        Ok(CVSSv2(metrics))
    }
}

impl CVSSv2 {
    fn impact(&self) -> Result<f64, CVSSError> {
        if let [_, _, _, c, i, a, ..] = &self[..] {
            Ok(10.41 * (1.0 - (1.0 - c.value()) * (1.0 - i.value()) * (1.0 - a.value())))
        } else {
            Err(CVSSError::IncompleteBaseScore)
        }
    }

    fn adjusted_impact(&self) -> Result<f64, CVSSError> {
        if let [_, _, _, c, i, a, _, _, _, _, _, cr, ir, ar] = &self[..] {
            Ok([
                10.0,
                10.41
                    * (1.0
                        - (1.0 - c.value() * cr.value())
                            * (1.0 - i.value() * ir.value())
                            * (1.0 - a.value() * ar.value())),
            ]
            .into_iter()
            .min_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap())
        } else {
            Err(CVSSError::IncompleteEnvironmentalScore)
        }
    }

    fn calculate_base_score(&self, adjusted_impact: Option<f64>) -> Result<f64, CVSSError> {
        let impact = match adjusted_impact {
            Some(value) => value,
            None => self.impact()?,
        };

        if let [av, ac, au, ..] = &self[..] {
            let exploitability = 20.0 * av.value() * ac.value() * au.value();
            let factor = if impact == 0.0 { 0.0 } else { 1.176 };
            Ok(round_to_1_decimal(
                ((0.6 * impact) + (0.4 * exploitability) - 1.5) * factor,
            ))
        } else {
            Err(CVSSError::IncompleteBaseScore)
        }
    }

    pub fn base_score(&self) -> Result<f64, CVSSError> {
        self.calculate_base_score(None)
    }

    fn calculate_temporal_score(&self, adjusted_impact: Option<f64>) -> Result<f64, CVSSError> {
        if let [exploitability, remediation_level, report_confidence, ..] = &self[6..] {
            let base_score = self.calculate_base_score(adjusted_impact)?;
            match (exploitability, remediation_level, report_confidence) {
                (
                    CVSSv2Metric::Exploitability(_),
                    CVSSv2Metric::RemediationLevel(_),
                    CVSSv2Metric::ReportConfidence(_),
                ) => Ok(round_to_1_decimal(
                    base_score
                        * exploitability.value()
                        * remediation_level.value()
                        * report_confidence.value(),
                )),
                _ => Err(CVSSError::IncompleteTemporalScore),
            }
        } else {
            Err(CVSSError::IncompleteTemporalScore)
        }
    }

    pub fn temporal_score(&self) -> Result<f64, CVSSError> {
        self.calculate_temporal_score(None)
    }

    pub fn environmental_score(&self) -> Result<(f64, f64), CVSSError> {
        if let [cdp, td, ..] = &self[9..] {
            let adjusted_impact = self.adjusted_impact()?;
            let adjusted_temporal = self.calculate_temporal_score(Some(self.adjusted_impact()?))?;
            let environmental_score = round_to_1_decimal(
                (adjusted_temporal + (10.0 - adjusted_temporal) * cdp.value()) * td.value(),
            );
            Ok((environmental_score, round_to_1_decimal(adjusted_impact)))
        } else {
            Err(CVSSError::IncompleteEnvironmentalScore)
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_base_score_accuracy() {
        let input = "AV:L/AC:M/Au:S/C:P/I:C/A:N";
        let expected = 5.0;
        let vector = CVSSv2::from_str(input).unwrap();
        let base_score = vector.base_score().unwrap();
        assert!(base_score == expected);
    }

    #[test]
    fn test_temporal_score_accuracy() {
        let input = "AV:L/AC:M/Au:S/C:P/I:C/A:N/E:POC/RL:W/RC:C";
        let expected = 4.3;
        let vector = CVSSv2::from_str(input).unwrap();
        let temporal_score = vector.temporal_score().unwrap();
        assert!(temporal_score == expected);
    }

    #[test]
    fn test_environmental_score_accuracy() {
        let input = "AV:L/AC:M/Au:S/C:P/I:C/A:N/E:POC/RL:W/RC:C/CDP:H/TD:M/CR:H/IR:M/AR:M";
        let expected_environmental = 5.5;
        let expected_modified_impact = 8.3;
        let vector = CVSSv2::from_str(input).unwrap();
        let (environmental_score, modified_impact) = vector.environmental_score().unwrap();
        assert!(environmental_score == expected_environmental);
        assert!(modified_impact == expected_modified_impact);
    }
}
