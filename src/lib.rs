extern crate derivative;
extern crate pest;
#[macro_use]
extern crate pest_derive;

use derive_more::Display;
use std::fmt;
use std::ops::Deref;
use std::str::FromStr;

pub mod errors;
pub mod metrics;
mod normalize;
mod parser;
pub mod severity;

use crate::metrics::*;
use crate::normalize::roundup;

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
        let strs: Vec<String> = vals.iter().map(|x| x.to_string()).collect();
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
        self.1 .0.into_iter()
    }
}

impl Deref for CVSSv3 {
    type Target = [CVSSv3Metric];
    fn deref(&self) -> &[CVSSv3Metric] {
        &self.1 .0[..]
    }
}

impl FromStr for CVSSv3 {
    type Err = errors::CVSSError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (version, metrics) = parser::parse(s)?;
        Ok(CVSSv3(version, Vector(metrics)))
    }
}

impl CVSSv3 {
    pub fn base_score(&self) -> Result<f64, errors::CVSSError> {
        use CVSSv3Metric::*;
        if let [av, ac, pr, ui, s, c, i, a, ..] = &self[..] {
            let iss: f64 = 1.0 - ((1.0 - c.value()) * (1.0 - i.value()) * (1.0 - a.value()));
            let impact = match s {
                Scope(scope @ S::C) => {
                    scope.value() * (iss - 0.029) - 3.25 * (iss - 0.02).powf(15.0)
                }
                Scope(scope @ S::U) => scope.value() * iss,
                _ => unreachable!(),
            };

            if let (PrivilegesRequired(privileges_required), Scope(scope)) = (pr, s) {
                let exploitability: f64 = 8.22
                    * av.value()
                    * ac.value()
                    * ui.value()
                    * privileges_required.scoped_value(scope);

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
                Err(errors::CVSSError::IncompleteBaseScore)
            }
        } else {
            Err(errors::CVSSError::IncompleteBaseScore)
        }
    }

    pub fn temporal_score(&self) -> Result<f64, errors::CVSSError> {
        let base_score = self.base_score()?;
        if let [e, rl, rc, ..] = &self[8..] {
            Ok(roundup(base_score * e.value() * rl.value() * rc.value()))
        } else {
            Err(errors::CVSSError::IncompleteTemporalScore)
        }
    }

    pub fn environmental_score(&self) -> Result<f64, errors::CVSSError> {
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
                    * privileges_required.scoped_value(scope)
                    * mui.value();
                if modified_impact <= 0.0 {
                    Ok(0.0)
                } else {
                    let temporal_product = e.value() * rl.value() * rc.value();
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
                Err(errors::CVSSError::IncompleteEnvironmentalScore)
            }
        } else {
            Err(errors::CVSSError::IncompleteEnvironmentalScore)
        }
    }

    pub fn severity(&self) -> Result<severity::SeverityRating, errors::CVSSError> {
        self.base_score()?.try_into()
    }
}
