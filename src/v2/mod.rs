extern crate derivative;
extern crate pest;
use crate::errors::CVSSError;
use std::fmt;
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

impl FromStr for CVSSv2 {
    type Err = CVSSError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let metrics = parser::parse(s)?;
        Ok(CVSSv2(metrics))
    }
}
