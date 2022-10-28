use crate::errors::CVSSError;
use crate::v2::metrics::CVSSv2Metric;

use pest::Parser;

#[derive(Parser)]
#[grammar = "v2/cvss_v2.pest"]
struct VectorParser;

pub(crate) fn parse(s: &str) -> Result<Vec<CVSSv2Metric>, CVSSError> {
    let parse_tree = VectorParser::parse(Rule::cvss_vector, s)
        .map_err(|_| CVSSError::ParsingError)?
        .next()
        .ok_or(CVSSError::ParsingError)?;

    println!("{:?}", parse_tree);
    for entry in parse_tree.into_inner() {
        match entry.as_rule() {
            Rule::access_vector => match entry.into_inner().next().unwrap().as_rule() {
                Rule::network => println!("network"),
                Rule::adjacent => println!("adjacent"),
                Rule::local => println!("local"),
                _ => unreachable!(),
            },
            Rule::access_complexity => match entry.into_inner().next().unwrap().as_rule() {
                Rule::high => println!("high"),
                Rule::medium => println!("medium"),
                Rule::low => println!("low"),
                _ => unreachable!(),
            },
            Rule::authentication => match entry.into_inner().next().unwrap().as_rule() {
                Rule::multiple => println!("multiple"),
                Rule::single => println!("single"),
                Rule::none => println!("none"),
                _ => unreachable!(),
            },
            Rule::confidentiality => match entry.into_inner().next().unwrap().as_rule() {
                Rule::none => println!("none"),
                Rule::partial => println!("partial"),
                Rule::complete => println!("complete"),
                _ => unreachable!(),
            },
            Rule::integrity => match entry.into_inner().next().unwrap().as_rule() {
                Rule::none => println!("none"),
                Rule::partial => println!("partial"),
                Rule::complete => println!("complete"),
                _ => unreachable!(),
            },
            Rule::availability => match entry.into_inner().next().unwrap().as_rule() {
                Rule::none => println!("none"),
                Rule::partial => println!("partial"),
                Rule::complete => println!("complete"),
                _ => unreachable!(),
            },

            Rule::exploitability => match entry.into_inner().next().unwrap().as_rule() {
                Rule::unproven => println!("unproven"),
                Rule::proof_of_concept => println!("proof of concept"),
                Rule::functional => println!("functional"),
                Rule::high => println!("high"),
                Rule::not_defined => println!("not defined"),
                _ => unreachable!(),
            },

            Rule::remediation_level => match entry.into_inner().next().unwrap().as_rule() {
                Rule::official_fix => (),
                Rule::temporary_fix => (),
                Rule::workaround => (),
                Rule::unavailable => (),
                _ => unreachable!(),
            },

            Rule::report_confidence => match entry.into_inner().next().unwrap().as_rule() {
                Rule::unconfirmed => (),
                Rule::uncorroborated => (),
                Rule::confirmed => (),
                Rule::not_defined => (),
                _ => unreachable!(),
            },

            Rule::collateral_damage_potential => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::none => (),
                    Rule::low => (),
                    Rule::low_medium => (),
                    Rule::medium_high => (),
                    Rule::high => (),
                    Rule::not_defined => (),
                    _ => unreachable!(),
                }
            }

            Rule::target_distribution => match entry.into_inner().next().unwrap().as_rule() {
                Rule::low => (),
                Rule::medium => (),
                Rule::high => (),
                Rule::not_defined => (),
                _ => unreachable!(),
            },

            Rule::confidentiality_requirement => {
                match entry.into_inner().next().unwrap().as_rule() {
                    Rule::low => (),
                    Rule::medium => (),
                    Rule::high => (),
                    Rule::not_defined => (),
                    _ => unreachable!(),
                }
            }

            Rule::integrity_requirement => match entry.into_inner().next().unwrap().as_rule() {
                Rule::low => (),
                Rule::medium => (),
                Rule::high => (),
                Rule::not_defined => (),
                _ => unreachable!(),
            },

            Rule::availability_requirement => match entry.into_inner().next().unwrap().as_rule() {
                Rule::low => (),
                Rule::medium => (),
                Rule::high => (),
                Rule::not_defined => (),
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
    }

    Ok(Vec::new())
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_can_parse_cvss_v2_base() {
        let result = parse("AV:L/AC:H/Au:N/C:C/I:C/A:C");
        assert!(result.is_ok());
        if let Ok(_vector) = result {
            println!("DONE");
            //panic!("not implemented");
        }
    }

    #[test]
    fn test_can_parse_cvss_v2_full() {
        let input = "AV:A/AC:M/Au:S/C:P/I:C/A:P/E:POC/RL:W/RC:UR/CDP:MH/TD:M/CR:M/IR:M/AR:M";
        let result = parse(input);
        assert!(result.is_ok());
        if let Ok(_vector) = result {
            println!("DONE");
            //panic!("not implemented");
        }
    }

    #[test]
    fn test_wont_accept_invalid_input() {
        let input = "AV:AA/E:POR:WR:RCP:HT:M/CR:/IR:M/AR:M";
        let result = parse(input);
        assert!(match result {
            Err(CVSSError::ParsingError) => true,
            other => {
                println!("{:?}", other);
                false
            }
        });
    }

    #[test]
    fn test_wont_allow_repeat_metrics() {
        let input = "AV:L/AC:H/Au:N/Au:N/C:C/I:C/A:C";
        let result = parse(input);
        assert!(match result {
            Err(CVSSError::ParsingError) => true,
            _ => false,
        });
    }
}
