use crate::errors::CVSSError;

use pest::Parser;

type Version = String;
type CVSSv2Metric = String;

#[derive(Parser)]
#[grammar = "v2/cvss_v2.pest"]
struct VectorParser;

pub(crate) fn parse(s: &str) -> Result<Vec<CVSSv2Metric>, CVSSError> {
    let parse_tree = VectorParser::parse(Rule::cvss_vector, s)
        .map_err(|_| CVSSError::ParsingError)?
        .next()
        .ok_or(CVSSError::ParsingError)?;

    println!("{:?}", parse_tree);

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
            panic!("not implemented");
        }
    }

    #[test]
    fn test_can_parse_cvss_v2_full() {
        let input = "AV:A/AC:M/Au:S/C:P/I:C/A:P/E:POC/RL:W/RC:UR/CDP:MH/TD:M/CR:M/IR:M/AR:M";
        let result = parse(input);
        assert!(result.is_ok());
        if let Ok(_vector) = result {
            panic!("not implemented");
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
