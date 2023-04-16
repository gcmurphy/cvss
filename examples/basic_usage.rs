use cvss::{severity::SeverityRating, CVSS};
use std::str::FromStr;

fn main() {
    let input = "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N/E:F/RL:U/RC:C/CR:H/IR:H/AR:M/MAV:N/MAC:L/MPR:N/MUI:N/MS:U/MC:H/MI:H/MA:H";
    let cvss = CVSS::from_str(input).unwrap();
    println!("Vector = {}", cvss);
    println!("Base Score = {:.1}", cvss.base_score().unwrap());
    println!("Temporal Score = {:.1}", cvss.temporal_score().unwrap());
    println!(
        "Environmental Score = {:.1}",
        cvss.environmental_score().unwrap()
    );
    let severity_rating: SeverityRating = (&cvss).try_into().unwrap();
    println!("Severity Rating = {}", severity_rating);
    cvss.into_iter().for_each(|i| println!("{}", i));
}
