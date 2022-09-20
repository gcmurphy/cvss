pub fn roundup(input: f64) -> f64 {
    let score = (input * 100_000.0) as u64;
    if score % 10000 == 0 {
        (score as f64) / 100_000.0
    } else {
        (((score as f64) / 10_000.0).floor() + 1.0) / 10.0
    }
}
