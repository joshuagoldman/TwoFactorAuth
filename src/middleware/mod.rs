use parse_duration::parse;

pub mod expiration;
pub mod models;

pub fn token_has_not_expired(
    token_created_time: &std::time::SystemTime,
    session_duration_str: &String,
) -> bool {
    let max_duration = parse(session_duration_str).unwrap_or(std::time::Duration::new(3600, 0));

    let elapsed_time = token_created_time.elapsed().unwrap();

    if elapsed_time.as_secs() > max_duration.as_secs() {
        false
    } else {
        true
    }
}
