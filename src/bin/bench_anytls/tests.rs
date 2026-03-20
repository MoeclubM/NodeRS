use super::*;

#[test]
fn parse_users_csv() {
    let parsed = parse_users("u1,u2, u3 ").expect("users");
    assert_eq!(parsed, vec!["u1", "u2", "u3"]);
}

#[test]
fn parse_client_args_accepts_multiple_users() {
    let parsed = parse_client_args(vec![
        "--server".into(),
        "127.0.0.1:443".into(),
        "--sni".into(),
        "example.com".into(),
        "--users".into(),
        "u1,u2".into(),
        "--target".into(),
        "127.0.0.1:80".into(),
        "--mode".into(),
        "udp-download".into(),
    ])
    .expect("parse client");
    assert_eq!(parsed.users, vec!["u1", "u2"]);
    assert!(matches!(parsed.mode, BenchMode::UdpDownload));
    assert_eq!(parsed.chunk_size, 1400);
}

#[test]
fn encode_uot_request_marks_connect_mode() {
    let encoded =
        encode_uot_request(&SocksTarget::Domain("example.com".into(), 53)).expect("encode request");
    assert_eq!(encoded[0], 1);
    assert_eq!(encoded[1], 0x03);
}

#[test]
fn parse_scenario_args_builds_targets() {
    let parsed = parse_scenario_args(vec![
        "--server".into(),
        "127.0.0.1:443".into(),
        "--sni".into(),
        "example.com".into(),
        "--user".into(),
        "u1".into(),
        "--tcp-upload-target".into(),
        "127.0.0.1:80".into(),
        "--udp-download-target".into(),
        "127.0.0.1:53".into(),
    ])
    .expect("parse scenario");
    assert!(parsed.tcp_upload_target.is_some());
    assert!(parsed.udp_download_target.is_some());
    assert_eq!(parsed.parallel, DEFAULT_SCENARIO_PARALLEL);
}
