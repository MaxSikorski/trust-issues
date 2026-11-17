//! Running as a service: the `/health` probe, the progress clock behind the
//! systemd watchdog, and the notify protocol itself.

mod common;

use common::*;
use trust_issues::node::HEALTHY_WITHIN_SECS;
use trust_issues::rpc::{Auth, router};
use trust_issues::source::SourceError;
use trust_issues::systemd;

#[tokio::test]
async fn health_needs_no_login_and_says_only_up_and_synced() {
    let blocks = build_chain(2, 1);
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    let (node, clock) = started_node(&[a, b.clone()], &blocks).await;
    let app = router(
        node.clone(),
        Auth {
            cookie_password: "c00k1e".into(),
            user: None,
            password: None,
        },
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let client = reqwest::Client::builder().no_proxy().build().unwrap();

    let r = client
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 200);
    let v: serde_json::Value = serde_json::from_str(&r.text().await.unwrap()).unwrap();
    assert_eq!(
        v,
        serde_json::json!({"status": "ok", "ready": true, "synced": true})
    );

    // The detailed status page still needs the login.
    let r = client
        .get(format!("http://{addr}/status"))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status().as_u16(), 401);

    // One source down for over 5 minutes: still up, no longer synced.
    b.with(|s| s.fail = Some(SourceError::Transport("down".into())));
    clock.advance(HEALTHY_WITHIN_SECS + 1);
    node.tick().await;
    let r = client
        .get(format!("http://{addr}/health"))
        .send()
        .await
        .unwrap();
    let v: serde_json::Value = serde_json::from_str(&r.text().await.unwrap()).unwrap();
    assert_eq!(v["synced"], false);
}

#[tokio::test]
async fn progress_resets_on_every_poll_even_when_every_source_fails() {
    let blocks = build_chain(3, 1);
    let a = FakeSource::honest("a", &blocks);
    let b = FakeSource::honest("b", &blocks);
    let (node, clock) = started_node(&[a.clone(), b.clone()], &blocks).await;
    assert_eq!(node.seconds_since_progress(), 0);
    clock.advance(500);
    assert_eq!(
        node.seconds_since_progress(),
        500,
        "nothing ran, so it grows"
    );
    node.tick().await;
    assert_eq!(node.seconds_since_progress(), 0);

    // Explorers down is not a hang: the node keeps working (and alarming),
    // so the watchdog must not restart it in a loop.
    for s in [&a, &b] {
        s.with(|st| st.fail = Some(SourceError::Transport("down".into())));
    }
    clock.advance(500);
    node.tick().await;
    assert_eq!(node.seconds_since_progress(), 0);
}

#[test]
fn the_watchdog_pings_only_while_the_node_makes_progress() {
    let poll = 60;
    assert!(systemd::should_ping(0, poll));
    assert!(systemd::should_ping(poll + systemd::STALL_GRACE_SECS, poll));
    assert!(!systemd::should_ping(
        poll + systemd::STALL_GRACE_SECS + 1,
        poll
    ));
}

#[test]
fn watchdog_settings_are_read_like_systemd_means_them() {
    use std::time::Duration;
    let f = systemd::watchdog_interval_from;
    assert_eq!(f(Some("2000000"), None, 7), Some(Duration::from_secs(1)));
    assert_eq!(
        f(Some("2000000"), Some("7"), 7),
        Some(Duration::from_secs(1))
    );
    assert_eq!(
        f(Some("2000000"), Some("8"), 7),
        None,
        "meant for another process"
    );
    assert_eq!(f(Some("0"), None, 7), None);
    assert_eq!(f(Some("soon"), None, 7), None);
    assert_eq!(f(None, None, 7), None, "no WatchdogSec");
}

#[cfg(unix)]
#[test]
fn notify_sends_one_datagram_to_the_socket() {
    use std::os::unix::net::UnixDatagram;
    let path = std::env::temp_dir().join(format!("ti-notify-{}.sock", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let listener = UnixDatagram::bind(&path).unwrap();
    systemd::notify_to(&path, "READY=1\nSTATUS=listening").unwrap();
    let mut buf = [0u8; 256];
    let n = listener.recv(&mut buf).unwrap();
    assert_eq!(&buf[..n], b"READY=1\nSTATUS=listening");
    let _ = std::fs::remove_file(&path);

    assert!(
        systemd::notify_to(std::path::Path::new("@abstract"), "READY=1").is_err(),
        "abstract sockets are refused, not misread as a file path"
    );
}
