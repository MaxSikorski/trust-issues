//! The liar demo (terminal and browser) must catch every lie it shows.

use trust_issues::demo::{self, Event};

#[test]
fn the_demo_catches_all_five_lies() {
    let events = demo::run_blocking();
    assert_eq!(demo::missed(&events), 0, "{events:#?}");
    let scenes = events
        .iter()
        .filter(|e| matches!(e, Event::Scene { .. }))
        .count();
    let caught = events
        .iter()
        .filter(|e| matches!(e, Event::Caught { .. }))
        .count();
    assert_eq!(scenes, 5);
    assert_eq!(caught, 5, "one catch per scene");
}

#[test]
fn the_demo_ends_not_synced_with_a_critical_tip_alarm() {
    let events = demo::run_blocking();
    let last_status = events.iter().rev().find_map(|e| match e {
        Event::Status { synced, .. } => Some(*synced),
        _ => None,
    });
    assert_eq!(last_status, Some(false));
    assert!(events.iter().any(|e| matches!(
        e,
        Event::Alarm { critical: true, code, .. } if code == "tip-stale"
    )));
}

#[test]
fn the_demo_events_serialize_for_the_browser() {
    let json = serde_json::to_string(&demo::run_blocking()).unwrap();
    assert!(json.starts_with("[{\"kind\":\"scene\",\"n\":1,"));
    assert!(json.contains("\"kind\":\"caught\""));
}
