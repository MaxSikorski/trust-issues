//! `cargo run --example liar`: watch Trust Issues catch a lying explorer.
//!
//! Three fake block explorers on a made-up regtest chain: alice and bob are
//! honest, mallory lies. Five scenes, each a real attack on a Lightning
//! node's chain backend, each run against the real code in `src/`.
//!
//! The scenes live in `src/demo/`; this file only prints them. The browser
//! demo (`web/`) animates the very same scenes from a WebAssembly build.
//!
//! No Tor, no network, no keys, no real coins. Add `--fast` to skip the
//! pauses (they're only there so you can read along).

use std::io::{IsTerminal, Write};
use std::time::Duration;

use trust_issues::demo::{self, Event};

struct Show {
    color: bool,
    pause: Duration,
}

impl Show {
    fn paint(&self, code: &str, s: &str) -> String {
        if self.color {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }

    fn line(&self, s: &str, beats: u32) {
        println!("{s}");
        std::io::stdout().flush().ok();
        std::thread::sleep(self.pause * beats);
    }

    fn print(&self, e: &Event) {
        match e {
            Event::Scene {
                n, title, story, ..
            } => {
                println!();
                println!("{}", self.paint("1", &format!("Scene {n}: {title}")));
                self.line(&self.paint("2", story), 2);
            }
            Event::Step { text } => self.line(&format!("  {text}"), 1),
            Event::Good { text } => self.line(&format!("  {} {text}", self.paint("32", "✔")), 1),
            Event::Caught { text, .. } => {
                self.line(&format!("  {} {text}", self.paint("31;1", "✘ CAUGHT:")), 1)
            }
            Event::Missed { text } => self.line(
                &format!(
                    "  {} expected: {text} This is a bug; please report it.",
                    self.paint("41;1", "NOT CAUGHT")
                ),
                1,
            ),
            Event::Alarm {
                critical,
                code,
                message,
            } => {
                let level = if *critical {
                    self.paint("31;1", "🚨 CRITICAL")
                } else {
                    self.paint("33;1", "⚠ WARNING")
                };
                self.line(&format!("  {level} [{code}] {message}"), 1);
            }
            Event::Status { tip, synced } => {
                let synced = if *synced {
                    self.paint("32", "yes")
                } else {
                    self.paint("31", "NO")
                };
                self.line(&format!("  Tip: block {tip}. Synced: {synced}."), 1);
            }
        }
    }
}

fn main() {
    let fast = std::env::args().any(|a| a == "--fast");
    let tty = std::io::stdout().is_terminal();
    let show = Show {
        color: tty,
        pause: if fast || !tty {
            Duration::ZERO
        } else {
            Duration::from_millis(900)
        },
    };

    // Every scene runs first (it takes milliseconds); then we replay it slowly.
    let events = demo::run_blocking();

    println!(
        "{}",
        show.paint(
            "1",
            "Trust Issues: not a node. Just a chorus of block explorers it doesn't believe."
        )
    );
    show.line(
        "Three explorers. One liar. Everything is fake except the checks.",
        2,
    );
    for e in &events {
        show.print(e);
    }

    println!();
    let missed = demo::missed(&events);
    if missed > 0 {
        println!(
            "{}",
            show.paint(
                "41;1",
                &format!("{missed} check(s) did NOT catch the lie. Please report this.")
            )
        );
        std::process::exit(1);
    }
    println!("{}", show.paint("1", "5 attacks, 5 caught."));
    println!("Signet only. Never use it with real money.");
}
