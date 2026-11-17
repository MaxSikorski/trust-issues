//! Manual check of the SOCKS path: `cargo run --example socks_probe -- <socks-addr> <url>`.
#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    for proxy in [
        format!("socks5h://{}", args[1]),
        format!("socks5h://probe:x@{}", args[1]),
    ] {
        let client = reqwest::Client::builder()
            .proxy(reqwest::Proxy::all(&proxy).unwrap())
            .build()
            .unwrap();
        match client.get(&args[2]).send().await {
            Ok(r) => println!(
                "{proxy}: HTTP {} {}",
                r.status(),
                r.text().await.unwrap_or_default()
            ),
            Err(e) => {
                let mut s = e.to_string();
                let mut cur = std::error::Error::source(&e);
                while let Some(c) = cur {
                    s.push_str(&format!(" | {c:?}"));
                    cur = c.source();
                }
                println!("{proxy}: ERR {s}");
            }
        }
    }
}
