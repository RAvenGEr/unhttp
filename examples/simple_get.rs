use std::env;

use log::error;
use unhttp::{Client, MultipartReplaceClient, Uri};

#[tokio::main]
async fn main() -> unhttp::Result<()> {
    pretty_env_logger::init();

    let url = match env::args().nth(1) {
        Some(url) => url,
        None => {
            println!("Usage: client <url>");
            return Ok(());
        }
    };

    let url = url.parse::<Uri>().unwrap();
    if url.scheme_str() != Some("http") {
        println!("Unhttp only works with 'http' URLs.");
        return Ok(());
    }

    println!("Attempting to GET: {url}");
    let mut client = Client::new();
    let response = client.get(url).await?;

    println!("Response is {}", response.status);

    if let Some(body) = client.body().await? {
        println!("Have body:{}", String::from_utf8_lossy(&body));
    } else {
        match MultipartReplaceClient::from_client_response(client, response) {
            Ok(mut m) => loop {
                let buf = m.next_part_sized().await?;
                println!("Chunk: `{}`", String::from_utf8_lossy(&buf));
            },
            Err(e) => {
                let (c, err) = e.into_parts();
                error!("Failed conversion {err}");
                client = c;
                loop {
                    let buf = client.read_some().await?;
                    println!("Have data: {}", String::from_utf8_lossy(&buf));
                }
            }
        }
    }

    Ok(())
}
