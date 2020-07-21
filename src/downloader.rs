use std::error::Error;

use indicatif::{ProgressBar, ProgressStyle};
use reqwest::{header, Client};
use std::path::Path;
use structopt::StructOpt;
use tokio::{fs, io::AsyncWriteExt};

type BoxResult<T> = Result<T, Box<dyn Error>>;

async fn download(url: &str, path: &PathBuf) -> BoxResult<()> {
    let client = Client::new();
    let total_size = {
        let resp = client.head(url).send().await?;
        if resp.status().is_success() {
            resp.headers()
                .get(header::CONTENT_LENGTH)
                .and_then(|ct_len| ct_len.to_str().ok())
                .and_then(|ct_len| ct_len.parse().ok())
                .unwrap_or(0)
        } else {
            return Err(format!("Couldn'n download URL: {}", url));
        }
    };

    let mut request = client.get(url);
    let pb = ProgressBar::new(total_size);
    pb.set_style(
        ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] \
                   [{bar:40.cyan/blue}] {bytes}/{total_bytes} ({eta})")
        .progress_chars("#>-"));

    let file = Path::new(path);

    if file.exists() {
        return Err(format!("File {:?} existed", file));
        // let size = file.metadata()?.len().saturating_sub(1);
        // request = request.header(header::RANGE, format!("bytes={}-", size));
        // pb.inc(size);
    }

    let mut source = request.send().await?;
    let mut dest = fs::OpenOptions::new().create(true).append(true).open(&file).await?;
    while let Some(chunk) = source.chunk().await? {
        dest.write_all(&chunk).await?;
        pb.inc(chunk.len() as u64);
    }

    println!("Download of '{}' has been completed.", file.to_str().unwrap());

    Ok(())
}
