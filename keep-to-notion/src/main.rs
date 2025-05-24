use anyhow::{Context, Result};
use dotenv::dotenv;
use indicatif::{ProgressBar, ProgressStyle};
use lazy_static::lazy_static;
use oauth2::{
    basic::BasicClient, reqwest::http_client, AuthUrl, ClientId, ClientSecret, CsrfToken,
    RedirectUrl, Scope, TokenResponse, TokenUrl,
};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use scraper::{Html, Selector};
use serde_json::json;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH, Duration};
use std::{fs, vec};
use url::Url;
use walkdir::WalkDir;
use zip;

#[derive(Clone)]
struct TokenManager {
    token: String,
    refresh_token: String,
    expires_at: u64,
}

impl TokenManager {
    fn new() -> Self {
        Self {
            token: String::new(),
            refresh_token: String::new(),
            expires_at: 0,
        }
    }

    fn is_valid(&self) -> bool {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        self.expires_at > current_time && !self.token.is_empty()
    }

    fn set_token(&mut self, token: String, refresh_token: String, expires_in: u64) {
        self.token = token;
        self.refresh_token = refresh_token;
        self.expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + expires_in;
    }
}

lazy_static! {
    static ref DROPBOX_TOKEN: Mutex<TokenManager> = Mutex::new(TokenManager::new());
}

fn find_html_files(dir: &Path) -> Vec<PathBuf> {
    WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "html"))
        .map(|e| e.path().to_path_buf())
        .collect()
}

fn extract_img_srcs(html_path: &Path) -> Result<Vec<String>> {
    let content = fs::read_to_string(html_path)
        .with_context(|| format!("Failed to read file: {:?}", html_path))?;
    let document = Html::parse_document(&content);
    let selector = Selector::parse("img").unwrap();

    Ok(document
        .select(&selector)
        .filter_map(|el| el.value().attr("src"))
        .map(|s| s.to_string())
        .collect())
}

fn find_image_in_dir(src_dir: &Path, filename: &str) -> Option<PathBuf> {
    for entry in WalkDir::new(src_dir).into_iter().filter_map(|e| e.ok()) {
        if let Some(file_name) = entry.path().file_name().and_then(|n| n.to_str()) {
            if file_name == filename {
                return Some(entry.path().to_path_buf());
            }
        }
    }
    None
}

fn extract_html_title(html_path: &Path) -> Result<String> {
    let content = fs::read_to_string(html_path)
        .with_context(|| format!("Failed to read file: {:?}", html_path))?;
    let document = Html::parse_document(&content);
    let selector = Selector::parse("title").unwrap();

    if let Some(title_element) = document.select(&selector).next() {
        // Extract the text inside the <title> tag
        let title_text = title_element
            .text()
            .collect::<Vec<_>>()
            .join("")
            .trim()
            .to_string();
        Ok(title_text)
    } else {
        Err(anyhow::anyhow!("No <title> tag found in {:?}", html_path))
    }
}

fn extract_html_body(html_path: &Path) -> Result<String> {
    let content = fs::read_to_string(html_path)
        .with_context(|| format!("Failed to read file: {:?}", html_path))?;
    let document = Html::parse_document(&content);
    let selector = Selector::parse("div.content").unwrap();

    if let Some(content_element) = document.select(&selector).next() {
        // Extract the text inside the div.content element
        let content_text = content_element
            .text()
            .collect::<Vec<_>>()
            .join("\n")
            .replace("☐\n\n\n", "◻️ ")
            .replace("☑\n\n\n", "✅ ")
            .replace("\n\n\n", "\n")
            .replace("\n\n", "\n")
            .trim()
            .to_string();
        Ok(content_text)
    } else {
        Err(anyhow::anyhow!(
            "No div with class 'content' found in {:?}",
            html_path
        ))
    }
}

fn extract_html_tags(html_path: &Path) -> Result<Vec<String>> {
    let content = fs::read_to_string(html_path)
        .with_context(|| format!("Failed to read file: {:?}", html_path))?;
    let document = Html::parse_document(&content);
    let selector = Selector::parse("div.chips .chip .label-name").unwrap();

    let tags: Vec<String> = document
        .select(&selector)
        .map(|element| element.text().collect::<String>().trim().to_string())
        .collect();
    Ok(tags)
}

fn _export_to_markdown(note: Note, output_dir: &Path, index: u64) -> Result<(), anyhow::Error> {
    let file_path = output_dir.join(format!("{}.md", index.to_string()));
    println!("file_path: {:?}", file_path.display());
    let mut file = BufWriter::new(File::create(&file_path)?);

    // Write YAML front matter
    // writeln!(file, "---")?;
    writeln!(file, "# {}", note.title)?;
    writeln!(file, "")?;
    writeln!(
        file,
        "tag: {}",
        note.tags
            .iter()
            .map(|t| format!("{}", t))
            .collect::<Vec<_>>()
            .join(", ")
    )?;
    writeln!(file, "")?;
    // writeln!(file, "---\n")?;

    // Write image references
    for image_path in note.image_paths {
        // If using relative paths:
        let image_path = Path::new(image_path);
        _copy_image(image_path, output_dir)?;
        let image_name = image_path.file_name().unwrap_or_default().to_string_lossy();
        writeln!(file, "![]({})", image_name)?;
        writeln!(file, "")?;
    }

    writeln!(file, "\n{}", note.body)?;
    Ok(())
}

fn _copy_image(image_path: &Path, target_folder: &Path) -> Result<(), anyhow::Error> {
    let file_name = image_path.file_name().unwrap();
    let destination = target_folder.join(file_name);

    fs::copy(image_path, &destination)
        .with_context(|| format!("Failed to copy image to {:?}", destination))?;
    Ok(())
}

fn get_dropbox_token() -> Result<String> {
    let token_manager = DROPBOX_TOKEN.lock().unwrap();
    if !token_manager.is_valid() {
        drop(token_manager);
        if !DROPBOX_TOKEN.lock().unwrap().refresh_token.is_empty() {
            refresh_dropbox_token()?;
        } else {
            create_dropbox_token()?;
        }
        Ok(DROPBOX_TOKEN.lock().unwrap().token.clone())
    } else {
        Ok(token_manager.token.clone())
    }
}

fn refresh_dropbox_token() -> Result<()> {
    let client_id = env::var("DROPBOX_KEY")?;
    let secret = env::var("DROPBOX_SECRET")?;
    let refresh_token = DROPBOX_TOKEN.lock().unwrap().refresh_token.clone();

    // 1. Setup OAuth2 client
    let client = BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(secret)),
        AuthUrl::new("https://www.dropbox.com/oauth2/authorize".to_string()).unwrap(),
        Some(TokenUrl::new("https://api.dropboxapi.com/oauth2/token".to_string()).unwrap()),
    );

    let token_response = client
        .exchange_refresh_token(&oauth2::RefreshToken::new(refresh_token))
        .request(http_client)
        .expect("Failed to refresh token");

    let mut token_manager = DROPBOX_TOKEN.lock().unwrap();
    token_manager.set_token(
        token_response.access_token().secret().to_string(),
        token_response.refresh_token().unwrap().secret().to_string(),
        token_response.expires_in().map(|d| d.as_secs()).unwrap_or(14400)
    );
    println!("DROPBOX_TOKEN: {}", token_manager.token);
    Ok(())
}

fn create_dropbox_token() -> Result<()> {
    let client_id = env::var("DROPBOX_KEY")?;
    let secret = env::var("DROPBOX_SECRET")?;

    // 1. Setup OAuth2 client
    let client = BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(secret)),
        AuthUrl::new("https://www.dropbox.com/oauth2/authorize".to_string()).unwrap(),
        Some(TokenUrl::new("https://api.dropboxapi.com/oauth2/token".to_string()).unwrap()),
    )
    .set_redirect_uri(RedirectUrl::new("http://localhost:8080/callback".to_string()).unwrap());

    // 2. Generate the authorization URL
    let (auth_url, _csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("files.content.write".to_string()))
        .add_scope(Scope::new("files.content.read".to_string()))
        .add_scope(Scope::new("sharing.write".to_string()))
        .add_extra_param("token_access_type", "offline")
        .url();

    // 3. Open the authorization URL in the default browser
    println!("Please open this URL in your browser to authorize the application:");
    println!("{}", auth_url);

    // 4. Start a local server to receive the callback
    let listener = std::net::TcpListener::bind("127.0.0.1:8080")?;
    println!("Waiting for authorization...");

    // 5. Handle the callback
    let (stream, _) = listener.accept()?;
    let mut stream = std::io::BufReader::new(stream);
    let mut request_line = String::new();
    stream.read_line(&mut request_line)?;

    // 6. Extract the authorization code from the request
    let code = request_line
        .split_whitespace()
        .nth(1)
        .and_then(|path| {
            Url::parse(&format!("http://localhost{}", path))
                .ok()
                .and_then(|url| {
                    url.query_pairs()
                        .find(|(key, _)| key == "code")
                        .map(|(_, value)| value.into_owned())
                })
        })
        .ok_or_else(|| anyhow::anyhow!("Failed to get authorization code"))?;

    // 7. Exchange the code for a token
    let token_response = client
        .exchange_code(oauth2::AuthorizationCode::new(code))
        .request(http_client)
        .expect("Failed to exchange code");

    let mut token_manager = DROPBOX_TOKEN.lock().unwrap();
    token_manager.set_token(
        token_response.access_token().secret().to_string(),
        token_response.refresh_token().unwrap().secret().to_string(),
        token_response
            .expires_in()
            .map(|d| d.as_secs())
            .unwrap_or(14400), // Default to 4 hours if not specified
    );
    println!("DROPBOX_TOKEN: {}", token_manager.token);
    Ok(())
}

fn upload_image_to_dropbox(file_path: &Path) -> Result<String, anyhow::Error> {
    let dropbox_path = format!(
        "/images/notion/{}",
        file_path.file_name().unwrap().to_str().unwrap()
    );
    let access_token = get_dropbox_token()?;

    let file_bytes = fs::read(file_path)?;

    let client = reqwest::blocking::Client::new();

    let dropbox_api_arg = serde_json::json!({
        "path": dropbox_path,
        "mode": "overwrite",
        "autorename": false,
        "mute": false
    }).to_string();
    
    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", access_token))?,
    );
    headers.insert(
        "Dropbox-API-Arg",
        HeaderValue::from_str(&dropbox_api_arg)?,
    );
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );

    println!("Uploading {} to Dropbox...", dropbox_path);

    let res = client
        .post("https://content.dropboxapi.com/2/files/upload")
        .headers(headers)
        .body(file_bytes)
        .timeout(Duration::from_secs(120))
        .send()?;

    if res.status().is_success() {
        println!("Upload success. Getting share link...");
        let url = get_or_create_shared_link(&dropbox_path)?;
        println!("Dropbox image URL: {}", url);
        Ok(url)
    } else {
        panic!("Failed to upload image to Dropbox: {:?}", res.text()?);
    }
}

fn get_or_create_shared_link(path: &str) -> Result<String, anyhow::Error> {
    let token = get_dropbox_token()?;
    let client = Client::new();

    // Try creating a new shared link
    let create_res = client
        .post("https://api.dropboxapi.com/2/sharing/create_shared_link_with_settings")
        .header(AUTHORIZATION, format!("Bearer {}", token))
        .header(CONTENT_TYPE, "application/json")
        .json(&json!({
            "path": path,
            "settings": {
                "requested_visibility": "public"
            }
        }))
        .send()?;

    if create_res.status().is_success() {
        let json: serde_json::Value = create_res.json()?;
        let url = json["url"]
            .as_str()
            .unwrap_or("")
            .replace("?dl=0", "?raw=1")
            .replace("&dl=0", "&raw=1");
        return Ok(url);
    } else {
        let err_json: serde_json::Value = create_res.json()?;
        let error_tag = err_json["error"][".tag"].as_str().unwrap_or("");

        // If link already exists, fetch it
        if error_tag == "shared_link_already_exists" {
            let list_res = client
                .post("https://api.dropboxapi.com/2/sharing/list_shared_links")
                .header(AUTHORIZATION, format!("Bearer {}", token))
                .header(CONTENT_TYPE, "application/json")
                .json(&json!({
                    "path": path,
                    "direct_only": true
                }))
                .send()?;

            if list_res.status().is_success() {
                let json: serde_json::Value = list_res.json()?;
                if let Some(url) = json["links"][0]["url"].as_str() {
                    return Ok(url.replace("?dl=0", "?raw=1").replace("&dl=0", "&raw=1"));
                } else {
                    panic!("No shared link found in response.");
                }
            } else {
                panic!("Failed to list shared links: {}", list_res.text()?);
            }
        } else {
            panic!("Dropbox error: {:?}", err_json);
        }
    }
}

fn send_note_to_notion(note: Note) -> Result<(), anyhow::Error> {
    let notion_token = env::var("NOTION_TOKEN")?;
    let database_id = env::var("NOTION_DATABASE_ID")?;
    let client = Client::new();

    let tags_json = note
        .tags
        .iter()
        .map(|tag| json!({ "name": tag }))
        .collect::<Vec<_>>();

    let chunks = split_text(note.body, 1000);
    let rich_text_array: Vec<_> = chunks
        .iter()
        .map(|chunk| {
            json!({
                "type": "text",
                "text": { "content": chunk }
            })
        })
        .collect();
    let paragraph_block = json!({
        "object": "block",
        "type": "paragraph",
        "paragraph": {
            "rich_text": rich_text_array
        }
    });

    let children_json = std::iter::once(paragraph_block)
        .chain(note.image_paths.iter().map(|url| {
            json!({
                "object": "block",
                "type": "image",
                "image": {
                    "type": "external",
                    "external": { "url": url }
                }
            })
        }))
        .collect::<Vec<_>>();
    print!("===================> {}", database_id);
    let json_request = &json!({
        "parent": { "database_id": database_id },
        "properties": {
            "Name": {
                "title": [{ "text": { "content": note.title } }]
            },
            "Tags": {
                "multi_select": tags_json
            }
        },
        "children": children_json
    });
    let res = client
        .post("https://api.notion.com/v1/pages")
        .header("Notion-Version", "2022-06-28")
        .header(AUTHORIZATION, format!("Bearer {}", notion_token))
        .header(CONTENT_TYPE, "application/json")
        .json(json_request)
        .timeout(Duration::from_secs(60))
        .send()?;

    if res.status() != 200 {
        panic!("Failed to upload to Notion: {}", res.text()?);
    }
    println!("----------- Uploaded to Notion -----------");

    println!("Sent note: {} | Status: {}", note.title, res.status());

    Ok(())
}

fn split_text(text: &str, max_len: usize) -> Vec<String> {
    let mut result = Vec::new();
    let mut start = 0;

    // Makeing sure not to cut in the middle of a UTF-8 character:
    let chars: Vec<char> = text.chars().collect();
    let len = chars.len();

    while start < len {
        let end = (start + max_len).min(len);
        let slice: String = chars[start..end].iter().collect();
        result.push(slice);
        start = end;
    }
    result
}

pub struct Note<'a> {
    pub title: &'a str,
    pub body: &'a str, // you can use HTML or convert to plain Markdown
    pub tags: &'a Vec<String>,
    pub image_paths: &'a Vec<String>, // relative or absolute paths
}

fn _zip_and_cleanup(target_dir: &Path) -> Result<(), anyhow::Error> {
    let zip_path = target_dir.join("markdown.zip");
    let file = File::create(&zip_path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options =
        zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

    for entry in WalkDir::new(target_dir).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path.is_file() && path != zip_path {
            let name = path.strip_prefix(target_dir).unwrap().to_str().unwrap();
            zip.start_file(name, options)?;
            let mut file = File::open(path)?;
            std::io::copy(&mut file, &mut zip)?;
            fs::remove_file(path)?;
        }
    }
    zip.finish()?;
    Ok(())
}

fn check_note_exists_in_notion(title: &str) -> Result<bool> {
    let notion_token = env::var("NOTION_TOKEN")?;
    let database_id = env::var("NOTION_DATABASE_ID")?;
    let client = Client::new();

    let json_request = json!({
        "filter": {
            "property": "Name",
            "title": {
                "equals": title
            }
        }
    });

    let res = client
        .post(format!(
            "https://api.notion.com/v1/databases/{}/query",
            database_id
        ))
        .header("Notion-Version", "2022-06-28")
        .header(AUTHORIZATION, format!("Bearer {}", notion_token))
        .header(CONTENT_TYPE, "application/json")
        .json(&json_request)
        .send()?;

    if res.status() != 200 {
        return Err(anyhow::anyhow!(
            "Failed to query Notion database: {}",
            res.text()?
        ));
    }

    let response: serde_json::Value = res.json()?;
    let results = response["results"].as_array().unwrap();

    Ok(!results.is_empty())
}

fn snapshot_progress(current_index: usize) -> Result<()> {
    let mut file = File::create("processing_snapshot.txt")?;
    writeln!(file, "{}", current_index)?;
    Ok(())
}

fn load_snapshot() -> Result<Option<usize>> {
    match File::open("processing_snapshot.txt") {
        Ok(file) => {
            let reader = BufReader::new(file);
            if let Some(Ok(line)) = reader.lines().next() {
                Ok(Some(line.parse::<usize>()?))
            } else {
                Ok(None)
            }
        }
        Err(_) => Ok(None),
    }
}

fn main() -> Result<()> {
    dotenv().ok();
    let args: Vec<String> = env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <source_dir>", args[0]);
        std::process::exit(1);
    }

    let source_dir = Path::new(&args[1]);

    let mut html_files = find_html_files(source_dir);
    html_files.sort(); // optional, for predictable order

    // Create progress bar with total items
    let pb = ProgressBar::new(html_files.len() as u64);
    pb.set_style(ProgressStyle::default_bar()
        .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} ({eta}) - {msg}")
        .unwrap()
        .progress_chars("#>-"));

    let start_index = load_snapshot()?.unwrap_or(0);
    pb.set_position(start_index as u64 - 1);
    println!("Starting from file number {}", start_index);

    let mut skipped_count = 0;
    for (index, html_file) in html_files.into_iter().enumerate().skip(start_index) {
        let title = extract_html_title(&html_file)?;

        // Check if note already exists in Notion
        if check_note_exists_in_notion(&title)? {
            pb.set_message(format!("Skipping existing note: {}", title));
            skipped_count += 1;
            snapshot_progress(index + 1)?;
            pb.inc(1);
            continue;
        }

        let body = extract_html_body(&html_file)?;
        let tags = extract_html_tags(&html_file)?;
        let mut image_urls = vec![];
        let mut block_size: u64 = 0;

        // Update progress message to show current HTML file
        pb.set_message(format!(
            "Processing HTML: {:?}",
            html_file.file_name().unwrap()
        ));

        let img_srcs = extract_img_srcs(&html_file)?;
        for img_src in img_srcs {
            let filename = Path::new(&img_src).file_name().unwrap().to_str().unwrap();
            if let Some(found_image_path) = find_image_in_dir(source_dir, filename) {
                // Update progress message to show current image
                pb.set_message(format!("Processing image: {}", filename));

                // Add the size of image file to block_size
                let size = fs::metadata(&found_image_path)?.len();
                block_size += size;

                let dropbox_path = upload_image_to_dropbox(&found_image_path)?;

                // Add found_image_path to vector
                image_urls.push(dropbox_path);
            } else {
                println!("Image not found for: {}", filename);
            }
            // Increment progress for each image
            pb.inc(1);
        }

        // Add the size of html file to block_size
        let html_size = fs::metadata(&html_file)?.len();
        block_size += html_size;

        let note = Note {
            title: &title,
            body: &body,
            tags: &tags,
            image_paths: &image_urls,
        };

        send_note_to_notion(note)?;
        // _export_to_markdown(note, output_dir, index)?;

        println!(
            "Processed {:?} ({} KB) --> tags: {:?} {}",
            html_file.file_name().unwrap(),
            block_size / 1024,
            tags,
            if image_urls.len() > 0 {
                "** include image(s) **"
            } else {
                ""
            }
        );

        // Increment progress for HTML file
        snapshot_progress(index + 1)?;
        pb.inc(1);
    }

    // _zip_and_cleanup(output_dir)?;

    // Finish progress bar with completion message
    pb.finish_with_message(format!(
        "✅ All files processed successfully ({} skipped)",
        skipped_count
    ));
    Ok(())
}
