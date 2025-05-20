use anyhow::{Context, Result};
use dotenv::dotenv;
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE};
use scraper::{Html, Selector};
use serde_json::json;
use std::env;
use std::fmt::format;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::{fs, vec};
use walkdir::WalkDir;
use zip;
use indicatif::{ProgressBar, ProgressStyle};

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

fn upload_image_to_dropbox(file_path: &Path) -> Result<String, anyhow::Error> {
    dotenv().ok();
    let dropbox_path = format!(
        "/images/notion/{}",
        file_path.file_name().unwrap().to_str().unwrap()
    );
    let access_token = env::var("DROPBOX_ACCESS_TOKEN")?;

    let file_bytes = fs::read(file_path)?;

    let client = Client::new();

    let mut headers = HeaderMap::new();
    headers.insert(
        AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {}", access_token))?,
    );
    headers.insert(
        "Dropbox-API-Arg",
        HeaderValue::from_str(&format!(
            r#"{{"path": "{}","mode": "overwrite","autorename": false,"mute": false}}"#,
            dropbox_path
        ))?,
    );
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );

    let res = client
        .post("https://content.dropboxapi.com/2/files/upload")
        .headers(headers)
        .body(file_bytes)
        .send()?;

    if res.status().is_success() {
        let response = res.text()?;
        let json: serde_json::Value = serde_json::from_str(&response)?;
        let url = get_or_create_shared_link(&dropbox_path)?;
        println!("Uploaded {} to Dropbox URL: {}", dropbox_path, url);
        Ok(url)
    } else {
        panic!("Failed to upload image to Dropbox: {:?}", res.text()?);
    }
}

fn get_or_create_shared_link(path: &str) -> Result<String, anyhow::Error> {
    dotenv().ok();
    let token = env::var("DROPBOX_ACCESS_TOKEN")?;
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
    dotenv().ok();
    let notion_token = env::var("NOTION_TOKEN")?;
    let database_id = env::var("NOTION_DATABASE_ID")?;
    let client = Client::new();

    let tags_json = note
        .tags
        .iter()
        .map(|tag| json!({ "name": tag }))
        .collect::<Vec<_>>();

    let chunks = split_text(note.body, 1000);
    let rich_text_array: Vec<_> = chunks.iter().map(|chunk| {
        json!({
            "type": "text",
            "text": { "content": chunk }
        })
    }).collect();
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
    dotenv().ok();
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
        .post(format!("https://api.notion.com/v1/databases/{}/query", database_id))
        .header("Notion-Version", "2022-06-28")
        .header(AUTHORIZATION, format!("Bearer {}", notion_token))
        .header(CONTENT_TYPE, "application/json")
        .json(&json_request)
        .send()?;

    if res.status() != 200 {
        return Err(anyhow::anyhow!("Failed to query Notion database: {}", res.text()?));
    }

    let response: serde_json::Value = res.json()?;
    let results = response["results"].as_array().unwrap();
    
    Ok(!results.is_empty())
}

fn main() -> Result<()> {
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

    let mut index: u64 = 0;
    let mut skipped_count = 0;
    for html_file in html_files {
        index += 1;
        let title = extract_html_title(&html_file)?;
        
        // Check if note already exists in Notion
        if check_note_exists_in_notion(&title)? {
            pb.set_message(format!("Skipping existing note: {}", title));
            skipped_count += 1;
            pb.inc(1);
            continue;
        }

        let body = extract_html_body(&html_file)?;
        let tags = extract_html_tags(&html_file)?;
        let mut image_urls = vec![];
        let mut block_size: u64 = 0;

        // Update progress message to show current HTML file
        pb.set_message(format!("Processing HTML: {:?}", html_file.file_name().unwrap()));

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

        // send_note_to_notion(note)?;
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
