use anyhow::{Context, Result};
use dotenv::dotenv;
use reqwest::blocking::Client;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use scraper::{Html, Selector};
use serde_json::json;
use std::env;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::{fs, vec};
use walkdir::WalkDir;
use zip;

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

fn export_to_markdown(note: Note, output_dir: &Path, index: u64) -> Result<(), anyhow::Error> {
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
        copy_image(image_path, output_dir)?;
        let image_name = image_path.file_name().unwrap_or_default().to_string_lossy();
        writeln!(file, "![]({})", image_name)?;
        writeln!(file, "")?;
    }

    writeln!(file, "\n{}", note.body)?;
    Ok(())
}

fn copy_image(image_path: &Path, target_folder: &Path) -> Result<(), anyhow::Error> {
    let file_name = image_path.file_name().unwrap();
    let destination = target_folder.join(file_name);

    fs::copy(image_path, &destination)
        .with_context(|| format!("Failed to copy image to {:?}", destination))?;
    Ok(())
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

    let children_json = vec![json!([
        {
            "object": "block",
            "type": "paragraph",
            "paragraph": {
                "rich_text": [{
                    "type": "text",
                    "text": { "content": note.body }
                }]
            }
        }
    ])]
    .into_iter()
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
    .collect::<Vec<serde_json::Value>>();
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

    println!("----------- Uploaded to Notion -----------");
    println!(
        "JSON request: {}",
        serde_json::to_string_pretty(json_request).unwrap()
    );
    println!("Sent note: {} | Status: {}", note.title, res.status());
    println!("----------------------------------------");

    Ok(())
}

pub struct Note<'a> {
    pub title: &'a str,
    pub body: &'a str, // you can use HTML or convert to plain Markdown
    pub tags: &'a Vec<String>,
    pub image_paths: &'a Vec<String>, // relative or absolute paths
}

fn zip_and_cleanup(target_dir: &Path) -> Result<(), anyhow::Error> {
    let zip_path = target_dir.join("markdown.zip");
    let file = File::create(&zip_path)?;
    let mut zip = zip::ZipWriter::new(file);
    let options = zip::write::FileOptions::default().compression_method(zip::CompressionMethod::Deflated);

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

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() != 3 {
        eprintln!("Usage: {} <source_dir> <output_dir>", args[0]);
        std::process::exit(1);
    }

    let source_dir = Path::new(&args[1]);
    let output_dir = Path::new(&args[2]);

    let mut html_files = find_html_files(source_dir);
    html_files.sort(); // optional, for predictable order

    let mut index: u64 = 0;
    for html_file in html_files {
        index += 1;
        let title = extract_html_title(&html_file)?;
        let body = extract_html_body(&html_file)?;
        let tags = extract_html_tags(&html_file)?;
        let mut images = vec![];
        let mut block_size: u64 = 0;

        let img_srcs = extract_img_srcs(&html_file)?;
        for img_src in img_srcs {
            let filename = Path::new(&img_src).file_name().unwrap().to_str().unwrap();
            if let Some(found_image_path) = find_image_in_dir(source_dir, filename) {
                // Add the size of image file to block_size
                let size = fs::metadata(&found_image_path)?.len();
                block_size += size;

                // Add found_image_path to vector
                images.push(found_image_path);
            } else {
                println!("Image not found for: {}", filename);
            }
        }

        // Add the size of html file to block_size
        let html_size = fs::metadata(&html_file)?.len();
        block_size += html_size;

        let image_urls: Vec<String> = images
            .into_iter()
            .map(|path| path.to_str().unwrap().to_string())
            .collect();

        let note = Note {
            title: &title,
            body: &body,
            tags: &tags,
            image_paths: &image_urls,
        };
        
        // send_note_to_notion(note)?;
        export_to_markdown(note, output_dir, index)?;

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

        if index == 20 {
            print!("break");
            break;
        }
    }

    zip_and_cleanup(output_dir)?;

    println!("✅ All HTML files processed.");
    Ok(())
}
