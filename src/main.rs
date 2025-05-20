fn upload_image_to_dropbox(file_path: &Path) -> Result<String, Box<dyn std::error::Error>> {
    dotenv().ok();
    let dropbox_path = format!("/images/notion/{}", file_path.file_name().unwrap().to_str().unwrap());
    let access_token = env::var("ACCESS_TOKEN")?;

    let file_bytes = fs::read(file_path)?;

    let client = Client::new();

    let mut headers = HeaderMap::new();
    headers.insert(AUTHORIZATION, HeaderValue::from_str(&format!("Bearer {}", access_token))?);
    headers.insert("Dropbox-API-Arg", HeaderValue::from_str(&format!(
        r#"{{"path": "{}","mode": "add","autorename": true,"mute": false}}"#,
        dropbox_path
    ))?);
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));

    let res = client
        .post("https://content.dropboxapi.com/2/files/upload")
        .headers(headers)
        .body(file_bytes)
        .send()?;

    if res.status().is_success() {
        println!("Uploaded {} to Dropbox!", dropbox_path);
        let response = res.text()?;
        let json: serde_json::Value = serde_json::from_str(&response)?;
        Ok(json["path_display"].as_str().unwrap().to_string())
    } else {
        let error_text = res.text()?;
        Err(format!("Failed to upload to Dropbox: {}", error_text).into())
    }
} 