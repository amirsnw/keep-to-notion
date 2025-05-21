# Keep-to-Notion

Keep-to-Notion is a Rust application designed to convert HTML files into Markdown format and upload notes to Notion. It handles images through Dropbox integration and can optionally zip the output Markdown files.

## Features

- **HTML to Markdown Conversion**: Extracts content from HTML files and converts it into Markdown format.
- **Notion Integration**: Uploads notes to a specified Notion database.
- **Dropbox Integration**: Automatically uploads and manages images through Dropbox with OAuth2 authentication.
- **Image Handling**: Uploads images to Dropbox and creates shareable links for Notion.
- **Zipping**: Optionally zips the output Markdown files for easy distribution or storage.

## Requirements

- Rust and Cargo installed on your system.
- A Notion account with a database set up for receiving notes. 
- A Dropbox account for image hosting.
- Notion Integration created: https://www.notion.com/my-integrations
- Dropbox App created: https://www.dropbox.com/developers/apps
- Environment variables set up for authentication and configuration.

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/keep-to-notion.git
   cd keep-to-notion
   ```

2. Build the project:
   ```bash
   cargo build --release
   ```

## Configuration

### Environment Variables

Create a `.env` file in the project root with the following variables:

```env
# Notion Configuration
NOTION_TOKEN=your_notion_integration_token
NOTION_DATABASE_ID=your_notion_database_id

# Dropbox Configuration
DROPBOX_KEY=your_dropbox_app_key
DROPBOX_SECRET=your_dropbox_app_secret
```

### Dropbox Setup

1. Create a Dropbox App at https://www.dropbox.com/developers/apps
2. Set the OAuth2 redirect URI to `http://localhost:8080/callback`
3. Enable the following permissions:
   - files.content.write
   - files.content.read
   - sharing.write

## Usage

Run the application with the following command:

```bash
cargo run --release <source_dir>
```

- `<source_dir>`: The directory containing HTML files to be processed.

### First Run

On the first run, the application will:
1. Open your browser for Dropbox authorization
2. Handle the OAuth callback automatically
3. Store the access token for future use

### Subsequent Runs

The application will:
1. Use the stored Dropbox token if valid
2. Automatically refresh the token if expired
3. Process HTML files and upload images to Dropbox
4. Create Notion pages with Dropbox image links

## Features in Detail

### Dropbox Integration
- Automatic OAuth2 authentication flow
- Token management with automatic refresh
- Image upload with public sharing links
- Secure token storage

### Notion Integration
- Direct upload to specified database
- Support for rich text content
- Image embedding via Dropbox links
- Tag support for organization

### Image Processing
- Automatic image detection in HTML
- Upload to Dropbox with unique paths
- Creation of public sharing links
- Integration with Notion content