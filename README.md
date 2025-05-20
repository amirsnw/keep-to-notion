# Keep-to-Notion

Keep-to-Notion is a Rust application designed to convert HTML files into Markdown format and upload notes to Notion. It handles images and can optionally zip the output Markdown files.

## Features

- **HTML to Markdown Conversion**: Extracts content from HTML files and converts it into Markdown format.
- **Notion Integration**: Uploads notes to a specified Notion database.
- **Image Handling**: Copies images referenced in HTML files and includes them in the Markdown output.
- **Zipping**: Optionally zips the output Markdown files for easy distribution or storage.

## Requirements

- Rust and Cargo installed on your system.
- A Notion account with a database set up for receiving notes. 
- Notion Integration created: https://www.notion.com/my-integrations
- Environment variables `NOTION_TOKEN` and `NOTION_DATABASE_ID` set up for authentication and database identification.

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

## Usage

Run the application with the following command:

```bash
cargo run --release <source_dir> <output_dir>
```

- `<source_dir>`: The directory containing HTML files to be processed.
- `<output_dir>`: The directory where the Markdown files will be saved.

## Environment Variables

Ensure the following environment variables are set:

- `NOTION_TOKEN`: Your Notion integration token.
- `NOTION_DATABASE_ID`: The ID of the Notion database where notes will be uploaded.