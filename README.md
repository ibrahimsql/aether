# AetherXSS Scanner

Advanced Cross-Site Scripting Scanner with Docker Integration

## Features

- 🔍 Advanced XSS payload detection
- 🎯 Multiple scanning methods (GET, POST, Headers)
- 🕷️ Web crawling capability
- 🎨 Beautiful animated UI
- 🐳 Docker support
- 📊 Detailed HTML reports
- 🚀 Multi-threading support
- 🔒 Custom payload support
- 🌐 Proxy support
- 📝 Verbose logging

## Quick Start with Docker

```bash
# Build and run with docker-compose
docker-compose up --build

# Or run directly with docker
docker build -t aetherxss .
docker run -v $(pwd)/reports:/app/reports aetherxss --url https://target.com
```

## Installation without Docker

```bash
# Install .NET 7.0 SDK
dotnet restore
dotnet build
dotnet run -- --url https://target.com
```

## Usage

```bash
AetherXSS --url <target_url> [options]

Options:
  --url <url>              Target URL to scan (required)
  --no-color               Disable colored output
  --proxy <proxy_url>      Use proxy for requests
  --cookie <cookie_data>   Use custom cookies
  --headers <h1:v1,...>    Use custom HTTP headers
  --threads <num>          Number of concurrent threads (default: 5)
  --delay <ms>            Delay between requests in milliseconds
  --timeout <sec>         Request timeout in seconds (default: 30)
  --output <file>         Save results to file
  --verbose               Show detailed output
  --crawl                 Enable web crawling
  --depth <num>           Crawling depth (default: 2)
```

## Directory Structure

```
.
├── AetherXSS.cs          # Main scanner code
├── AetherXSS.csproj      # Project file
├── Dockerfile            # Docker configuration
├── docker-compose.yml    # Docker Compose configuration
├── reports/              # Scan reports directory
├── wordlists/            # Custom wordlists directory
└── custom_payloads/      # Custom XSS payloads directory
```

## Required Dependencies

- .NET 7.0 SDK
- Newtonsoft.Json
- HtmlAgilityPack
- Selenium.WebDriver
- Microsoft.Playwright
- Serilog
- Spectre.Console

## Security Notes

- Always get permission before scanning any website
- Use with caution on production systems
- Consider using proxy for anonymity
- Review and customize payloads before use

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Author

- [@ibrahimsql](https://github.com/ibrahimsql)
- Email: ibrahimsql@proton.me 
