# VulnPublisherPro

A comprehensive Python CLI tool that automates vulnerability intelligence collection, AI-powered content generation, and multi-platform publishing for cybersecurity professionals.

## 🚀 Features

- **Multi-Source Data Collection**: Scrapes vulnerabilities from 13+ platforms including NVD, GitHub Security, HackerOne, Bugcrowd, CISA KEV, and more
- **AI-Powered Content Generation**: Uses OpenAI GPT models for intelligent vulnerability analysis and content creation
- **Autonomous Publishing**: Automatically publishes to 13+ social media and professional platforms
- **Interactive CLI**: Rich command-line interface with progress tracking and user-friendly menus
- **Blog Generation Engine**: Creates multi-perspective technical blogs with autonomous publishing
- **Expert Simulation**: AI-driven expert commentary and interview generation
- **Automated Scheduling**: Background task scheduling for continuous operation
- **Database Management**: PostgreSQL support with automated backup and cleanup

<<<<<<< refs/remotes/origin/master
### 🤖 AI Integration
- **Auto Categorizer** - ✅ Automatic vulnerability classification
- **Expert Simulator** - ✅ Expert interview generation
- **Content Generator** - ✅ AI-powered content creation
- **Blog Engine** - ✅ Professional blog post generation

## 🚀 SYSTEM CAPABILITIES
=======
## 🏗️ Architecture
>>>>>>> local

### Core Components

- **CLI Interface**: Interactive command-line tool built with Click, Rich, and Inquirer
- **Scraping Engine**: Modular scrapers for various vulnerability databases and platforms
- **AI Integration**: OpenAI-powered content generation and categorization
- **Publishing System**: Multi-platform publishers with rate limiting and error handling
- **Blog Engine**: Autonomous blog generation with multiple perspectives
- **Scheduler**: Background task management for automated operations

### Supported Data Sources

**Government & Standards:**
- National Vulnerability Database (NVD)
- CISA Known Exploited Vulnerabilities (KEV)
- MITRE CVE Database

**Bug Bounty Platforms:**
- HackerOne
- Bugcrowd
- Intigriti

**Security Databases:**
- GitHub Security Advisories
- CVE Details
- Exploit Database
- Rapid7
- VulnCheck
- VulnDB

**Community Sources:**
- Reddit Security Communities

### Publishing Platforms

**Social Media:**
- Twitter/X
- LinkedIn
- Facebook
- Instagram
- TikTok
- Mastodon

**Communication:**
- Discord
- Telegram
- Slack
- Microsoft Teams

**Publishing:**
- Medium
- Reddit
- YouTube

## 📦 Installation

### Prerequisites

- Python 3.11+
- PostgreSQL database
- OpenAI API key (for AI features)

### Quick Start

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd vulnpublisherpro
   ```

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up environment variables:**
   ```bash
   export DATABASE_URL="postgresql://user:password@host:port/database"
   export OPENAI_API_KEY="your-openai-api-key"
   ```

4. **Initialize the database:**
   ```bash
   python main.py setup
   ```

5. **Run the interactive CLI:**
   ```bash
   python main.py interactive
   ```

## 🎮 Usage

### Interactive Mode

Launch the interactive CLI to access all features through a user-friendly menu:

```bash
python main.py interactive
```

### Command Line Options

```bash
# Run specific scrapers
python main.py scrape --source nvd --limit 10

# Generate content for vulnerabilities
python main.py generate --type summary --vulnerability CVE-2024-12345

# Publish content to specific platforms
python main.py publish --platform twitter --content-id 123

# Start the scheduler for automated operations
python main.py schedule --interval daily

# Set up the database
python main.py setup

# View statistics and reports
python main.py stats
```

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `DATABASE_URL` | PostgreSQL connection string | Yes |
| `OPENAI_API_KEY` | OpenAI API key for AI features | Yes |
| `TWITTER_API_KEY` | Twitter API credentials | Optional |
| `LINKEDIN_ACCESS_TOKEN` | LinkedIn API token | Optional |
| `DISCORD_BOT_TOKEN` | Discord bot token | Optional |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token | Optional |

### Configuration File

Create a `config.json` file to customize settings:

```json
{
  "scraping": {
    "max_results": 100,
    "update_interval": 3600
  },
  "publishing": {
    "enabled_platforms": ["twitter", "linkedin", "discord"],
    "rate_limits": {
      "twitter": 15,
      "linkedin": 5
    }
  },
  "ai": {
    "model": "gpt-4",
    "max_tokens": 2000,
    "temperature": 0.7
  }
}
```

## 🔧 API Integration

### Required API Keys

To use all features, you'll need API keys from:

- **OpenAI**: For AI-powered content generation
- **Twitter/X**: For social media publishing
- **LinkedIn**: For professional network publishing
- **Discord**: For community publishing
- **Telegram**: For messaging platform publishing
- **And others** depending on your publishing needs

### Setting Up API Keys

1. Visit the respective platform's developer portal
2. Create an application and obtain API credentials
3. Add the credentials to your environment variables
4. The application will automatically detect and use available keys

## 📊 Features Deep Dive

### AI Content Generation

- **Multiple Content Types**: Summaries, detailed reports, alerts, and threaded content
- **Auto-categorization**: AI-driven vulnerability classification
- **Expert Simulation**: Simulated expert commentary and interviews
- **Platform Optimization**: Content automatically formatted for each platform

### Blog Generation

- **Multi-perspective Content**: Technical, business impact, and developer-focused views
- **Interactive Elements**: Code snippets, diagrams, step-by-step guides
- **Series Management**: Multi-part vulnerability analysis
- **Autonomous Publishing**: Automated blog publishing to multiple platforms

### Scheduling & Automation

- **Configurable Intervals**: Customize timing for different operations
- **Background Processing**: Continuous operation without user intervention
- **Error Handling**: Robust error recovery and retry mechanisms
- **Graceful Shutdown**: Signal handling for clean stops and restarts

## 🛠️ Development

### Project Structure

```
vulnpublisherpro/
├── main.py                 # Main CLI application
├── config.py              # Configuration management
├── database.py            # Database operations
├── content_generator.py   # Content generation logic
├── scheduler.py           # Task scheduling
├── utils.py               # Utility functions
├── scrapers/              # Vulnerability scrapers
├── publishers/            # Publishing modules
├── ai_integration/        # AI-powered features
├── blog_engine/           # Blog generation system
└── content/               # Generated content storage
```

### Adding New Scrapers

1. Create a new scraper class in `scrapers/`
2. Inherit from `BaseScraper`
3. Implement required methods
4. Add to the main scraper registry

### Adding New Publishers

1. Create a new publisher class in `publishers/`
2. Inherit from `BasePublisher`
3. Implement platform-specific publishing logic
4. Add to the main publisher registry

## 📈 Monitoring & Logging

- **Comprehensive Logging**: Detailed logs with rotation
- **Progress Tracking**: Real-time progress displays
- **Error Reporting**: Detailed error messages and stack traces
- **Statistics**: Built-in reporting and analytics

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support, please:
1. Check the documentation
2. Review existing issues
3. Create a new issue with detailed information
4. Contact the maintainers

## 🔮 Roadmap

- [ ] Additional vulnerability sources
- [ ] More publishing platforms
- [ ] Enhanced AI models
- [ ] Web dashboard interface
- [ ] Real-time notifications
- [ ] Advanced analytics
- [ ] Enterprise features

---

**VulnPublisherPro** - Automating cybersecurity intelligence for the modern world.