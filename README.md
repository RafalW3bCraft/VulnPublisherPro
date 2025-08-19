# 🚀 GitHub Repository Manager

**Advanced GitHub Repository Management with 100% Reliable Follower Growth Automation**

A comprehensive command-line tool and production-ready system for managing GitHub repositories with sophisticated automation capabilities, featuring continuous follower growth cycles, strategic targeting, and intelligent blacklisting systems.

## Overview

GitHub Repository Manager is a production-grade automation system that provides:
- **100% Reliable Follower Growth**: Continuous Follow → Wait → Unfollow → Repeat cycles
- **Strategic Targeting**: Activity-based user discovery with star thresholds
- **Moon-Symbol Tracking**: Progressive blacklisting system (🌙 🌙 🌙)
- **Intelligent Unfollow Logic**: 15 days standard, 90 days for users with ≥179 stars
- **Production Deployment**: Ready for Render with background workers and monitoring
- **Comprehensive Repository Management**: Bulk operations and advanced diagnostics

## Features

### 🎯 100% Reliable Automation Engine
- **Continuous Cycling**: Never-stop automation with Follow → Wait → Unfollow → Repeat
- **Strategic Targeting**: Discover active users based on recent GitHub activity
- **High-Value Detection**: Identify users with ≥179 stars for extended 90-day wait periods
- **Smart Rate Limiting**: Automatic rate limit detection and recovery
- **Comprehensive Tracking**: Every action logged with timestamps and reliability scores

### 🌙 Advanced Moon-Symbol System
- **Progressive Blacklisting**: 🌙 → 🌙🌙 → 🌙🌙🌙 → **PERMANENT BLACKLIST**
- **Intelligent Retry Logic**: Multiple attempts before permanent blacklisting
- **Damaged.txt Management**: Comprehensive blacklist file with timestamps
- **Strategic Unfollow Timing**: 15 days standard, 90 days for valuable users
- **Automatic Cleanup**: Scheduled maintenance of blacklists and tracking

### 🏭 Production-Ready Deployment
- **Render Integration**: Complete deployment configuration with render.yaml
- **Background Workers**: Continuous automation with web dashboard monitoring
- **PostgreSQL Database**: Comprehensive data storage with automatic migrations
- **Health Monitoring**: Real-time system health checks every 30 minutes
- **Auto-Recovery**: Intelligent error handling and recovery mechanisms

### 📊 Performance & Analytics
- **Reliability Scoring**: Real-time automation success rate tracking
- **Comprehensive Statistics**: Daily and weekly performance reports
- **Growth Metrics**: Target 150+ followers per month with 20-40% follow-back rate
- **Performance Monitoring**: Track automation cycles and success rates
- **Resource Optimization**: Efficient memory and CPU usage patterns

### 🔧 Repository Management
- **Repository Visibility Management**: Bulk operations to make repositories private or public
- **Interactive Repository Selection**: Choose specific repositories through an intuitive interface
- **Repository Filtering**: Filter repositories by visibility status (public/private)
- **Repository Toggle**: Toggle visibility of individual or multiple repositories
- **Repository Backup**: Create backups of repository configurations

### 🛡️ Security & Protection
- **Comprehensive Ban Lists**: Multi-level blacklisting with moon-symbol tracking
- **Whitelist Protection**: Protect important users from automation
- **Token Security**: Secure GitHub token handling and rotation recommendations
- **Rate Limit Compliance**: Automatic GitHub API rate limit management
- **Audit Trail**: Complete logging of all automation actions

## Requirements

### For Local Development
- Python 3.11 or higher
- GitHub Personal Access Token with full permissions
- Internet connection for GitHub API access

### For Production Deployment (Render)
- Render account for hosting
- GitHub repository with this codebase
- PostgreSQL database (automatically provisioned)
- Environment variables configuration

## Installation

### Local Installation
1. Clone or download the repository
2. Install dependencies:
   ```bash
   pip install colorama cryptography flask psycopg2-binary requests schedule tqdm
   ```
3. Set up your GitHub token as an environment variable:
   ```bash
   export GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
   ```

### Production Deployment (Render)
1. **Fork this repository** to your GitHub account
2. **Create Render account** at [render.com](https://render.com)
3. **Connect repository** and import the included `render.yaml`
4. **Set environment variables** in Render dashboard:
   - `GITHUB_TOKEN`: Your GitHub Personal Access Token (required)
   - `GITHUB_USERNAME`: Your GitHub username (optional - auto-detected)
   - `AUTOMATION_CYCLE_INTERVAL`: Hours between cycles (default: 3)
   - `MAX_DAILY_FOLLOWS`: Daily follow limit (default: 75)
   - `MAX_MOON_SYMBOLS`: Moon limit before blacklisting (default: 3)
5. **Deploy**: Render will automatically create web service + background worker

## Usage

### Basic Repository Management

```bash
# Interactive repository selection
python github_automation.py repo-manager

# Bulk make repositories private
python github_automation.py repo-manager --make-private

# Bulk make repositories public
python github_automation.py repo-manager --make-public

# Filter and show only public repositories
python github_automation.py repo-manager --filter public

# Toggle repository visibility
python github_automation.py repo-manager --toggle-visibility
```

### 🎯 Strategic Automation

```bash
# Start 100% reliable continuous automation
python github_automation.py repo-manager --strategic-automation

# Strategic follow with targeting
python github_automation.py repo-manager --auto-follow octocat --limit 50

# Unfollow non-followers with moon tracking
python github_automation.py repo-manager --unfollow-nonfollowers --whitelist data/whitelist.txt

# Comprehensive automation statistics
python github_automation.py repo-manager --stats --stats-username octocat

# Interactive mode for guided operations
python github_automation.py repo-manager --interactive

# Health monitoring and status
python github_automation.py repo-manager --health-check
```

### Advanced Features

```bash
# Promotion targeting specific users
python github_automation.py repo-manager --promotion --promotion-target octocat --promotion-limit 50

# Auto-sync with custom interval
python github_automation.py repo-manager --auto-sync --check-interval 3600

# Ban list management
python github_automation.py repo-manager --ban-list-add username1,username2
python github_automation.py repo-manager --ban-list-remove username1

# Create repository backup
python github_automation.py repo-manager --backup-create
```

### Debug and Diagnostics

```bash
# Debug repository access and permissions
python github_automation.py repo-manager --debug

# Enable verbose logging
python github_automation.py repo-manager --verbose

# Skip confirmation prompts
python github_automation.py repo-manager --no-confirm
```

## Configuration

### Environment Variables
- `GITHUB_TOKEN`: GitHub Personal Access Token (required)
- `GITHUB_USERNAME`: GitHub username (optional - auto-detected)
- `DATABASE_URL`: PostgreSQL connection string (auto-set by Render)
- `AUTOMATION_CYCLE_INTERVAL`: Hours between automation cycles (default: 3)
- `MAX_DAILY_FOLLOWS`: Maximum follows per day (default: 75)
- `MAX_MOON_SYMBOLS`: Moon symbols before blacklisting (default: 3)
- `ENABLE_AUTO_RECOVERY`: Enable automatic error recovery (default: true)

### File-Based Configuration
- `data/whitelist.txt`: Users protected from automation
- `data/damaged.txt`: Blacklisted users with moon symbols and timestamps
- `data/scheduler_config.json`: Automation schedule settings
- `data/daily_reports/`: Daily performance reports
- `data/weekly_reports/`: Weekly analysis and optimization suggestions

### Strategic Automation Settings
- **Follow Limits**: 75 follows/day, 100 unfollows/day capacity
- **Wait Periods**: 15 days standard, 90 days for users with ≥179 stars
- **Moon System**: 🌙 → 🌙🌙 → 🌙🌙🌙 → Permanent blacklist
- **Target Growth**: 150+ followers per month
- **Success Rate**: 20-40% follow-back rate expected

## Security Features

### API Security
- **Token Validation**: Automatic GitHub token validation and permission checking
- **Secure Storage**: Environment variable-based token storage (never in code)
- **Token Rotation**: 90-day rotation recommendations with monitoring
- **Permission Verification**: Automatic API permission validation

### Rate Limit Management
- **Smart Throttling**: Automatic rate limit detection and recovery
- **Exponential Backoff**: Gradual retry intervals on API failures
- **Request Spacing**: 2-5 second delays between API calls
- **Burst Protection**: Prevents accidental API abuse

### User Protection Systems
- **Multi-Level Blacklisting**: Comprehensive damaged user tracking
- **Whitelist Protection**: Protect important users from automation
- **Moon-Symbol Tracking**: Progressive punishment system
- **Audit Trail**: Complete logging of all user interactions

## Error Handling & Recovery

### Automatic Recovery
- **Intelligent Recovery**: Automatic recovery from API errors and rate limits
- **Health Monitoring**: Continuous system health checks every 30 minutes
- **Exponential Backoff**: Smart retry strategies for different error types
- **Session Persistence**: Maintains automation state across restarts

### Comprehensive Logging
- **Structured Logging**: JSON-formatted logs with timestamps and context
- **Reliability Scoring**: Real-time success rate tracking and reporting
- **Performance Metrics**: Detailed performance and timing information
- **Error Classification**: Categorized error types with specific recovery actions

### Production Monitoring
- **Real-Time Dashboards**: Web interface for monitoring automation status
- **Alert Systems**: Automated alerts for system degradation or failures
- **Performance Reports**: Daily and weekly performance analysis
- **Resource Monitoring**: Memory, CPU, and database usage tracking

## 🚀 Production Deployment

The system is designed for production deployment on **Render** with:

### Architecture
- **Web Service**: Monitoring dashboard and manual controls (Port 5000)
- **Background Worker**: 24/7 automation engine with health monitoring
- **PostgreSQL Database**: Comprehensive data storage with automatic backups
- **Auto-Scaling**: Render's automatic scaling based on usage

### Performance Expectations
- **Monthly Growth**: 150+ new followers with systematic targeting
- **System Reliability**: 95%+ uptime with automatic recovery
- **Resource Usage**: ~100MB memory per service, minimal CPU usage
- **Follow Success Rate**: 20-40% industry-standard follow-back rate

### Monitoring & Analytics
- **Real-Time Status**: Live automation status and performance metrics
- **Health Dashboards**: System health monitoring with alerts
- **Growth Analytics**: Comprehensive follower growth tracking
- **Performance Reports**: Daily/weekly analysis and optimization

## Project Information

- **Author**: RafalW3bCraft
- **Email**: thewhitefalcon13@proton.me
- **License**: MIT License
- **Version**: 2.0.0 - Enhanced with 100% Reliable Automation
- **GitHub**: RafalW3bCraft/GitHub-Repository-Manager
- **Deployment Guide**: See `deploy/DEPLOYMENT_GUIDE.md` for complete setup instructions

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, bug reports, or feature requests, please open an issue on the GitHub repository.