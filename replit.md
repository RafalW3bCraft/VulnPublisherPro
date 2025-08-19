# GitHub Repository Manager

## Project Overview
A comprehensive Python CLI tool for GitHub repository management and user automation. Provides bulk operations for repository visibility management, user follow/unfollow automation, and advanced features like promotion engines and ban list management.

## Project Architecture

### Core Components
- **Main Entry Point**: `github_automation.py` - Primary CLI interface
- **Core Modules**:
  - `core/github_api.py` - GitHub API integration
  - `core/file_manager.py` - File operations management
  - `core/logger.py` - Logging functionality
  - `core/validators.py` - Input validation
  - `core/ban_manager.py` - User ban list management
  - `core/promotion_engine.py` - User promotion and targeting
  - `core/config_manager.py` - Configuration management
- **Strategic Automation**:
  - `core/database.py` - PostgreSQL database with user tracking
  - `core/strategic_automation.py` - Intelligent follow/unfollow automation
  - `core/scheduler.py` - Background task scheduling
  - `core/automation_manager.py` - Master automation controller
  - `core/rate_limiter.py` - GitHub API rate limiting compliance
- **CLI Interface**:
  - `cli/commands.py` - Command implementations with strategic automation
  - `cli/interactive.py` - Interactive mode interface
- **Deployment**:
  - `deploy/render_deployment.py` - Production deployment for Render.com
  - `deploy/render.yaml` - Render service configuration
  - `deploy/requirements.txt` - Production dependencies

### Key Features
- Repository visibility management (bulk private/public operations)
- User automation (follow/unfollow with targeting)
- Interactive repository selection
- Ban list and whitelist management
- Promotion engine for targeted engagement
- Comprehensive logging and debugging tools
- **Strategic Follower Growth Automation**:
  - PostgreSQL database for enterprise tracking
  - Intelligent user targeting with activity analysis
  - 15-day/90-day waiting periods based on user value
  - Moon symbol retry tracking and automatic blacklisting
  - Background scheduling with configurable intervals
  - Real-time followback detection and confirmation
  - Rate-limited API compliance for safe automation
  - Production deployment on Render.com with web dashboard

## Project Information
- **Name**: GitHub Repository Manager
- **Author**: RafalW3bCraft (thewhitefalcon13@proton.me)
- **License**: MIT License
- **Version**: 1.0.0
- **Python Version**: 3.11+
- **Dependencies**: colorama, cryptography, requests, tqdm

## Recent Changes

### 2025-08-19: Strategic Automation Implementation
- ✓ Implemented comprehensive PostgreSQL database for enterprise-grade user tracking
- ✓ Created strategic automation engine with intelligent follow/unfollow cycles
- ✓ Added 15-day standard waiting period and 90-day waiting for high-value users (>179 stars)
- ✓ Implemented moon symbol tracking for retry attempts and automatic blacklisting
- ✓ Built advanced scheduling system with background automation
- ✓ Added Render.com deployment configuration for production automation
- ✓ Created rate limiter for GitHub API compliance
- ✓ Developed comprehensive automation manager with status reporting
- ✓ Added export/import and data cleanup functionality

### 2025-08-19: Project Name Standardization
- ✓ Updated project name from "gitMaster-init" to "GitHub Repository Manager" across all files
- ✓ Updated pyproject.toml with new project name
- ✓ Updated CLI help text and command descriptions
- ✓ Updated README.md with comprehensive documentation
- ✓ Updated header displays in commands.py
- ✓ Updated main script docstring and descriptions

## User Preferences
- Project should maintain consistent naming as "GitHub Repository Manager"
- Prefer comprehensive documentation and clear project structure
- Focus on GitHub repository and user management functionality

## Technical Notes
- Uses argparse for CLI interface with subcommands
- Implements modular architecture with separation of concerns
- Colorama for cross-platform colored terminal output
- Request-based GitHub API integration
- File-based configuration and data management