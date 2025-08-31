# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Common Commands

### Media Manager (Primary Tool)
```bash
# Run the comprehensive media library manager
python media_manager.py

# Quick utilities for specific tasks
python quick_scan.py        # Fast scan for common issues
python quick_fixes.py       # Automated cleanup
python targeted_cleanup.py  # Directory-specific cleanup
```

### Legacy Video Conversion
```bash
# Run standalone conversion scripts (deprecated - use media_manager.py instead)
python convert.py
python scan_and_convert.py
```

### Media Library Maintenance
```bash
# Clean up old talk show recordings (runs on TV directory)
./TV/trim-nightly-talk-shows.sh

# Mount network media drive
./mountsmb.sh
```

## Architecture Overview

This is a comprehensive media library management system with a primary Python application and utility scripts for video processing, organization, and maintenance. The system uses SQLite for caching and performance optimization.

### Key Components

1. **media_manager.py** - Comprehensive media library management application
   - 18 menu options organized by category (Analysis, Processing, Subtitles, Organization, Backup)
   - SQLite database for metadata caching and performance
   - Background analysis with progress tracking and recommendations
   - Batch operations for bulk video processing
   - Cloud backup/sync integration with rclone
   - Smart organization with Plex naming compliance
   - Subtitle management (download and check external/embedded)
   - Storage analytics and duplicate detection

2. **media_library.db** - SQLite database (auto-created)
   - Caches video metadata (resolution, codec, subtitles, file stats)
   - Stores analysis sessions and recommendations
   - Enables incremental scanning (only new/modified files)
   - Provides fast queries for complex analysis

3. **convert.py** - Legacy standalone video conversion utility
   - Converts videos >2GB or >1080p resolution to 1080p MP4
   - Uses FFmpeg with H.264/AAC encoding
   - Renames originals with "-CONVERTED" suffix

4. **Quick utilities**:
   - **quick_scan.py** - Fast overview scan without deep analysis
   - **quick_fixes.py** - Automated system file cleanup and naming fixes
   - **targeted_cleanup.py** - Directory-specific cleanup operations
   - **scan_and_convert.py** - Batch conversion for >1080p videos

5. **mountsmb.sh** - Network drive mounting script
   - Mounts SMB share at /Volumes/media
   - **Security Note**: Contains hardcoded credentials

6. **TV/trim-nightly-talk-shows.sh** - Automated cleanup
   - Deletes talk show recordings older than 7 days

### Directory Structure

- `/Volumes/media/Video/` - Root media library
  - `Movies/`, `TV/`, `Kids Movies/`, `Christmas/`, `Music Videos/`, `Personal/`, `HalloweenFX/`, `Misc/` - Content directories
  - `convert_env/` - Python 3.12 virtual environment
  - `PlexDBRepair-master/` - External Plex database repair utility
  - `media_library.db` - SQLite metadata cache
  - Analysis reports (JSON format with timestamps)

### Dependencies

- **Python 3.x** with standard library
- **FFmpeg** - Video processing and analysis
- **subliminal** - Subtitle downloading (pip install subliminal)
- **rclone** - Cloud backup/sync (brew install rclone)
- **SQLite** - Built into Python, no additional install needed

### Key Features

- **Background Analysis**: Comprehensive library scanning with visual progress bars
- **Incremental Scanning**: Only analyzes new/changed files using SQLite cache
- **Database Status Display**: Main menu shows cached file count and last scan time
- **Smart Recommendations**: Prioritized action lists based on analysis
- **Batch Operations**: Bulk processing for codec conversion, quality changes, file management
- **Cloud Sync**: Full rclone integration for backup to any cloud provider
- **Plex Integration**: Naming compliance and organization for Plex Media Server
- **Subtitle Management**: Download external subtitles, check embedded subtitles
- **Storage Analytics**: Disk usage analysis and growth predictions

### Security Features

- **Enterprise-Grade Security**: Comprehensive protection against common vulnerability classes
- **Input Validation**: Strict validation of all user input with sanitization
- **Command Injection Prevention**: Parameterized commands with rclone remote validation
- **SQL Injection Prevention**: Parameterized queries throughout database operations
- **Path Traversal Protection**: Comprehensive path validation and sanitization
- **Rate Limiting**: External command execution limits to prevent DoS attacks
- **Symlink Attack Prevention**: TOCTOU protection with atomic file operations
- **Information Disclosure Prevention**: Path and error message sanitization
- **Cryptographic Security**: Secure random number generation for timing operations
- **Performance Limits**: DoS protection with file count and directory depth limits

### Workflow Recommendations

1. **First-time setup**: Run Option 1 (Background Analysis) for comprehensive library overview
2. **Regular maintenance**: Use incremental analysis to check for new files
3. **Storage optimization**: Follow high-priority recommendations from analysis
4. **Cloud backup**: Configure rclone remotes and use Option 18 for backup

### Important Notes

- SQLite database improves performance significantly for large libraries
- All operations include progress tracking and confirmation prompts
- Analysis results are cached for 24 hours by default
- Cloud sync requires rclone configuration (run `rclone config`)
- FFmpeg must be installed and available in PATH

### Security Architecture

The application implements multiple layers of security protection:

1. **ExternalCommandManager**: Rate-limited subprocess execution (max 3 concurrent, 100ms intervals)
2. **PerformanceLimits**: DoS protection (100K files max, 20 depth levels, 10K directories)
3. **Input Sanitization**: All user input validated with strict alphanumeric checks
4. **Path Security**: Comprehensive validation, symlink blocking, and traversal prevention
5. **Database Security**: Parameterized queries, secure file permissions (0600)
6. **Error Sanitization**: All error messages scrubbed of sensitive system information
7. **Audit Logging**: Security events logged for monitoring and compliance

### Security Compliance

- **No shell=True usage**: All subprocess calls use argument arrays
- **No hardcoded credentials**: Environment-based authentication only
- **Cryptographically secure random**: Uses secrets module for all random operations
- **OWASP compliance**: Protected against Top 10 vulnerabilities
- **Enterprise security**: Suitable for production environments

### Security Testing

The application has undergone comprehensive security testing including:
- Command injection testing with malicious payloads
- SQL injection testing with database operations
- Path traversal testing with directory operations
- DoS testing with resource exhaustion attempts
- Input validation testing with edge cases
- Symlink attack testing with TOCTOU scenarios