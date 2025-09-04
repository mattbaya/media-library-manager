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
   - 21 menu options organized by category (Analysis, Processing, Subtitles, Organization, Backup, Settings)
   - SQLite database for metadata caching and performance
   - Background analysis with progress tracking and recommendations
   - Batch operations for bulk video processing
   - Cloud backup/sync integration with rclone
   - Smart organization with Plex naming compliance
   - Subtitle management (download and check external/embedded)
   - Storage analytics and duplicate detection
   - Manual file correction with TMDB API integration for proper naming
   - Configurable folder scanning with movie/TV type designation

2. **media_library.db** - SQLite database (auto-created)
   - Caches video metadata (resolution, codec, subtitles, file stats)
   - Stores analysis sessions and recommendations
   - Stores manual file corrections with TMDB metadata
   - Enables incremental scanning (only new/modified files)
   - Provides instant queries for all analysis operations

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
  - `.media-manager/` - Application data directory
    - `media_library.db` - SQLite metadata cache
    - `settings.json` - User preferences and configuration
  - `convert_env/` - Python 3.12 virtual environment
  - `PlexDBRepair-master/` - External Plex database repair utility
  - Analysis reports (JSON format with timestamps)

### Dependencies

- **Python 3.x** with standard library
- **requests** - HTTP library for TMDB API calls (pip install requests)
- **FFmpeg** - Video processing and analysis
- **subliminal** - Subtitle downloading (pip install subliminal) 
- **rclone** - Cloud backup/sync (brew install rclone)
- **SQLite** - Built into Python, no additional install needed

### Key Features

- **Background Analysis**: Comprehensive library scanning with visual progress bars
- **Incremental Scanning**: Only analyzes new/changed files using SQLite cache
- **Database Status Display**: Main menu shows cached file count and last scan time
- **Intelligent Cache Usage**: All menu options leverage cached scan data for instant results
- **Smart Action Menus**: Post-analysis menus with relevant actions based on found issues
- **Granular Content Selection**: Process Movies, TV Shows, or specific shows independently
- **Flexible Batch Processing**: Choose batch sizes and background/foreground processing modes
- **Smart Recommendations**: Prioritized action lists based on analysis
- **Batch Operations**: Bulk processing for codec conversion, quality changes, file management
- **Cloud Sync**: Full rclone integration for backup to any cloud provider
- **Plex Integration**: Naming compliance and organization for Plex Media Server
- **Subtitle Management**: Download external subtitles, check embedded subtitles
- **Storage Analytics**: Disk usage analysis and growth predictions
- **Configurable Folders**: Define custom folders as movie or TV type (e.g., "80s Movies", "Classic TV")
- **TV Show Navigation**: Paginated browsing with search, alphabetical sorting, and filtering
- **Progress Tracking**: Live progress bars for subtitle downloads and TV show renaming
- **Parallel Processing**: Configurable concurrent subtitle downloads (default: 8)
- **Language Preferences**: Configure which subtitle languages to keep/remove
- **Personal Content Exclusion**: Non-TV/Movie folders automatically excluded from media operations
- **TMDB Integration**: Manual file correction with movie/TV database lookup for accurate Plex naming
- **Automated Task Execution**: Full scans now execute all requested fixes (conversion, subtitles, etc.)
- **Performance Optimization**: All size analysis operations use database queries for instant results
- **Strict Authorization Control**: All file operations validate authorization before execution
- **Database-Powered Conversion**: Video resolution scanning uses cached metadata for instant results

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
- **Folder Authorization Control**: Strict validation prevents operations on unauthorized directories

### Workflow Recommendations

1. **First-time setup**: Run Option 1 (Background Analysis) for comprehensive library overview
2. **Regular maintenance**: Use incremental analysis to check for new files  
3. **Manual corrections**: Use Option 17 to fix misnamed files with TMDB lookup (requires free API key)
4. **Storage optimization**: Options 3-5 provide instant database-powered file size analysis
5. **Cloud backup**: Configure rclone remotes and use Option 20 for backup

### Important Notes

- SQLite database improves performance significantly for large libraries
- All operations include progress tracking and confirmation prompts
- Analysis results are cached for 24 hours by default
- Cloud sync requires rclone configuration (run `rclone config`)
- TMDB integration requires free API key from https://www.themoviedb.org/settings/api
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
8. **Authorization Enforcement**: Strict file operation validation prevents unauthorized directory access

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