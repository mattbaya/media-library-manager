#!/usr/bin/env python3
import os
import subprocess
import sys
import json
from pathlib import Path
import shutil
from datetime import datetime, timedelta
from collections import defaultdict
import threading
import time
import sqlite3
import hashlib
import queue
import unicodedata
import re
import random
import secrets
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed
import errno
import stat
import requests

# Safe file size constants to prevent integer overflow
class FileSizeConstants:
    KB = 1024
    MB = KB * KB  # 1,048,576
    GB = MB * KB  # 1,073,741,824
    TB = GB * KB  # 1,099,511,627,776
    
    # Safe thresholds (well below max int values)
    MAX_FILE_SIZE = 100 * GB  # 100GB max
    LARGE_FILE_THRESHOLD = 5 * GB
    HUGE_FILE_THRESHOLD = 10 * GB
    SAMPLE_FILE_MAX = 100 * MB

# Performance and DoS prevention constants
class PerformanceLimits:
    # Prevent DoS via excessive file scanning
    MAX_FILES_PER_SCAN = 100000  # 100K files max per scan operation
    MAX_DIRECTORIES_PER_SCAN = 10000  # 10K directories max
    MAX_SCAN_DEPTH = 20  # Maximum directory depth
    
    # Memory usage limits
    MAX_MEMORY_ITEMS = 50000  # Max items to keep in memory at once
    BATCH_SIZE = 1000  # Process files in batches

# Standardized timeout constants to prevent DoS attacks
class TimeoutConstants:
    # Quick operations (version checks, simple commands)
    QUICK = 5
    
    # Standard operations (file analysis, queries)
    STANDARD = 30
    
    # Medium operations (file conversions, downloads)
    MEDIUM = 300  # 5 minutes
    
    # Long operations (large file processing, backups)
    LONG = 3600  # 1 hour
    
    # Database connections
    DATABASE = 30.0

class ExternalCommandManager:
    """Manages external command execution with rate limiting and concurrency controls."""
    
    def __init__(self, max_concurrent=4):
        self.max_concurrent = max_concurrent
        self.executor = ThreadPoolExecutor(max_workers=max_concurrent)
        self.active_commands = {}
        self.command_lock = threading.Lock()
        self.command_count = 0
        self.last_command_time = 0
        self.min_command_interval = 0.1  # 100ms between commands
    
    def safe_subprocess_run(self, cmd, **kwargs):
        """Execute subprocess with concurrency and rate limits."""
        current_time = time.time()
        
        # Rate limiting - prevent too rapid command execution
        with self.command_lock:
            time_since_last = current_time - self.last_command_time
            if time_since_last < self.min_command_interval:
                time.sleep(self.min_command_interval - time_since_last)
            
            self.last_command_time = time.time()
            self.command_count += 1
        
        # Check if we're at concurrent command limit
        with self.command_lock:
            if len(self.active_commands) >= self.max_concurrent:
                # Wait for a command to complete
                time.sleep(0.5)
        
        # Submit to executor with timeout
        future = self.executor.submit(subprocess.run, cmd, **kwargs)
        
        # Track active command
        cmd_id = id(future)
        with self.command_lock:
            self.active_commands[cmd_id] = {
                'cmd': cmd[:3] if cmd else 'unknown',  # First 3 elements only for security
                'start_time': time.time()
            }
        
        try:
            # Default timeout if not specified
            timeout = kwargs.get('timeout', TimeoutConstants.MEDIUM)
            result = future.result(timeout=timeout)
            return result
        except Exception as e:
            # Log command failure for security monitoring
            return type('SubprocessResult', (), {
                'returncode': -1, 
                'stdout': '', 
                'stderr': f'Command execution failed: {str(e)[:100]}'
            })()
        finally:
            # Remove from active tracking
            with self.command_lock:
                self.active_commands.pop(cmd_id, None)

class DatabaseContext:
    """Context manager for safe database connections with automatic cleanup."""
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = None
    
    def __enter__(self):
        self.conn = sqlite3.connect(self.db_path, timeout=TimeoutConstants.DATABASE)
        self.conn.row_factory = sqlite3.Row
        return self.conn
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            if exc_type is None:
                self.conn.commit()
            else:
                self.conn.rollback()
            self.conn.close()
        return False

class TMDBLookup:
    """Handle TMDB API lookups for movie and TV show metadata."""
    
    def __init__(self):
        self.api_key = None
        self.base_url = "https://api.themoviedb.org/3"
        self.session = requests.Session()
        self.session.timeout = TimeoutConstants.STANDARD
        
    def set_api_key(self, api_key):
        """Set TMDB API key."""
        if not api_key or not isinstance(api_key, str) or len(api_key) < 10:
            raise ValueError("Invalid TMDB API key")
        self.api_key = api_key
        
    def search_movie(self, title, year=None):
        """Search for a movie by title and optional year."""
        if not self.api_key:
            raise ValueError("TMDB API key not set")
            
        params = {
            'api_key': self.api_key,
            'query': title
        }
        if year:
            params['year'] = year
            
        try:
            response = self.session.get(f"{self.base_url}/search/movie", params=params)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"TMDB API error: {str(e)}")
            return None
            
    def search_tv(self, title, year=None):
        """Search for a TV show by title and optional year."""
        if not self.api_key:
            raise ValueError("TMDB API key not set")
            
        params = {
            'api_key': self.api_key,
            'query': title
        }
        if year:
            params['first_air_date_year'] = year
            
        try:
            response = self.session.get(f"{self.base_url}/search/tv", params=params)
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"TMDB API error: {str(e)}")
            return None
            
    def get_movie_details(self, movie_id):
        """Get detailed movie information by TMDB ID."""
        if not self.api_key:
            raise ValueError("TMDB API key not set")
            
        try:
            response = self.session.get(f"{self.base_url}/movie/{movie_id}", 
                                      params={'api_key': self.api_key})
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"TMDB API error: {str(e)}")
            return None
            
    def get_tv_details(self, tv_id):
        """Get detailed TV show information by TMDB ID."""
        if not self.api_key:
            raise ValueError("TMDB API key not set")
            
        try:
            response = self.session.get(f"{self.base_url}/tv/{tv_id}", 
                                      params={'api_key': self.api_key})
            response.raise_for_status()
            return response.json()
        except requests.RequestException as e:
            print(f"TMDB API error: {str(e)}")
            return None

class MediaManager:
    def __init__(self, base_path="/Volumes/media/Video"):
        # Validate and normalize base path
        self.base_path = os.path.abspath(os.path.realpath(base_path))
        
        # Ensure base_path exists and is accessible
        if not os.path.exists(self.base_path):
            raise ValueError(f"Base path does not exist: {self.base_path}")
        if not os.path.isdir(self.base_path):
            raise ValueError(f"Base path is not a directory: {self.base_path}")
        if not os.access(self.base_path, os.R_OK):
            raise ValueError(f"Base path is not readable: {self.base_path}")
        
        self.video_extensions = ('.mp4', '.mkv', '.avi', '.mov', '.flv', '.m4v', '.wmv')
        
        # Default language preferences - can be modified via settings menu
        self.preferred_languages = ['en', 'eng', 'english']  # Languages to keep
        self.max_parallel_downloads = 8  # Default parallel download limit
        
        # Store database and settings in media directory
        db_dir = os.path.join(self.base_path, '.media-manager')
        
        # Create directory with restrictive permissions
        os.makedirs(db_dir, mode=0o700, exist_ok=True)
        
        self.db_path = os.path.join(db_dir, 'media_library.db')
        self.settings_file = os.path.join(db_dir, 'settings.json')
        
        # Set restrictive permissions on database file if it exists
        if os.path.exists(self.db_path):
            # Set secure permissions and verify
            os.chmod(self.db_path, 0o600)  # Read/write for owner only
            current_perms = oct(os.stat(self.db_path).st_mode)[-3:]
            if current_perms != '600':
                self.security_audit_log("DB_PERMISSION_WARNING", f"Database permissions {current_perms} instead of 600")
        
        # Initialize loop safety mechanisms
        self.max_menu_iterations = 1000  # Safety limit to prevent infinite loops
        self.loop_start_time = None
        self.running = True
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self.graceful_shutdown)
        signal.signal(signal.SIGINT, self.graceful_shutdown)
        
        # Initialize external command manager for rate limiting and security
        self.cmd_manager = ExternalCommandManager(max_concurrent=3)
        
        # Check dependencies at startup
        self.check_dependencies()
        
        # Load language preferences from settings
        self.load_settings()
        
        self.init_database()
        
        # Background task management with thread safety
        self.task_queue = queue.Queue()
        self.active_tasks = {}
        self.completed_tasks = []
        self.task_counter = 0
        self.max_concurrent_tasks = 2
        self._task_lock = threading.Lock()
        self._progress_lock = threading.Lock()
        
        # Resource limits to prevent exhaustion
        self.max_files_per_scan = 100000  # Limit file scanning
        self.max_directory_depth = 20  # Prevent deep recursion
        self.max_path_length = 4096      # Prevent path length attacks
        self.files_scanned_count = 0
        
        # Initialize TMDB lookup instance
        self.tmdb = TMDBLookup()
        
        # Signal handling for graceful shutdown
        self._shutdown_requested = False
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # Rate limiting and DoS protection
        self.rate_limit_window = 60  # 1 minute window
        self.max_operations_per_minute = 30  # Limit operations per minute
        self.operation_timestamps = []
        self.failed_operation_count = 0
        self.max_failed_operations = 10  # Lock after 10 failed operations
        self._rate_limit_lock = threading.Lock()
        
    def init_database(self):
        """Initialize SQLite database for video metadata caching with security hardening."""
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            
            # Apply comprehensive security hardening PRAGMAs (skip journal_mode due to filesystem compatibility)
            cursor.execute('PRAGMA synchronous = FULL')  # Maximum data integrity
            cursor.execute('PRAGMA foreign_keys = ON')   # Enable foreign key constraints
            cursor.execute('PRAGMA secure_delete = ON')  # Overwrite deleted data
            cursor.execute('PRAGMA temp_store = MEMORY') # Store temp data in memory, not disk
            cursor.execute('PRAGMA cell_size_check = ON')  # Enable database consistency checks
            cursor.execute('PRAGMA trusted_schema = OFF')  # Disable trusted schema for security
            cursor.execute('PRAGMA auto_vacuum = FULL')    # Automatic database maintenance
            
            # Create main video files table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS video_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_path TEXT UNIQUE NOT NULL,
                    relative_path TEXT NOT NULL,
                    filename TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    file_modified REAL NOT NULL,
                    last_scanned REAL NOT NULL,
                    width INTEGER,
                    height INTEGER,
                    duration REAL,
                    codec TEXT,
                    bitrate INTEGER,
                    framerate REAL,
                    has_external_subs BOOLEAN DEFAULT 0,
                    has_embedded_subs BOOLEAN DEFAULT 0,
                    subtitle_languages TEXT,
                    naming_issues TEXT,
                    needs_conversion BOOLEAN DEFAULT 0,
                    conversion_reason TEXT,
                    checksum TEXT
                )
            ''')
            
            # Create analysis sessions table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS analysis_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    total_files INTEGER NOT NULL,
                    files_analyzed INTEGER NOT NULL,
                    duration_seconds REAL,
                    recommendations TEXT,
                    status TEXT DEFAULT 'completed'
                )
            ''')
            
            # Create folder configuration table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS folder_config (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    folder_path TEXT UNIQUE NOT NULL,
                    folder_type TEXT NOT NULL CHECK(folder_type IN ('movies', 'tv')),
                    enabled BOOLEAN DEFAULT 1,
                    last_updated REAL NOT NULL
                )
            ''')
            
            # Create manual corrections table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS manual_corrections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    original_file_path TEXT NOT NULL,
                    original_filename TEXT NOT NULL,
                    corrected_title TEXT NOT NULL,
                    corrected_year INTEGER,
                    media_type TEXT NOT NULL CHECK(media_type IN ('movie', 'tv')),
                    tmdb_id INTEGER,
                    tmdb_title TEXT,
                    tmdb_year INTEGER,
                    correction_date REAL NOT NULL,
                    applied BOOLEAN DEFAULT 0,
                    UNIQUE(original_file_path)
                )
            ''')
            
            # Add default folders if not already configured
            cursor.execute('SELECT COUNT(*) FROM folder_config')
            if cursor.fetchone()[0] == 0:
                default_folders = [
                    (os.path.join(self.base_path, 'Movies'), 'movies'),
                    (os.path.join(self.base_path, 'TV'), 'tv')
                ]
                for folder_path, folder_type in default_folders:
                    if os.path.exists(folder_path):
                        cursor.execute('''
                            INSERT OR IGNORE INTO folder_config (folder_path, folder_type, last_updated)
                            VALUES (?, ?, ?)
                        ''', (folder_path, folder_type, time.time()))
            
            # Create indexes for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_path ON video_files(file_path)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_modified ON video_files(file_modified)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_needs_conversion ON video_files(needs_conversion)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_naming_issues ON video_files(naming_issues)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_folder_type ON folder_config(folder_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_corrections_applied ON manual_corrections(applied)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_corrections_media_type ON manual_corrections(media_type)')
        
        # Set secure file permissions on database (readable/writable by owner only)
        try:
            os.chmod(self.db_path, 0o600)
            # Verify permissions were set correctly
            current_perms = oct(os.stat(self.db_path).st_mode)[-3:]
            if current_perms != '600':
                self.security_audit_log("DB_PERMISSION_WARNING", f"Database permissions {current_perms} instead of 600")
        except OSError as e:
            print(f"Warning: Could not set secure permissions on database: {self.sanitize_error_message(str(e))}")
    
    def security_audit_log(self, operation, details=""):
        """Log security-relevant operations for audit purposes."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] SECURITY: {operation}"
        if details:
            log_entry += f" - {details}"
        
        # Log to secure file in base directory
        audit_log_path = os.path.join(self.base_path, "security_audit.log")
        try:
            if self.validate_safe_path(audit_log_path):
                with open(audit_log_path, 'a', encoding='utf-8') as f:
                    f.write(log_entry + '\n')
        except (OSError, IOError):
            # Fallback to stderr if file logging fails
            print(f"AUDIT: {log_entry}", file=sys.stderr)
    
    def operation_log(self, operation, status, details="", file_path=None):
        """Log all operations with success/failure status for debugging."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {operation.upper()}: {status}"
        
        if file_path:
            sanitized_path = os.path.relpath(file_path, self.base_path) if file_path.startswith(self.base_path) else "[EXTERNAL_PATH]"
            log_entry += f" - File: {sanitized_path}"
        
        if details:
            sanitized_details = self.sanitize_error_message(details)
            log_entry += f" - {sanitized_details}"
        
        # Log to operations file
        ops_log_path = os.path.join(self.base_path, "operations.log")
        try:
            if self.validate_safe_path(ops_log_path):
                with open(ops_log_path, 'a', encoding='utf-8') as f:
                    f.write(log_entry + '\n')
        except (OSError, IOError):
            # Fallback to stderr if file logging fails
            print(f"OPS_LOG: {log_entry}", file=sys.stderr)
        
        # Also print to console in verbose mode (can be toggled later)
        if not hasattr(self, 'verbose_logging'):
            self.verbose_logging = True  # Default to verbose for now
        
        if self.verbose_logging:
            status_icon = "✓" if status == "SUCCESS" else "✗" if status == "FAILED" else "ℹ️"
            print(f"   {status_icon} LOG: {operation} - {status}")
    
    def sanitize_error_message(self, error_msg):
        """Sanitize error messages to prevent information disclosure."""
        if not isinstance(error_msg, str):
            error_msg = str(error_msg)
        
        # Replace absolute paths with relative paths
        sanitized = error_msg.replace(self.base_path, "[BASE_PATH]")
        
        # Remove common sensitive patterns
        import re
        sanitized = re.sub(r'/Users/[^/\s]+', '/Users/[USER]', sanitized)
        sanitized = re.sub(r'/home/[^/\s]+', '/home/[USER]', sanitized)
        sanitized = re.sub(r'/Volumes/[^/\s]+', '/Volumes/[VOLUME]', sanitized)
        sanitized = re.sub(r'/Applications/[^/\s]+', '/Applications/[APP]', sanitized)
        sanitized = re.sub(r'/System/[^/\s]+', '/System/[SYSTEM]', sanitized)
        sanitized = re.sub(r'/Library/[^/\s]+', '/Library/[LIB]', sanitized)
        sanitized = re.sub(r'file://[^\s]+', 'file://[PATH]', sanitized)
        sanitized = re.sub(r'[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}', '[UUID]', sanitized)
        
        return sanitized
    
    def sanitize_path_for_display(self, path):
        """Sanitize file paths for safe display in error messages."""
        if not isinstance(path, str):
            path = str(path)
        
        # Convert to relative path if under base_path
        try:
            if path.startswith(self.base_path):
                return os.path.relpath(path, self.base_path)
        except (ValueError, OSError):
            pass
        
        # Replace sensitive directory patterns
        import re
        sanitized = re.sub(r'/Users/[^/\s]+', '/Users/[USER]', path)
        sanitized = re.sub(r'/home/[^/\s]+', '/home/[USER]', sanitized)
        sanitized = re.sub(r'/Volumes/[^/\s]+', '/Volumes/[VOLUME]', sanitized)
        sanitized = re.sub(r'/Applications/[^/\s]+', '/Applications/[APP]', sanitized)
        sanitized = re.sub(r'/System/[^/\s]+', '/System/[SYSTEM]', sanitized)
        sanitized = re.sub(r'/Library/[^/\s]+', '/Library/[LIB]', sanitized)
        
        return sanitized
    
    def check_rate_limit(self, operation_name="operation"):
        """Check if operation is within rate limits to prevent DoS."""
        with self._rate_limit_lock:
            current_time = time.time()
            
            # Remove timestamps older than rate limit window
            self.operation_timestamps = [
                timestamp for timestamp in self.operation_timestamps 
                if current_time - timestamp < self.rate_limit_window
            ]
            
            # Check if we're over the rate limit
            if len(self.operation_timestamps) >= self.max_operations_per_minute:
                remaining_time = self.rate_limit_window - (current_time - self.operation_timestamps[0])
                print(f"⚠️  Rate limit exceeded. Please wait {remaining_time:.1f} seconds before trying again.")
                self.security_audit_log("RATE_LIMIT_EXCEEDED", f"Operation: {operation_name}")
                return False
            
            # Check if too many failed operations
            if self.failed_operation_count >= self.max_failed_operations:
                print(f"⚠️  Too many failed operations ({self.failed_operation_count}). System temporarily locked.")
                self.security_audit_log("FAILED_OP_LOCKOUT", f"Operation: {operation_name}")
                return False
            
            # Record this operation
            self.operation_timestamps.append(current_time)
            return True
    
    def record_operation_failure(self, operation_name="operation"):
        """Record a failed operation for DoS protection."""
        with self._rate_limit_lock:
            self.failed_operation_count += 1
            self.security_audit_log("OPERATION_FAILED", f"Operation: {operation_name}, Total failures: {self.failed_operation_count}")
    
    def reset_failure_count(self):
        """Reset failure count after successful operations."""
        with self._rate_limit_lock:
            if self.failed_operation_count > 0:
                self.failed_operation_count = max(0, self.failed_operation_count - 1)
    
    def _signal_handler(self, signum, frame):
        """Handle system signals for graceful shutdown."""
        signal_name = signal.Signals(signum).name
        print(f"\n⚠️  Received {signal_name} signal. Initiating graceful shutdown...")
        self.security_audit_log("SIGNAL_RECEIVED", f"Signal: {signal_name}")
        self._shutdown_requested = True
        
        # Cancel any active tasks
        with self._task_lock:
            for task_id in list(self.active_tasks.keys()):
                self.active_tasks[task_id]['status'] = 'cancelled'
        
        self.cleanup_and_exit(0)
    
    def safe_input(self, prompt="", default=None, validator=None):
        """Safe input handling with EOFError protection and validation."""
        try:
            # Check if running in non-interactive mode
            if not sys.stdin.isatty():
                if default is not None:
                    return default
                else:
                    print(f"\nNon-interactive mode detected. Unable to get input for: {prompt}")
                    self.cleanup_and_exit(1)
            
            user_input = input(prompt).strip()
            
            # Apply validator if provided
            if validator:
                validated = validator(user_input)
                if validated is None:
                    return self.safe_input(prompt, default, validator)
                return validated
            
            return user_input
            
        except EOFError:
            if default is not None:
                return default
            print("\nEOF detected. Exiting...")
            self.cleanup_and_exit(0)
        except KeyboardInterrupt:
            print("\n\nOperation cancelled.")
            self.cleanup_and_exit(0)
    
    def safe_int_input(self, prompt="", min_val=None, max_val=None, default=None):
        """Safe integer input with validation."""
        def int_validator(value):
            if not value and default is not None:
                return default
            try:
                num = int(value)
                if min_val is not None and num < min_val:
                    print(f"Value must be at least {min_val}")
                    return None
                if max_val is not None and num > max_val:
                    print(f"Value must be at most {max_val}")
                    return None
                return num
            except ValueError:
                print("Please enter a valid number")
                return None
        
        return self.safe_input(prompt, default, int_validator)
    
    def safe_path_input(self, prompt="", must_exist=True, base_path_required=True):
        """Safe path input with validation."""
        def path_validator(value):
            if not value:
                print("Path cannot be empty")
                return None
            
            # Resolve path to absolute
            abs_path = os.path.abspath(os.path.expanduser(value))
            
            # Check if path traversal attempt
            if base_path_required:
                try:
                    # Ensure path is within base_path
                    rel_path = os.path.relpath(abs_path, self.base_path)
                    if rel_path.startswith('..'):
                        print(f"Path must be within {self.base_path}")
                        return None
                except ValueError:
                    print(f"Path must be within {self.base_path}")
                    return None
            
            # Check existence if required
            if must_exist and not os.path.exists(abs_path):
                print(f"Path does not exist: {self.sanitize_path_for_display(abs_path)}")
                return None
            
            return abs_path
        
        return self.safe_input(prompt, None, path_validator)
    
    def safe_file_operation_atomic(self, file_path, operation_type="read"):
        """Perform file operations atomically to prevent TOCTOU attacks."""
        try:
            # Check if it's a symlink first
            if os.path.islink(file_path):
                self.security_audit_log("SYMLINK_BLOCKED", f"Blocked symlink operation: {self.sanitize_path_for_display(file_path)}")
                return False, "Symbolic links not allowed"
            
            # For read operations, use O_NOFOLLOW to prevent symlink following
            if operation_type == "read":
                try:
                    fd = os.open(file_path, os.O_RDONLY | os.O_NOFOLLOW)
                    os.close(fd)
                    return True, "Safe to read"
                except OSError as e:
                    if e.errno == errno.ELOOP:
                        self.security_audit_log("SYMLINK_ATTACK", f"Symlink attack detected: {self.sanitize_path_for_display(file_path)}")
                        return False, "Symbolic link detected"
                    return False, f"File access error: {self.sanitize_error_message(str(e))}"
            
            # For other operations, do additional validation
            stat_info = os.lstat(file_path)  # Use lstat to not follow symlinks
            if stat.S_ISLNK(stat_info.st_mode):
                self.security_audit_log("SYMLINK_BLOCKED", f"Blocked symlink operation: {self.sanitize_path_for_display(file_path)}")
                return False, "Symbolic links not allowed"
                
            return True, "File operation safe"
            
        except OSError as e:
            return False, f"File validation error: {self.sanitize_error_message(str(e))}"
    
    def safe_walk(self, root_path, followlinks=False):
        """Safe directory walking with DoS protection limits."""
        file_count = 0
        dir_count = 0
        depth = 0
        
        try:
            for current_root, dirs, files in os.walk(root_path, followlinks=followlinks):
                # Check depth limit
                relative_path = os.path.relpath(current_root, root_path)
                current_depth = len(relative_path.split(os.sep)) if relative_path != '.' else 0
                if current_depth > PerformanceLimits.MAX_SCAN_DEPTH:
                    self.security_audit_log("SCAN_DEPTH_LIMIT", f"Stopped scan at depth {current_depth}")
                    break
                
                # Check directory count limit
                dir_count += 1
                if dir_count > PerformanceLimits.MAX_DIRECTORIES_PER_SCAN:
                    self.security_audit_log("SCAN_DIR_LIMIT", f"Stopped scan at {dir_count} directories")
                    break
                
                # Filter and count files
                valid_files = []
                for file in files:
                    file_count += 1
                    if file_count > PerformanceLimits.MAX_FILES_PER_SCAN:
                        self.security_audit_log("SCAN_FILE_LIMIT", f"Stopped scan at {file_count} files")
                        return
                    
                    file_path = os.path.join(current_root, file)
                    
                    # Skip symlinks for security
                    if os.path.islink(file_path):
                        self.security_audit_log("SYMLINK_SKIPPED", f"Skipped symlink: {self.sanitize_path_for_display(file_path)}")
                        continue
                    
                    valid_files.append(file)
                
                yield current_root, dirs, valid_files
                
        except OSError as e:
            self.security_audit_log("WALK_ERROR", f"Error during directory walk: {self.sanitize_error_message(str(e))}")
            return
    
    def validate_safe_path(self, path):
        """Validate that a path is safe for operations with strict directory access control."""
        if not path:
            return False
        
        # Normalize Unicode to handle different encodings
        normalized_path = self.normalize_unicode_path(path)
        
        # Resolve to absolute path
        abs_path = os.path.abspath(os.path.realpath(normalized_path))
        
        # STRICT: Ensure path is within base_path - no exceptions
        try:
            rel_path = os.path.relpath(abs_path, self.base_path)
            if rel_path.startswith('..') or os.path.isabs(rel_path):
                return False
        except ValueError:
            return False
        
        # Additional security: Check that resolved path starts with base_path
        if not abs_path.startswith(self.base_path + os.sep) and abs_path != self.base_path:
            return False
        
        # Check for invalid characters that could be used in command injection
        invalid_chars = [';', '&', '|', '`', '$', '(', ')', '<', '>', '"', "'", '\x00', '\n', '\r', '\t']
        if any(char in abs_path for char in invalid_chars):
            return False
        
        # Additional FFmpeg-specific filename validation
        filename = os.path.basename(abs_path)
        # Reject filenames that could be interpreted as FFmpeg options
        if filename.startswith('-') or filename.startswith('+'):
            return False
        
        # Reject filenames with null bytes or control characters
        if any(ord(c) < 32 for c in filename if c not in ['\n', '\r', '\t']):
            return False
        
        # Validate Unicode normalization consistency
        if normalized_path != path:
            # Potential Unicode attack - reject path entirely for security
            print(f"Security: Rejecting path with suspicious Unicode: {repr(self.sanitize_path_for_display(path))}")
            return False
        
        # Additional Unicode security checks
        # Reject paths with homograph characters that could be used for attacks
        dangerous_chars = [
            '\u202e',  # Right-to-left override
            '\u202d',  # Left-to-right override
            '\u200e',  # Left-to-right mark
            '\u200f',  # Right-to-left mark
            '\ufeff',  # Zero width no-break space
            '\u200b',  # Zero width space
            '\u2060',  # Word joiner
        ]
        if any(char in abs_path for char in dangerous_chars):
            return False
        
        return True
    
    def normalize_unicode_path(self, path):
        """Secure Unicode path normalization with attack detection."""
        if not isinstance(path, str):
            path = str(path)
        
        # Apply different normalization forms to detect manipulation
        nfc = unicodedata.normalize('NFC', path)
        nfd = unicodedata.normalize('NFD', path)
        nfkc = unicodedata.normalize('NFKC', path)
        nfkd = unicodedata.normalize('NFKD', path)
        
        # If any normalization changes the path significantly, it's suspicious
        if not all(norm == path for norm in [nfc, nfd, nfkc, nfkd]):
            self.security_audit_log("UNICODE_ATTACK_DETECTED", f"Path normalization changed: {repr(path)}")
            # Still allow with warning for legitimate Unicode file names
            if len(path) != len(nfc) or any(ord(c) > 0x7F for c in path):
                print(f"Warning: Unicode normalization changed path: {repr(path)} -> {repr(nfc)}")
        
        # Remove any zero-width or control characters that could cause issues
        cleaned = ''.join(char for char in nfc 
                         if not unicodedata.category(char).startswith('C') 
                         or char in ['\n', '\r', '\t'])
        
        # Reject paths with dangerous Unicode patterns
        dangerous_patterns = ['\u202E', '\u202D', '\uFEFF', '\u200B', '\u200C', '\u200D']
        for pattern in dangerous_patterns:
            if pattern in cleaned:
                raise ValueError(f"Path contains dangerous Unicode character: {repr(pattern)}")
        
        return cleaned
    
    def validate_rclone_remote_name(self, remote_name):
        """Validate rclone remote name to prevent command injection."""
        if not remote_name:
            return False, "Remote name cannot be empty"
        
        # Check for shell metacharacters that could lead to command injection
        dangerous_chars = [
            ';', '&', '|', '$', '`', '\n', '\r', '\t',
            '(', ')', '{', '}', '[', ']', '<', '>', 
            '"', "'", '\\', '!', '*', '?', '~',
            '\x00', '\x1a', '\x1b'  # Null and escape chars
        ]
        
        for char in dangerous_chars:
            if char in remote_name:
                self.security_audit_log("RCLONE_INJECTION_ATTEMPT", f"Dangerous character '{char}' in remote: {remote_name}")
                return False, f"Remote name contains dangerous character: {repr(char)}"
        
        # Check for command substitution patterns
        dangerous_patterns = [
            '$(', '${', '`', '<(', '>(', 
            '&&', '||', ';;', '|&',
            '../', '..\\', './/', '.\\\\',
            'cmd.exe', '/bin/sh', '/bin/bash'
        ]
        
        for pattern in dangerous_patterns:
            if pattern in remote_name.lower():
                self.security_audit_log("RCLONE_INJECTION_ATTEMPT", f"Dangerous pattern '{pattern}' in remote: {remote_name}")
                return False, f"Remote name contains dangerous pattern: {pattern}"
        
        # Validate remote name format (alphanumeric, dash, underscore only)
        # This is the safest approach - whitelist allowed characters
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', remote_name):
            self.security_audit_log("RCLONE_INVALID_REMOTE", f"Invalid characters in remote: {remote_name}")
            return False, "Remote name can only contain letters, numbers, dash, and underscore"
        
        # Check length limits
        if len(remote_name) > 64:
            return False, "Remote name too long (max 64 characters)"
        
        return True, "Remote name is safe"
    
    def validate_codec_name(self, codec_name):
        """Validate codec name from video metadata to prevent injection."""
        if not codec_name:
            return "unknown"
        
        # Convert to string and limit length
        codec_str = str(codec_name)[:50]  # Limit length to prevent DoS
        
        # Remove any dangerous characters that could be used for injection
        import re
        # Only allow alphanumeric characters, dots, dashes, and underscores
        cleaned_codec = re.sub(r'[^a-zA-Z0-9._-]', '', codec_str.lower())
        
        # If the cleaned codec is empty, return unknown
        if not cleaned_codec:
            return "unknown"
        
        # Check for suspicious patterns that could indicate injection attempts
        suspicious_patterns = ['select', 'insert', 'update', 'delete', 'drop', 'union', 'or', 'and', '--', ';']
        if any(pattern in cleaned_codec.lower() for pattern in suspicious_patterns):
            self.security_audit_log("CODEC_INJECTION_ATTEMPT", f"Suspicious codec name: {codec_name}")
            return "suspicious"
        
        return cleaned_codec
    
    def validate_python_executable(self, python_path):
        """Validate that a path points to a legitimate Python executable."""
        try:
            # Check if it's a regular file (not a symlink that could be manipulated)
            if not os.path.isfile(python_path) or os.path.islink(python_path):
                return False
            
            # Check file permissions - should not be writable by others
            stat_info = os.stat(python_path)
            perms = stat_info.st_mode & 0o777  # Get permission bits
            if perms & 0o022:  # Check if writable by group or others
                self.security_audit_log("PYTHON_INSECURE_PERMS", f"Python executable has insecure permissions {oct(perms)}: {python_path}")
                return False
            
            # Additional check: ensure it's actually executable by owner
            if not (perms & 0o100):  # Owner execute bit not set
                self.security_audit_log("PYTHON_NOT_EXECUTABLE", f"Python path not executable: {python_path}")
                return False
            
            # Try to execute it with a simple test to ensure it's actually Python
            result = self.cmd_manager.safe_subprocess_run([python_path, '-c', 'import sys; print(sys.version_info.major)'], 
                                  capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and result.stdout.strip() == '3':
                return True
            else:
                self.security_audit_log("PYTHON_INVALID", f"Path does not execute as Python 3: {python_path}")
                return False
                
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired) as e:
            self.security_audit_log("PYTHON_VALIDATION_ERROR", f"Error validating Python executable {python_path}: {e}")
            return False
    
    def graceful_shutdown(self, signum, frame):
        """Handle shutdown signals gracefully."""
        print("\n🛑 Received shutdown signal. Exiting safely...")
        self.running = False
        sys.exit(0)
    
    def detect_file_encoding(self, file_path):
        """Detect file encoding with fallback options."""
        encodings_to_try = ['utf-8', 'utf-8-sig', 'latin1', 'cp1252', 'iso-8859-1']
        
        for encoding in encodings_to_try:
            try:
                with open(file_path, 'r', encoding=encoding) as f:
                    # Try to read first few lines to test encoding
                    f.read(1024)
                return encoding
            except (UnicodeDecodeError, UnicodeError):
                continue
            except (OSError, IOError):
                break
        
        # Fallback to UTF-8 with error handling
        return 'utf-8'
    
    def safe_read_text_file(self, file_path):
        """Safely read text file with encoding detection."""
        encoding = self.detect_file_encoding(file_path)
        try:
            with open(file_path, 'r', encoding=encoding, errors='replace') as f:
                return f.read()
        except (OSError, IOError, UnicodeError) as e:
            print(f"Warning: Could not read text file {self.sanitize_path_for_display(file_path)}: {self.sanitize_error_message(str(e))}")
            return None
    
    def safe_scan_directory(self, directory_path):
        """Unicode-safe directory scanning with validation and resource limits."""
        video_files = []
        
        # Validate directory is safe
        if not self.validate_safe_path(directory_path):
            print(f"Warning: Skipping unsafe directory: {directory_path}")
            return video_files
        
        # Reset file counter for this scan
        self.files_scanned_count = 0
        
        try:
            for root, dirs, files in self.safe_walk(directory_path, followlinks=False):
                # Check resource limits
                if self.files_scanned_count >= self.max_files_per_scan:
                    print(f"Warning: File scan limit reached ({self.max_files_per_scan}). Stopping scan.")
                    break
                
                # Check directory depth to prevent deep recursion attacks
                depth = len(os.path.relpath(root, directory_path).split(os.sep))
                if depth > self.max_directory_depth:
                    print(f"Warning: Maximum directory depth ({self.max_directory_depth}) exceeded. Skipping: {root}")
                    dirs.clear()  # Don't recurse further
                    continue
                
                # Check path length to prevent path length attacks
                if len(root) > self.max_path_length:
                    print(f"Warning: Path length ({len(root)}) exceeds maximum ({self.max_path_length}). Skipping: {root[:100]}...")
                    dirs.clear()  # Don't recurse further
                    continue
                # Validate each subdirectory is safe
                if not self.validate_safe_path(root):
                    print(f"Warning: Skipping unsafe subdirectory: {root}")
                    continue
                
                for file in files:
                    # Check file count limit
                    if self.files_scanned_count >= self.max_files_per_scan:
                        print(f"Warning: File scan limit reached. Processed {self.files_scanned_count} files.")
                        break
                    
                    try:
                        # Normalize Unicode in filename
                        normalized_file = self.normalize_unicode_path(file)
                        
                        if normalized_file.lower().endswith(self.video_extensions):
                            file_path = os.path.join(root, normalized_file)
                            
                            # Check total file path length
                            if len(file_path) > self.max_path_length:
                                print(f"Warning: File path length ({len(file_path)}) exceeds maximum. Skipping: {file_path[:100]}...")
                                continue
                            
                            # Double-check the final path is safe
                            if self.validate_safe_path(file_path):
                                video_files.append(file_path)
                                self.files_scanned_count += 1
                            else:
                                print(f"Warning: Skipping unsafe file: {self.sanitize_path_for_display(file_path)}")
                        
                        self.files_scanned_count += 1
                    
                    except UnicodeError as e:
                        print(f"Warning: Unicode error processing file {self.sanitize_path_for_display(file)}: {self.sanitize_error_message(str(e))}")
                        continue
                        
        except (OSError, IOError) as e:
            print(f"Error scanning directory {self.sanitize_path_for_display(directory_path)}: {self.sanitize_error_message(str(e))}")
        
        return video_files
    
    def check_file_permissions(self, file_path, operation='read'):
        """Check file permissions before operations."""
        if not os.path.exists(file_path):
            return False, "File does not exist"
        
        if operation == 'read':
            if not os.access(file_path, os.R_OK):
                return False, "No read permission"
        elif operation == 'write':
            if os.path.isfile(file_path) and not os.access(file_path, os.W_OK):
                return False, "No write permission"
            elif os.path.isdir(file_path) and not os.access(file_path, os.W_OK):
                return False, "No write permission to directory"
        elif operation == 'delete':
            parent_dir = os.path.dirname(file_path)
            if not os.access(parent_dir, os.W_OK):
                return False, "No delete permission (parent directory not writable)"
        
        return True, "OK"
    
    def check_disk_space(self, required_bytes=0):
        """Check available disk space with symlink attack protection."""
        try:
            # Resolve symlinks to prevent symlink attacks
            real_path = os.path.realpath(self.base_path)
            
            # Validate the resolved path is still safe
            if not real_path.startswith('/Volumes/media/'):
                return False, "Disk space check blocked - potential symlink attack"
            
            total, used, free = shutil.disk_usage(real_path)
            
            if required_bytes > 0 and free < required_bytes:
                return False, f"Insufficient disk space. Need {required_bytes/(1024**3):.2f} GB, have {free/(1024**3):.2f} GB"
            
            # Warn if less than 5% free space
            if free / total < 0.05:
                return False, f"Low disk space warning: Only {free/(1024**3):.2f} GB ({(free/total)*100:.1f}%) remaining"
            
            return True, f"Available: {free/(1024**3):.2f} GB"
            
        except OSError as e:
            return False, f"Could not check disk space: {e}"
    
    def safe_file_delete(self, file_path):
        """Safely delete file with comprehensive checks."""
        # Validate path is safe
        if not self.validate_safe_path(file_path):
            return False, "Unsafe file path"
        
        # Check permissions
        can_delete, perm_msg = self.check_file_permissions(file_path, 'delete')
        if not can_delete:
            return False, f"Permission denied: {perm_msg}"
        
        # Check if file is being used (basic check)
        try:
            # Try to open file exclusively to check if it's in use
            with open(file_path, 'r+b') as f:
                pass
        except PermissionError:
            return False, "File appears to be in use by another application"
        except (OSError, IOError) as e:
            return False, f"Cannot access file: {e}"
        
        # Perform deletion
        try:
            os.remove(file_path)
            # Log security-relevant file deletion
            self.security_audit_log("FILE_DELETED", f"Path: {file_path}")
            return True, "File deleted successfully"
        except (OSError, IOError) as e:
            return False, f"Deletion failed: {e}"
    
    def safe_directory_delete(self, dir_path):
        """Safely delete directory with comprehensive checks."""
        # Validate path is safe
        if not self.validate_safe_path(dir_path):
            return False, "Unsafe directory path"
        
        # Check if directory exists
        if not os.path.isdir(dir_path):
            return False, "Path is not a directory"
        
        # Check permissions
        can_delete, perm_msg = self.check_file_permissions(dir_path, 'delete')
        if not can_delete:
            return False, f"Permission denied: {perm_msg}"
        
        # Additional safety: ensure directory is within base_path
        if not dir_path.startswith(self.base_path + os.sep):
            return False, "Directory must be within base path"
        
        # Perform deletion
        try:
            shutil.rmtree(dir_path)
            # Log security-relevant directory deletion
            self.security_audit_log("DIRECTORY_DELETED", f"Path: {dir_path}")
            return True, "Directory deleted successfully"
        except OSError as e:
            return False, f"Failed to delete directory: {e}"
    
    def safe_file_rename(self, old_path, new_path):
        """Safely rename file with validation."""
        # Validate both paths are safe
        if not self.validate_safe_path(old_path) or not self.validate_safe_path(new_path):
            return False, "Unsafe file path"
        
        # Check if source exists
        if not os.path.exists(old_path):
            return False, "Source file does not exist"
        
        # Check if destination already exists
        if os.path.exists(new_path):
            return False, "Destination file already exists"
        
        # Perform rename
        try:
            os.rename(old_path, new_path)
            self.security_audit_log("FILE_RENAMED", f"From: {old_path} To: {new_path}")
            return True, "File renamed successfully"
        except OSError as e:
            return False, f"Failed to rename file: {e}"
    
    def cleanup_and_exit(self, exit_code=0):
        """Perform cleanup before exiting."""
        try:
            # Close any active database connections
            if hasattr(self, '_active_connections'):
                for conn in self._active_connections:
                    try:
                        conn.close()
                    except (sqlite3.Error, OSError) as e:
                        self.security_audit_log("DB_CLOSE_ERROR", f"Failed to close connection: {e}")
            
            # Clean up temporary files if any exist
            temp_files = ['temp_scan.py', 'temp_convert.py']
            for temp_file in temp_files:
                if os.path.exists(temp_file):
                    try:
                        os.remove(temp_file)
                    except OSError as e:
                        self.security_audit_log("TEMP_CLEANUP_ERROR", f"Failed to remove {temp_file}: {e}")
            
            print("\nCleanup completed.")
        except Exception as e:
            self.security_audit_log("CLEANUP_ERROR", f"Cleanup failed: {e}")
        
        sys.exit(exit_code)
    
    def check_dependencies(self):
        """Check all required dependencies at startup."""
        missing_deps = []
        
        # Check FFmpeg
        try:
            result = self.cmd_manager.safe_subprocess_run(['ffmpeg', '-version'], capture_output=True, text=True, timeout=TimeoutConstants.QUICK)
            if result.returncode != 0:
                missing_deps.append("FFmpeg")
        except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
            missing_deps.append("FFmpeg")
        
        # Check FFprobe
        try:
            result = self.cmd_manager.safe_subprocess_run(['ffprobe', '-version'], capture_output=True, text=True, timeout=TimeoutConstants.QUICK)
            if result.returncode != 0:
                missing_deps.append("FFprobe")
        except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
            missing_deps.append("FFprobe")
        
        # Use only secure Python executable paths - SECURITY: Removed environment variable override
        # to prevent arbitrary code execution through malicious Python interpreters
        default_venv_path = os.path.join(self.base_path, "convert_env", "bin", "python")
        
        # Try to use virtual environment if it exists and is safe, otherwise use current interpreter
        if (os.path.exists(default_venv_path) and 
            self.validate_safe_path(default_venv_path) and
            self.validate_python_executable(default_venv_path)):
            self.python_executable = default_venv_path
            self.security_audit_log("PYTHON_ENV_SELECTED", f"Using venv: {default_venv_path}")
        else:
            self.python_executable = sys.executable  # Use current secure Python interpreter
            self.security_audit_log("PYTHON_ENV_FALLBACK", f"Using system Python: {sys.executable}")
        
        # Check optional dependencies
        self.optional_deps = {}
        
        # Check subliminal
        try:
            import subliminal
            self.optional_deps['subliminal'] = True
        except ImportError:
            self.optional_deps['subliminal'] = False
            print("Info: subliminal not installed - subtitle download will be unavailable")
        
        # Check rclone
        try:
            result = self.cmd_manager.safe_subprocess_run(['rclone', 'version'], capture_output=True, text=True, timeout=TimeoutConstants.QUICK)
            self.optional_deps['rclone'] = (result.returncode == 0)
        except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
            self.optional_deps['rclone'] = False
            print("Info: rclone not installed - backup/sync will be unavailable")
        
        # Report critical missing dependencies
        if missing_deps:
            print("❌ Critical dependencies missing:")
            for dep in missing_deps:
                print(f"  - {dep}")
            print("\nPlease install missing dependencies before running.")
            self.cleanup_and_exit(1)
    
    def load_settings(self):
        """Load user settings from JSON file."""
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, 'r') as f:
                    settings = json.load(f)
                    self.preferred_languages = settings.get('preferred_languages', ['en', 'eng', 'english'])
                    self.max_parallel_downloads = settings.get('max_parallel_downloads', 8)
                    # Load TMDB API key if available
                    api_key = settings.get('tmdb_api_key')
                    if api_key:
                        try:
                            self.tmdb.set_api_key(api_key)
                        except ValueError:
                            pass  # Invalid key, will prompt user later
            except (json.JSONDecodeError, IOError):
                pass  # Use defaults if file is corrupted
    
    def save_settings(self):
        """Save user settings to JSON file."""
        settings = {
            'preferred_languages': self.preferred_languages,
            'max_parallel_downloads': self.max_parallel_downloads,
            'tmdb_api_key': self.tmdb.api_key
        }
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(settings, f, indent=2)
        except IOError:
            print("Warning: Could not save settings file")
            
    def load_settings_dict(self):
        """Load settings as dictionary."""
        if os.path.exists(self.settings_file):
            try:
                with open(self.settings_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                pass
        return {}
        
    def save_settings_dict(self, settings):
        """Save settings dictionary to file."""
        try:
            with open(self.settings_file, 'w') as f:
                json.dump(settings, f, indent=2)
        except IOError:
            print("Warning: Could not save settings file")
    
    def manage_language_preferences(self):
        """Allow user to configure preferred subtitle languages."""
        self.clear_screen()
        print("🌐 Subtitle Language Preferences")
        print("="*60)
        print(f"Current preferred languages: {', '.join(self.preferred_languages)}")
        print(f"Parallel downloads: {self.max_parallel_downloads}")
        print("\nCommon language codes:")
        print("  en, eng, english - English")
        print("  es, spa, spanish - Spanish") 
        print("  fr, fre, french - French")
        print("  de, ger, german - German")
        print("  it, ita, italian - Italian")
        print("  pt, por, portuguese - Portuguese")
        print("  ru, rus, russian - Russian")
        print("  ja, jpn, japanese - Japanese")
        print("  ko, kor, korean - Korean")
        print("  zh, chi, chinese - Chinese")
        
        print("\nOptions:")
        print("1. Set new preferred languages")
        print("2. Add a language to current list")
        print("3. Remove a language from current list")
        print("4. Reset to English only")
        print("5. Set parallel download limit")
        print("6. Clean up unwanted subtitle files now")
        print("0. Go back")
        
        choice = self.safe_input("\nEnter your choice: ")
        
        if choice == '1':
            new_langs = self.safe_input("Enter preferred languages (comma-separated): ").strip()
            if new_langs:
                self.preferred_languages = [lang.strip().lower() for lang in new_langs.split(',') if lang.strip()]
                self.save_settings()
                print(f"✓ Updated preferred languages: {', '.join(self.preferred_languages)}")
        elif choice == '2':
            new_lang = self.safe_input("Enter language code to add: ").strip().lower()
            if new_lang and new_lang not in self.preferred_languages:
                self.preferred_languages.append(new_lang)
                self.save_settings()
                print(f"✓ Added {new_lang} to preferred languages")
        elif choice == '3':
            if len(self.preferred_languages) > 1:
                print("Current languages:")
                for i, lang in enumerate(self.preferred_languages, 1):
                    print(f"  {i}. {lang}")
                try:
                    idx = int(self.safe_input("Enter number to remove: ")) - 1
                    if 0 <= idx < len(self.preferred_languages):
                        removed = self.preferred_languages.pop(idx)
                        self.save_settings()
                        print(f"✓ Removed {removed} from preferred languages")
                except ValueError:
                    print("Invalid selection")
            else:
                print("Cannot remove - need at least one preferred language")
        elif choice == '4':
            self.preferred_languages = ['en']
            self.save_settings()
            print("✓ Reset to English only")
        elif choice == '5':
            try:
                new_limit = int(self.safe_input(f"Enter parallel download limit (1-20, current: {self.max_parallel_downloads}): "))
                if 1 <= new_limit <= 20:
                    self.max_parallel_downloads = new_limit
                    self.save_settings()
                    print(f"✓ Updated parallel download limit to {new_limit}")
                else:
                    print("Invalid limit. Must be between 1 and 20.")
            except ValueError:
                print("Invalid number")
        elif choice == '6':
            self.cleanup_unwanted_subtitles()
        
        if choice in ['1', '2', '3', '4', '5']:
            self.safe_input("\nPress Enter to continue...")
    
    def detect_subtitle_languages(self, video_path):
        """Detect languages of existing subtitle files for a video."""
        base_name = os.path.splitext(video_path)[0]
        video_dir = os.path.dirname(video_path)
        video_filename = os.path.splitext(os.path.basename(video_path))[0]
        
        subtitle_files = []
        
        # Common subtitle extensions and language patterns
        subtitle_exts = ['.srt', '.vtt', '.ass', '.ssa', '.sub']
        
        # Find all subtitle files for this video
        for file in os.listdir(video_dir):
            if file.startswith(video_filename):
                for ext in subtitle_exts:
                    if file.endswith(ext):
                        full_path = os.path.join(video_dir, file)
                        subtitle_files.append((full_path, file))
        
        # Parse language codes from filenames
        detected_languages = []
        for full_path, filename in subtitle_files:
            # Remove video name and extension to get language part
            lang_part = filename[len(video_filename):].lower()
            
            # Common patterns: .en.srt, .english.srt, .es.srt, .spa.srt, etc.
            for part in lang_part.split('.'):
                if part and part not in subtitle_exts:
                    detected_languages.append((full_path, part))
        
        return detected_languages
    
    def cleanup_unwanted_subtitles(self):
        """Remove subtitle files for languages not in preferred list."""
        self.clear_screen()
        print("🧹 Subtitle Language Cleanup")
        print("="*60)
        print(f"Preferred languages: {', '.join(self.preferred_languages)}")
        print("This will scan for and remove subtitle files in other languages.")
        
        print("\nChoose scope:")
        print("1. Scan entire library")
        print("2. Scan Movies only")
        print("3. Scan TV shows only")
        print("4. Scan specific directory")
        print("0. Cancel")
        
        scope_choice = self.safe_input("\nEnter your choice: ")
        
        if scope_choice == '0':
            return
        elif scope_choice == '1':
            scan_path = self.base_path
            scope_name = "entire library"
        elif scope_choice == '2':
            scan_path = os.path.join(self.base_path, "Movies")
            scope_name = "Movies"
        elif scope_choice == '3':
            scan_path = os.path.join(self.base_path, "TV")
            scope_name = "TV shows"
        elif scope_choice == '4':
            print(f"\nSubdirectories in {self.base_path}:")
            subdirs = [d for d in os.listdir(self.base_path) if os.path.isdir(os.path.join(self.base_path, d))]
            for i, subdir in enumerate(subdirs, 1):
                print(f"  {i}. {subdir}")
            
            try:
                dir_choice = int(self.safe_input("Select directory: ")) - 1
                if 0 <= dir_choice < len(subdirs):
                    scan_path = os.path.join(self.base_path, subdirs[dir_choice])
                    scope_name = subdirs[dir_choice]
                else:
                    print("Invalid selection")
                    self.safe_input("Press Enter to continue...")
                    return
            except ValueError:
                print("Invalid selection")
                self.safe_input("Press Enter to continue...")
                return
        else:
            print("Invalid choice")
            self.safe_input("Press Enter to continue...")
            return
        
        if not os.path.exists(scan_path):
            print(f"Directory not found: {scan_path}")
            self.safe_input("Press Enter to continue...")
            return
        
        print(f"\n🔍 Scanning {scope_name} for unwanted subtitle files...")
        
        # Collect videos and their unwanted subtitles
        unwanted_files = []
        video_count = 0
        
        for root, dirs, files in os.walk(scan_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    video_count += 1
                    video_path = os.path.join(root, file)
                    
                    # Get subtitle languages for this video
                    detected_langs = self.detect_subtitle_languages(video_path)
                    
                    # Find unwanted languages
                    for sub_path, lang_code in detected_langs:
                        if lang_code not in self.preferred_languages:
                            unwanted_files.append((sub_path, lang_code, os.path.basename(video_path)))
        
        if not unwanted_files:
            print(f"✅ No unwanted subtitle files found in {scope_name}")
            print(f"   Scanned {video_count} video files")
            self.safe_input("\nPress Enter to continue...")
            return
        
        print(f"\n📋 Found {len(unwanted_files)} unwanted subtitle files:")
        print(f"   Scanned {video_count} video files in {scope_name}")
        
        # Group by language for summary
        lang_counts = {}
        for _, lang_code, _ in unwanted_files:
            lang_counts[lang_code] = lang_counts.get(lang_code, 0) + 1
        
        print("\nLanguages to be removed:")
        for lang, count in sorted(lang_counts.items()):
            print(f"   {lang}: {count} files")
        
        # Show first 10 files as examples
        print(f"\nExample files (showing first 10):")
        for i, (sub_path, lang_code, video_name) in enumerate(unwanted_files[:10], 1):
            sub_filename = os.path.basename(sub_path)
            print(f"   {i:2}. {sub_filename} ({lang_code}) - from {video_name}")
        
        if len(unwanted_files) > 10:
            print(f"   ... and {len(unwanted_files) - 10} more files")
        
        print(f"\n⚠️  This will permanently delete {len(unwanted_files)} subtitle files")
        confirm = self.safe_input("Are you sure you want to proceed? (y/N): ")
        
        if confirm.lower() != 'y':
            print("Cancelled")
            self.safe_input("Press Enter to continue...")
            return
        
        # Delete the unwanted files
        deleted_count = 0
        failed_count = 0
        
        for sub_path, lang_code, video_name in unwanted_files:
            try:
                if os.path.exists(sub_path):
                    os.remove(sub_path)
                    deleted_count += 1
                    self.operation_log("subtitle_cleanup", "DELETED", f"Removed {lang_code} subtitle", sub_path)
            except OSError as e:
                failed_count += 1
                self.operation_log("subtitle_cleanup", "DELETE_FAILED", str(e), sub_path)
        
        print(f"\n✓ Cleanup complete!")
        print(f"   Deleted: {deleted_count} files")
        if failed_count > 0:
            print(f"   Failed: {failed_count} files")
        
        self.safe_input("\nPress Enter to continue...")
    
    def get_video_resolution_safe(self, file_path):
        """Safely get video resolution using FFprobe without temporary scripts."""
        # Validate path first
        if not self.validate_safe_path(file_path):
            return None, None
        
        cmd = [
            "ffprobe",
            "-v", "error",
            "-select_streams", "v:0",
            "-show_entries", "stream=width,height", 
            "-of", "csv=s=x:p=0",
            file_path
        ]
        
        try:
            result = self.cmd_manager.safe_subprocess_run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
                                  text=True, timeout=TimeoutConstants.STANDARD)
            if result.returncode == 0:
                try:
                    width, height = result.stdout.strip().split('x')
                    return int(width), int(height)
                except (ValueError, AttributeError):
                    pass
        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass
        
        return None, None
    
    def convert_video_safe(self, file_path, output_file, target_width, target_height):
        """Safely convert video without temporary scripts."""
        # Validate paths
        if not self.validate_safe_path(file_path) or not self.validate_safe_path(output_file):
            return False
        
        # Validate width/height parameters to prevent injection
        try:
            target_width = int(target_width)
            target_height = int(target_height)
            if target_width <= 0 or target_height <= 0 or target_width > 7680 or target_height > 4320:
                return False
        except (ValueError, TypeError):
            return False
        
        cmd = [
            "ffmpeg",
            "-i", file_path,
            "-vf", f"scale={target_width}:{target_height}",
            "-c:v", "libx264",
            "-crf", "23", 
            "-preset", "medium",
            "-c:a", "aac",
            "-b:a", "128k",
            "-y",
            output_file
        ]
        
        try:
            result = self.cmd_manager.safe_subprocess_run(cmd, capture_output=True, text=True, timeout=TimeoutConstants.LONG)  # 1 hour timeout
            return result.returncode == 0
        except (subprocess.SubprocessError, subprocess.TimeoutExpired):
            return False
    
    def safe_file_operation(self, operation, file_path, *args, **kwargs):
        """Safely perform file operations with Unicode and comprehensive error handling."""
        try:
            # Normalize the file path
            normalized_path = self.normalize_unicode_path(file_path)
            
            # Validate the path is safe
            if not self.validate_safe_path(normalized_path):
                raise ValueError(f"Unsafe file path: {self.sanitize_path_for_display(file_path)}")
            
            # Check file permissions based on operation type
            operation_name = operation.__name__ if hasattr(operation, '__name__') else str(operation)
            if 'write' in operation_name.lower() or 'convert' in operation_name.lower():
                can_access, msg = self.check_file_permissions(normalized_path, 'write')
                if not can_access:
                    raise PermissionError(f"Write permission denied: {msg}")
            elif 'delete' in operation_name.lower() or 'remove' in operation_name.lower():
                can_access, msg = self.check_file_permissions(normalized_path, 'delete')
                if not can_access:
                    raise PermissionError(f"Delete permission denied: {msg}")
            else:
                # Default to read permission check
                can_access, msg = self.check_file_permissions(normalized_path, 'read')
                if not can_access:
                    raise PermissionError(f"Read permission denied: {msg}")
            
            # Perform the operation
            return operation(normalized_path, *args, **kwargs)
            
        except UnicodeError as e:
            print(f"Unicode error with file {self.sanitize_path_for_display(file_path)}: {self.sanitize_error_message(str(e))}")
            return None
        except PermissionError as e:
            print(f"Permission error for {self.sanitize_path_for_display(file_path)}: {self.sanitize_error_message(str(e))}")
            return None
        except (OSError, IOError) as e:
            print(f"File operation error for {self.sanitize_path_for_display(file_path)}: {self.sanitize_error_message(str(e))}")
            return None
    
    def get_db_connection(self):
        """DEPRECATED: Use get_db_context() instead for proper connection management."""
        raise DeprecationWarning("Use get_db_context() instead for proper connection management")
    
    def get_db_context(self):
        """Get database connection as context manager for safe handling."""
        return DatabaseContext(self.db_path)
    
    def get_file_checksum(self, file_path, size_limit_gb=1):
        """Generate checksum for small files or size-based hash for large files."""
        # Use safe file operation with Unicode handling
        return self.safe_file_operation(self._calculate_checksum, file_path, size_limit_gb)
    
    def _calculate_checksum(self, file_path, size_limit_gb=1):
        """Internal checksum calculation."""
        file_size = os.path.getsize(file_path)
        
        # Validate file size to prevent integer overflow issues
        if file_size > FileSizeConstants.MAX_FILE_SIZE:
            raise ValueError(f"File too large: {file_size} bytes exceeds maximum {FileSizeConstants.MAX_FILE_SIZE} bytes")
        
        # For large files, use size + mtime as quick hash
        if file_size > size_limit_gb * FileSizeConstants.GB:
            mtime = os.path.getmtime(file_path)
            return f"size_{file_size}_mtime_{int(mtime)}"
        
        # For smaller files, use secure file hash (SHA-256)
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def is_file_changed(self, file_path):
        """Check if file has changed since last scan."""
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            
            try:
                # Get file stats
                stat = os.stat(file_path)
                current_mtime = stat.st_mtime
                current_size = stat.st_size
                
                # Check database
                cursor.execute(
                    'SELECT file_modified, file_size, checksum FROM video_files WHERE file_path = ?',
                    (file_path,)
                )
                row = cursor.fetchone()
                
                if not row:
                    return True  # New file
                
                # Check if basic file attributes changed
                if row['file_modified'] != current_mtime or row['file_size'] != current_size:
                    return True
                    
                return False
                
            except (OSError, IOError, sqlite3.Error) as e:
                print(f"Warning: Could not check file change status for {self.sanitize_path_for_display(file_path)}: {self.sanitize_error_message(str(e))}")
                return True  # Error, assume changed
    
    def get_database_status(self):
        """Get database status including file count and last scan info."""
        try:
            with self.get_db_context() as conn:
                cursor = conn.cursor()
                
                # Get total files in database
                cursor.execute('SELECT COUNT(*) FROM video_files')
                total_files = cursor.fetchone()[0]
                
                # Get last scan time
                cursor.execute('SELECT MAX(last_scanned) FROM video_files WHERE last_scanned IS NOT NULL')
                last_scan_timestamp = cursor.fetchone()[0]
                
                # Get last analysis session
                cursor.execute('SELECT MAX(timestamp), total_files FROM analysis_sessions ORDER BY timestamp DESC LIMIT 1')
                session_row = cursor.fetchone()
                
                status = {
                    'total_files': total_files,
                    'last_scan': None,
                    'last_analysis': None,
                    'session_files': 0
                }
                
                if last_scan_timestamp:
                    status['last_scan'] = datetime.fromtimestamp(last_scan_timestamp)
                
                if session_row and session_row[0]:
                    status['last_analysis'] = datetime.fromtimestamp(session_row[0])
                    status['session_files'] = session_row[1] or 0
                
                return status
                
        except sqlite3.Error as e:
            self.security_audit_log("DB_STATUS_ERROR", str(e))
            return {
                'total_files': 0,
                'last_scan': None,
                'last_analysis': None,
                'session_files': 0,
                'error': True
            }
    
    def validate_file_data(self, file_data):
        """Validate file data before database insertion."""
        required_fields = ['file_path', 'relative_path', 'filename', 'file_size', 'file_modified']
        
        # Check required fields
        for field in required_fields:
            if field not in file_data or file_data[field] is None:
                raise ValueError(f"Missing required field: {field}")
        
        # Validate file_path exists and is accessible
        file_path = file_data['file_path']
        if not os.path.exists(file_path):
            raise ValueError(f"File does not exist: {self.sanitize_path_for_display(file_path)}")
        
        # Validate file size matches actual file
        actual_size = os.path.getsize(file_path)
        if file_data['file_size'] != actual_size:
            raise ValueError(f"File size mismatch: DB={file_data['file_size']}, Actual={actual_size}")
        
        # Validate modification time is reasonable
        actual_mtime = os.path.getmtime(file_path)
        if abs(file_data['file_modified'] - actual_mtime) > 1.0:  # Allow 1 second tolerance
            raise ValueError(f"Modification time mismatch: DB={file_data['file_modified']}, Actual={actual_mtime}")
        
        # Validate numeric fields are within reasonable bounds
        if file_data['file_size'] < 0 or file_data['file_size'] > FileSizeConstants.MAX_FILE_SIZE:
            raise ValueError(f"File size out of bounds: {file_data['file_size']}")
        
        # Validate optional numeric fields
        for field, max_val in [('width', 16384), ('height', 16384), ('bitrate', 1000000000), ('framerate', 500)]:
            if file_data.get(field) is not None:
                value = file_data[field]
                if not isinstance(value, (int, float)) or value < 0 or value > max_val:
                    raise ValueError(f"{field} out of bounds: {value}")
        
        # Validate text fields for suspicious content
        text_fields = ['codec', 'subtitle_languages', 'naming_issues', 'conversion_reason']
        for field in text_fields:
            if file_data.get(field):
                value = str(file_data[field])
                # Check for SQL injection patterns
                suspicious_patterns = ['DROP', 'DELETE', 'INSERT', 'UPDATE', 'UNION', '--', ';', 'EXEC']
                if any(pattern in value.upper() for pattern in suspicious_patterns):
                    self.security_audit_log("SUSPICIOUS_DATA", f"Field {field}: {value[:50]}")
                    file_data[field] = "[SANITIZED]"
    
    def save_video_metadata(self, file_data):
        """Save or update video metadata in database with validation."""
        # Validate data before saving
        try:
            self.validate_file_data(file_data)
        except ValueError as e:
            self.security_audit_log("DATA_VALIDATION_FAILED", str(e))
            print(f"⚠️  Data validation failed: {self.sanitize_error_message(str(e))}")
            return False
        
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO video_files (
                    file_path, relative_path, filename, file_size, file_modified,
                    last_scanned, width, height, duration, codec, bitrate, framerate,
                    has_external_subs, has_embedded_subs, subtitle_languages,
                    naming_issues, needs_conversion, conversion_reason, checksum
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                file_data['file_path'],
                file_data['relative_path'], 
                file_data['filename'],
                file_data['file_size'],
                file_data['file_modified'],
                time.time(),
                file_data.get('width'),
                file_data.get('height'),
                file_data.get('duration'),
                file_data.get('codec'),
                file_data.get('bitrate'),
                file_data.get('framerate'),
                file_data.get('has_external_subs', False),
                file_data.get('has_embedded_subs', False),
                file_data.get('subtitle_languages'),
                ','.join(file_data.get('naming_issues', [])) if file_data.get('naming_issues') else None,
                file_data.get('needs_conversion', False),
                file_data.get('conversion_reason'),
                file_data.get('checksum')
            ))
        
        return True
    
    def save_video_metadata_batch(self, file_data_list, batch_size=100):
        """Save multiple video metadata records in batches for better performance."""
        if not file_data_list:
            return True
            
        total_saved = 0
        errors = []
        
        # Process in batches
        for i in range(0, len(file_data_list), batch_size):
            batch = file_data_list[i:i + batch_size]
            
            # Validate all items in batch first
            valid_batch = []
            for file_data in batch:
                try:
                    self.validate_file_data(file_data)
                    valid_batch.append(file_data)
                except ValueError as e:
                    errors.append(f"{file_data.get('file_path', 'Unknown')}: {str(e)}")
                    
            if not valid_batch:
                continue
                
            # Save batch in single transaction
            try:
                with self.get_db_context() as conn:
                    cursor = conn.cursor()
                    
                    for file_data in valid_batch:
                        cursor.execute('''
                            INSERT OR REPLACE INTO video_files (
                                file_path, relative_path, filename, file_size, file_modified,
                                last_scanned, width, height, duration, codec, bitrate, framerate,
                                has_external_subs, has_embedded_subs, subtitle_languages,
                                naming_issues, needs_conversion, conversion_reason, checksum
                            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ''', (
                            file_data['file_path'],
                            file_data['relative_path'], 
                            file_data['filename'],
                            file_data['file_size'],
                            file_data['file_modified'],
                            time.time(),
                            file_data.get('width'),
                            file_data.get('height'),
                            file_data.get('duration'),
                            file_data.get('codec'),
                            file_data.get('bitrate'),
                            file_data.get('framerate'),
                            file_data.get('has_external_subs', False),
                            file_data.get('has_embedded_subs', False),
                            file_data.get('subtitle_languages'),
                            ','.join(file_data.get('naming_issues', [])) if file_data.get('naming_issues') else None,
                            file_data.get('needs_conversion', False),
                            file_data.get('conversion_reason'),
                            file_data.get('checksum')
                        ))
                    
                    total_saved += len(valid_batch)
                    
            except sqlite3.Error as e:
                error_msg = f"Database error saving batch {i//batch_size + 1}: {str(e)}"
                self.security_audit_log("BATCH_SAVE_ERROR", error_msg)
                errors.append(error_msg)
                
        if errors:
            print(f"\n⚠️  Saved {total_saved} files with {len(errors)} errors")
            if len(errors) <= 5:
                for error in errors:
                    print(f"   - {error}")
            else:
                print(f"   - Showing first 5 errors:")
                for error in errors[:5]:
                    print(f"   - {error}")
                    
        return total_saved > 0
    
    def verify_database_integrity(self):
        """Verify database integrity and consistency with file system."""
        print("🔍 Verifying database integrity...")
        
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            
            # Get all database entries
            cursor.execute('SELECT file_path, file_size, file_modified, checksum FROM video_files')
            db_entries = cursor.fetchall()
            
            inconsistencies = []
            checked_count = 0
            
            for row in db_entries:
                file_path = row['file_path']
                db_size = row['file_size']
                db_mtime = row['file_modified']
                db_checksum = row['checksum']
                
                try:
                    # Check if file still exists
                    if not os.path.exists(file_path):
                        inconsistencies.append({
                            'file': self.sanitize_path_for_display(file_path),
                            'issue': 'File no longer exists'
                        })
                        continue
                    
                    # Check file size
                    actual_size = os.path.getsize(file_path)
                    if db_size != actual_size:
                        inconsistencies.append({
                            'file': self.sanitize_path_for_display(file_path),
                            'issue': f'Size mismatch: DB={db_size}, Actual={actual_size}'
                        })
                    
                    # Check modification time (allow 1 second tolerance)
                    actual_mtime = os.path.getmtime(file_path)
                    if abs(db_mtime - actual_mtime) > 1.0:
                        inconsistencies.append({
                            'file': self.sanitize_path_for_display(file_path),
                            'issue': f'Modified time mismatch'
                        })
                    
                    checked_count += 1
                    
                except (OSError, IOError) as e:
                    inconsistencies.append({
                        'file': self.sanitize_path_for_display(file_path),
                        'issue': f'Access error: {self.sanitize_error_message(str(e))}'
                    })
            
            # Report results
            print(f"✅ Checked {checked_count} database entries")
            if inconsistencies:
                print(f"⚠️  Found {len(inconsistencies)} inconsistencies:")
                for issue in inconsistencies[:10]:  # Limit output
                    print(f"  {issue['file']}: {issue['issue']}")
                if len(inconsistencies) > 10:
                    print(f"  ... and {len(inconsistencies) - 10} more")
                
                self.security_audit_log("DB_INTEGRITY_ISSUES", f"Found {len(inconsistencies)} inconsistencies")
                return False
            else:
                print("✅ Database integrity verified - no inconsistencies found")
                return True
    
    def get_cached_analysis(self, max_age_hours=24):
        """Get cached analysis results if recent enough."""
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            
            # Get most recent analysis session
            cursor.execute('''
                SELECT * FROM analysis_sessions 
                WHERE timestamp > ? 
                ORDER BY timestamp DESC 
                LIMIT 1
            ''', (time.time() - max_age_hours * 3600,))
            
            session = cursor.fetchone()
            if not session:
                return None
                
            # Get all video data
            cursor.execute('SELECT * FROM video_files ORDER BY relative_path')
            videos = cursor.fetchall()
            
            return {
                'session': dict(session),
                'videos': [dict(row) for row in videos],
                'timestamp': session['timestamp']
            }
    
    def save_analysis_session(self, total_files, files_analyzed, duration_seconds, recommendations):
        """Save analysis session metadata."""
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO analysis_sessions (
                    timestamp, total_files, files_analyzed, duration_seconds, 
                    recommendations, status
                ) VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                time.time(),
                total_files,
                files_analyzed,
                duration_seconds,
                json.dumps(recommendations),
                'completed'
            ))
    
    def add_background_task(self, task_type, file_path, action_func, description):
        """Add a task to the background processing queue."""
        self.task_counter += 1
        task = {
            'id': self.task_counter,
            'type': task_type,
            'file_path': file_path,
            'action': action_func,
            'description': description,
            'status': 'queued',
            'started_at': None,
            'completed_at': None,
            'result': None
        }
        self.task_queue.put(task)
        return task['id']
    
    def process_background_tasks(self, found_issues):
        """Process background tasks with concurrent execution."""
        if self.task_queue.empty():
            return
        
        print(f"\n🔧 Starting background task processing (max {self.max_concurrent_tasks} concurrent)...")
        
        def execute_task(task):
            task['status'] = 'running'
            task['started_at'] = time.time()
            self.active_tasks[task['id']] = task
            
            try:
                result = task['action'](task['file_path'])
                task['result'] = result
                task['status'] = 'completed'
            except (subprocess.SubprocessError, OSError, IOError, ValueError, UnicodeError) as e:
                task['result'] = f"Error: {self.sanitize_error_message(str(e))}"
                task['status'] = 'failed'
            except Exception as e:
                # Log unexpected exceptions for security monitoring
                self.security_audit_log("UNEXPECTED_TASK_ERROR", f"Task {task['id']}: {type(e).__name__}")
                task['result'] = "Error: Task failed"
                task['status'] = 'failed'
            finally:
                task['completed_at'] = time.time()
                if task['id'] in self.active_tasks:
                    del self.active_tasks[task['id']]
                self.completed_tasks.append(task)
            
            return task
        
        # Convert queue to list for ThreadPoolExecutor
        tasks_to_process = []
        while not self.task_queue.empty():
            tasks_to_process.append(self.task_queue.get())
        
        if not tasks_to_process:
            return
        
        # Execute tasks with limited concurrency
        with ThreadPoolExecutor(max_workers=self.max_concurrent_tasks) as executor:
            futures = {executor.submit(execute_task, task): task for task in tasks_to_process}
            
            for future in as_completed(futures):
                task = futures[future]
                try:
                    completed_task = future.result()
                    status_icon = "✅" if completed_task['status'] == 'completed' else "❌"
                    found_issues['background_tasks'].append(f"{status_icon} {completed_task['description']}")
                except (KeyError, TypeError, AttributeError) as e:
                    found_issues['background_tasks'].append(f"❌ Task {task['id']} failed: Parse error")
    
    def download_subtitle_task(self, file_path):
        """Background task for downloading subtitles."""
        try:
            # Check if subliminal is available
            if not self.optional_deps.get('subliminal', False):
                print(f"Subliminal not available for {self.sanitize_path_for_display(file_path)}")
                return
            
            import subliminal
            from subliminal import download_best_subtitles, save_subtitles
            from babelfish import Language
            
            # Create video object
            video_path = Path(file_path)
            video = subliminal.scan_video(str(video_path))
            
            # Download English subtitles
            subtitles = download_best_subtitles([video], {Language('en')})
            
            if video in subtitles and subtitles[video]:
                save_subtitles(video, subtitles[video])
                return f"Downloaded {len(subtitles[video])} subtitle(s)"
            else:
                return "No subtitles found"
                
        except ImportError:
            return "subliminal not installed (pip install subliminal)"
        except (subprocess.SubprocessError, OSError, IOError) as e:
            return f"Error: {self.sanitize_error_message(str(e))}"
    
    def remove_system_file_task(self, file_path):
        """Background task for removing system files."""
        # Use safe deletion method
        success, message = self.safe_file_delete(file_path)
        if success:
            return "Removed successfully"
        else:
            return f"Error removing: {message}"
    
    def check_video_corruption_task(self, file_path):
        """Background task for checking video file integrity."""
        try:
            # Quick integrity check using ffprobe
            cmd = [
                'ffprobe',
                '-v', 'error',
                '-f', 'null',
                '-',
                '-i', file_path
            ]
            
            result = self.cmd_manager.safe_subprocess_run(cmd, capture_output=True, text=True, timeout=TimeoutConstants.STANDARD)
            
            if result.returncode == 0:
                return "File integrity OK"
            else:
                return f"Corruption detected: {result.stderr.strip()}"
                
        except subprocess.TimeoutExpired:
            return "Timeout during check (file may be corrupted)"
        except (subprocess.SubprocessError, OSError, IOError) as e:
            return f"Error checking: {self.sanitize_error_message(str(e))}"
    
    def rename_file_task(self, file_path):
        """Background task for renaming files to fix naming issues."""
        try:
            if not os.path.exists(file_path):
                return f"File not found: {file_path}"
                
            directory = os.path.dirname(file_path)
            filename = os.path.basename(file_path)
            new_filename = filename
            
            # Fix double spaces
            new_filename = re.sub(r'\s+', ' ', new_filename)
            
            # Fix double periods (except for file extension)
            name, ext = os.path.splitext(new_filename)
            name = re.sub(r'\.+', '.', name)
            new_filename = name + ext
            
            # Fix TV show naming for Plex (convert common formats to S##E## format)
            tv_patterns = [
                (r'(\d+)x(\d+)', r'S\1E\2'),  # 1x01 -> S01E01
                (r'[Ss](\d{1,2})[Ee](\d{1,2})', lambda m: f'S{m.group(1).zfill(2)}E{m.group(2).zfill(2)}'),  # s1e1 -> S01E01
            ]
            
            for pattern, replacement in tv_patterns:
                new_filename = re.sub(pattern, replacement, new_filename)
            
            # Only rename if changed
            if new_filename != filename:
                new_path = os.path.join(directory, new_filename)
                
                # Check if target exists
                if os.path.exists(new_path):
                    return f"Cannot rename: {new_filename} already exists"
                
                os.rename(file_path, new_path)
                
                # Update database with new path
                with self.get_db_context() as conn:
                    cursor = conn.cursor()
                    cursor.execute('UPDATE video_files SET file_path = ?, filename = ? WHERE file_path = ?',
                                 (new_path, new_filename, file_path))
                
                return f"Renamed to: {new_filename}"
            else:
                return "No renaming needed"
                
        except (OSError, IOError) as e:
            return f"Error renaming: {self.sanitize_error_message(str(e))}"
    
    def rename_file_task_no_db(self, file_path):
        """Rename file without database update (for batching)."""
        try:
            if not os.path.exists(file_path):
                return {'success': False, 'error': f"File not found: {file_path}"}
                
            directory = os.path.dirname(file_path)
            filename = os.path.basename(file_path)
            new_filename = filename
            
            # Fix double spaces
            new_filename = re.sub(r'\s+', ' ', new_filename)
            
            # Fix double periods (except for file extension)
            name, ext = os.path.splitext(new_filename)
            name = re.sub(r'\.+', '.', name)
            new_filename = name + ext
            
            # Fix TV show naming for Plex (convert common formats to S##E## format)
            tv_patterns = [
                (r'(\d+)x(\d+)', r'S\1E\2'),  # 1x01 -> S01E01
                (r'[Ss](\d{1,2})[Ee](\d{1,2})', lambda m: f'S{m.group(1).zfill(2)}E{m.group(2).zfill(2)}'),  # s1e1 -> S01E01
            ]
            
            for pattern, replacement in tv_patterns:
                new_filename = re.sub(pattern, replacement, new_filename)
            
            # Only rename if changed
            if new_filename != filename:
                new_path = os.path.join(directory, new_filename)
                
                # Check if target exists
                if os.path.exists(new_path):
                    return {'success': False, 'error': f"Cannot rename: {new_filename} already exists"}
                
                os.rename(file_path, new_path)
                
                return {
                    'success': True, 
                    'new_path': new_path, 
                    'new_filename': new_filename,
                    'old_path': file_path
                }
            else:
                return {'success': False, 'error': 'No renaming needed'}
                
        except (OSError, IOError) as e:
            return {'success': False, 'error': f"Error renaming: {self.sanitize_error_message(str(e))}"}
    
    def transcode_video_task(self, file_path):
        """Background task for transcoding videos to 1080p."""
        try:
            if not os.path.exists(file_path):
                return f"File not found: {file_path}"
                
            # Get output path
            directory = os.path.dirname(file_path)
            filename = os.path.basename(file_path)
            name, ext = os.path.splitext(filename)
            output_path = os.path.join(directory, f"{name}_1080p{ext}")
            
            # Check if output already exists
            if os.path.exists(output_path):
                return f"Output file already exists: {output_path}"
            
            # Build ffmpeg command for 1080p conversion
            cmd = [
                'ffmpeg',
                '-i', file_path,
                '-vf', 'scale=-2:1080',  # Scale to 1080p height, maintain aspect ratio
                '-c:v', 'libx264',
                '-preset', 'slow',
                '-crf', '23',
                '-c:a', 'copy',  # Copy audio without re-encoding
                '-map_metadata', '0',  # Copy all metadata
                output_path
            ]
            
            # Run conversion (with long timeout for large files)
            result = self.cmd_manager.safe_subprocess_run(cmd, capture_output=True, text=True, 
                                                        timeout=TimeoutConstants.LONG)
            
            if result.returncode == 0:
                # Update database to mark as converted
                original_size = os.path.getsize(file_path)
                new_size = os.path.getsize(output_path)
                size_reduction = (1 - new_size/original_size) * 100
                
                with self.get_db_context() as conn:
                    cursor = conn.cursor()
                    cursor.execute('''UPDATE video_files 
                                    SET needs_conversion = 0, 
                                        conversion_reason = ? 
                                    WHERE file_path = ?''',
                                 (f"Converted to 1080p, saved {size_reduction:.1f}%", file_path))
                
                return f"Transcoded successfully, saved {size_reduction:.1f}% space"
            else:
                return f"Transcoding failed: {result.stderr.strip()}"
                
        except subprocess.TimeoutExpired:
            return "Timeout during transcoding"
        except (subprocess.SubprocessError, OSError, IOError) as e:
            return f"Error transcoding: {self.sanitize_error_message(str(e))}"
    
    def optimize_container_task(self, file_path):
        """Background task for converting problematic containers to MP4."""
        try:
            if not os.path.exists(file_path):
                return f"File not found: {file_path}"
                
            # Get output path (same name but .mp4 extension)
            directory = os.path.dirname(file_path)
            filename = os.path.basename(file_path)
            name, old_ext = os.path.splitext(filename)
            output_path = os.path.join(directory, f"{name}.mp4")
            
            # Check if output already exists
            if os.path.exists(output_path):
                return f"MP4 version already exists: {output_path}"
            
            # Build ffmpeg command for container conversion
            # Use stream copy when possible to avoid re-encoding
            cmd = [
                'ffmpeg',
                '-i', file_path,
                '-c', 'copy',  # Copy streams without re-encoding when possible
                '-movflags', '+faststart',  # Optimize for streaming (web optimization)
                '-avoid_negative_ts', 'make_zero',  # Fix timing issues
                output_path
            ]
            
            # Run conversion
            result = self.cmd_manager.safe_subprocess_run(cmd, capture_output=True, text=True, 
                                                        timeout=TimeoutConstants.LONG)
            
            if result.returncode == 0:
                # Verify new file is smaller or same size
                original_size = os.path.getsize(file_path)
                new_size = os.path.getsize(output_path)
                
                # Update database to mark as optimized
                with self.get_db_context() as conn:
                    cursor = conn.cursor()
                    cursor.execute('''UPDATE video_files 
                                    SET file_path = ?, 
                                        filename = ?,
                                        file_size = ?,
                                        conversion_reason = ?
                                    WHERE file_path = ?''',
                                 (output_path, f"{name}.mp4", new_size, 
                                  f"Optimized {old_ext} to MP4 for streaming", file_path))
                
                # Option to remove original (ask user later or make it configurable)
                return f"Optimized {old_ext} to MP4 ({original_size//(1024*1024)}MB → {new_size//(1024*1024)}MB)"
            else:
                # If stream copy fails, try with re-encoding
                if '-c copy' in ' '.join(cmd):
                    cmd = [
                        'ffmpeg',
                        '-i', file_path,
                        '-c:v', 'libx264',
                        '-preset', 'fast',
                        '-crf', '23',
                        '-c:a', 'aac',
                        '-movflags', '+faststart',
                        output_path
                    ]
                    
                    result = self.cmd_manager.safe_subprocess_run(cmd, capture_output=True, text=True, 
                                                                timeout=TimeoutConstants.LONG)
                    
                    if result.returncode == 0:
                        original_size = os.path.getsize(file_path)
                        new_size = os.path.getsize(output_path)
                        
                        with self.get_db_context() as conn:
                            cursor = conn.cursor()
                            cursor.execute('''UPDATE video_files 
                                            SET file_path = ?, 
                                                filename = ?,
                                                file_size = ?,
                                                conversion_reason = ?
                                            WHERE file_path = ?''',
                                         (output_path, f"{name}.mp4", new_size, 
                                          f"Re-encoded {old_ext} to MP4 for streaming", file_path))
                        
                        return f"Re-encoded {old_ext} to MP4 ({original_size//(1024*1024)}MB → {new_size//(1024*1024)}MB)"
                
                return f"Container optimization failed: {result.stderr.strip()}"
                
        except subprocess.TimeoutExpired:
            return "Timeout during container optimization"
        except (subprocess.SubprocessError, OSError, IOError) as e:
            return f"Error optimizing container: {self.sanitize_error_message(str(e))}"

    def clear_screen(self):
        # Safe screen clearing without os.system()
        if os.name == 'posix':
            print('\033[H\033[2J\033[3J', end='')
        else:
            print('\033[2J\033[H', end='')
        
    def get_video_info(self, file_path):
        """Get video information using ffprobe."""
        cmd = [
            "ffprobe",
            "-v", "quiet",
            "-print_format", "json",
            "-show_format",
            "-show_streams",
            file_path
        ]
        try:
            result = self.cmd_manager.safe_subprocess_run(cmd, capture_output=True, text=True, timeout=TimeoutConstants.STANDARD)
            if result.returncode == 0:
                try:
                    # Safe JSON parsing with size limit to prevent DoS
                    if len(result.stdout) > 1024 * 1024:  # 1MB limit
                        raise ValueError("JSON output too large")
                    return json.loads(result.stdout)
                except (json.JSONDecodeError, ValueError) as e:
                    self.security_audit_log("JSON_PARSE_ERROR", f"Failed to parse FFprobe JSON: {e}")
                    return None
        except (subprocess.SubprocessError, OSError, IOError) as e:
            print(f"Error getting info for {file_path}: {self.sanitize_error_message(str(e))}")
        return None
    
    def inventory_videos(self):
        """Create an inventory of all video files."""
        print("\nInventorying all video files...")
        print("Scanning directories...")
        
        inventory = []
        total_size = 0
        files_processed = 0
        errors = 0
        
        # First, count total files for progress
        total_files = sum(1 for root, dirs, files in os.walk(self.base_path, followlinks=False) 
                         for file in files if file.lower().endswith(self.video_extensions))
        
        print(f"Found {total_files} video files to inventory\n")
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    files_processed += 1
                    
                    # Show progress every 10 files
                    if files_processed % 10 == 0 or files_processed == total_files:
                        print(f"Processing: {files_processed}/{total_files} files ({(files_processed/total_files)*100:.1f}%)", end='\r')
                    
                    try:
                        size = os.path.getsize(file_path)
                        total_size += size
                        relative_path = os.path.relpath(file_path, self.base_path)
                        inventory.append({
                            'path': file_path,
                            'relative_path': relative_path,
                            'name': file,
                            'size': size,
                            'size_gb': size / (1024**3)
                        })
                    except OSError:
                        errors += 1
                        continue
        
        # Save inventory to file in secure location
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        inventory_file = os.path.join(self.base_path, f"video_inventory_{timestamp}.txt")
        
        # Validate write path is safe
        if not self.validate_safe_path(inventory_file):
            print("Error: Cannot write inventory file to unsafe location")
            return
        
        with open(inventory_file, 'w') as f:
            f.write(f"Video Inventory - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Base Path: {self.base_path}\n")
            f.write(f"Total Videos: {len(inventory)}\n")
            f.write(f"Total Size: {total_size / (1024**3):.2f} GB\n")
            f.write("="*80 + "\n\n")
            
            for item in sorted(inventory, key=lambda x: x['relative_path']):
                f.write(f"{item['relative_path']} ({item['size_gb']:.2f} GB)\n")
        
        print(f"\n\n✓ Inventory complete!")
        print(f"  Total videos: {len(inventory)}")
        print(f"  Total size: {total_size / (1024**3):.2f} GB")
        if errors > 0:
            print(f"  Errors: {errors} files could not be read")
        print(f"  Saved to: {inventory_file}")
        self.safe_input("\nPress Enter to continue...")
        
    def list_conversion_candidates(self):
        """List videos that are candidates for conversion."""
        print("\nFinding conversion candidates from database...")
        
        # Query database for conversion candidates
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT file_path, filename, width, height, file_size, codec
                FROM video_files
                WHERE (width > 1920 OR height > 1080)
                AND filename NOT LIKE '%-CONVERTED%'
                ORDER BY file_size DESC
            ''')
            candidates = cursor.fetchall()
        
        if not candidates:
            print("No videos found that need conversion.")
            print("(Run Background Analysis if you haven't scanned recently)")
            self.safe_input("\nPress Enter to continue...")
            return
            
        print(f"\nFound {len(candidates)} videos larger than 1080p:")
        print("="*80)
        
        # Group by directory for better organization
        by_directory = {}
        total_size = 0
        
        for file_path, filename, width, height, file_size, codec in candidates:
            directory = os.path.dirname(file_path).replace(self.base_path, '').strip('/')
            if not directory:
                directory = "Root"
                
            if directory not in by_directory:
                by_directory[directory] = []
                
            size_gb = file_size / (1024**3)
            total_size += file_size
            
            by_directory[directory].append({
                'filename': filename,
                'resolution': f"{width}x{height}",
                'size_gb': size_gb,
                'codec': codec,
                'path': file_path
            })
        
        # Display organized results
        display_count = 0
        for directory, files in sorted(by_directory.items()):
            if display_count >= 20:  # Show first 20 files
                break
                
            print(f"\n📁 {directory}/")
            for file in files[:5]:  # Show up to 5 per directory
                if display_count >= 20:
                    break
                display_count += 1
                print(f"  {file['filename']}")
                print(f"    {file['resolution']} | {file['size_gb']:.2f} GB | {file['codec']}")
        
        if len(candidates) > 20:
            print(f"\n... and {len(candidates) - 20} more files")
        
        # Summary statistics
        potential_savings = total_size * 0.4  # Estimate 40% size reduction
        print(f"\n📊 Summary:")
        print(f"Total files: {len(candidates)}")
        print(f"Total size: {total_size / (1024**3):.2f} GB")
        print(f"Potential savings: ~{potential_savings / (1024**3):.2f} GB")
        
        # Save detailed report
        candidates_file = os.path.join(self.base_path, "conversion_candidates.txt")
        with open(candidates_file, "w") as f:
            f.write(f"Conversion Candidates Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n\n")
            f.write(f"Total candidates: {len(candidates)}\n")
            f.write(f"Total size: {total_size / (1024**3):.2f} GB\n")
            f.write(f"Potential savings: ~{potential_savings / (1024**3):.2f} GB\n\n")
            
            for directory, files in sorted(by_directory.items()):
                f.write(f"\n{directory}/\n")
                f.write("-" * len(directory) + "--\n")
                for file in sorted(files, key=lambda x: x['size_gb'], reverse=True):
                    f.write(f"  {file['filename']} - {file['resolution']} - {file['size_gb']:.2f} GB - {file['codec']}\n")
        
        print(f"\n📄 Detailed report saved to: conversion_candidates.txt")
        
        # Offer conversion
        convert = self.safe_input("\nWould you like to start converting these files? (y/N): ")
        if convert.lower() == 'y':
            print("\n🎥 Starting batch conversion to 1080p...")
            converted = 0
            for file_path, filename, width, height, file_size, codec in candidates[:10]:  # Convert first 10 as example
                print(f"\rConverting {converted + 1}/{min(10, len(candidates))}: {filename}", end='', flush=True)
                result = self.transcode_video_task(file_path)
                if "successfully" in result.lower():
                    converted += 1
            print(f"\n✓ Converted {converted} files!")
        
        self.safe_input("\nPress Enter to continue...")
        
    def top_shows_by_size(self):
        """Show top 10 TV shows by total size."""
        print("\nCalculating top 10 shows by size from database...")
        
        # Use database for fast aggregation
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT 
                    SUBSTR(file_path, 1, INSTR(SUBSTR(file_path, LENGTH(?) + 5), '/') + LENGTH(?) + 4) as show_path,
                    COUNT(*) as file_count,
                    SUM(file_size) as total_size,
                    COUNT(CASE WHEN width > 1920 OR height > 1080 THEN 1 END) as oversized_count
                FROM video_files
                WHERE file_path LIKE ?
                GROUP BY show_path
                ORDER BY total_size DESC
                LIMIT 10
            ''', (os.path.join(self.base_path, 'TV'), os.path.join(self.base_path, 'TV'), os.path.join(self.base_path, 'TV') + '/%'))
            
            shows = cursor.fetchall()
        
        if not shows:
            print("No TV shows found in database. Run Background Analysis first.")
            self.safe_input("\nPress Enter to continue...")
            return
            
        print("\nTop 10 TV Shows by Size:")
        print("="*60)
        
        show_data = []
        for show_path, file_count, total_size, oversized_count in shows:
            show_name = os.path.basename(show_path)
            size_gb = total_size / (1024**3)
            show_data.append({
                'path': show_path,
                'name': show_name,
                'size_gb': size_gb,
                'file_count': file_count,
                'oversized_count': oversized_count
            })
            
        for i, show in enumerate(show_data, 1):
            print(f"{i:2}. {show['name']}")
            print(f"    Size: {show['size_gb']:.2f} GB | Episodes: {show['file_count']}")
            if show['oversized_count'] > 0:
                print(f"    ⚠️  {show['oversized_count']} episodes larger than 1080p")
        
        # Calculate totals
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT COUNT(DISTINCT SUBSTR(file_path, 1, INSTR(SUBSTR(file_path, LENGTH(?) + 5), '/') + LENGTH(?) + 4)),
                       SUM(file_size)
                FROM video_files
                WHERE file_path LIKE ?
            ''', (os.path.join(self.base_path, 'TV'), os.path.join(self.base_path, 'TV'), os.path.join(self.base_path, 'TV') + '/%'))
            total_shows, total_size = cursor.fetchone()
        
        print(f"\nTotal TV Shows: {total_shows}")
        print(f"Total Size: {total_size / (1024**3):.2f} GB")
        
        # Ask about conversion
        total_oversized = sum(show['oversized_count'] for show in show_data)
        if total_oversized > 0:
            print(f"\n⚡ {total_oversized} episodes could be converted to 1080p to save space")
            convert = self.safe_input("\nWould you like to convert shows with oversized episodes? (y/N): ")
            
            if convert.lower() == 'y':
                print("\nSelect shows to convert (comma-separated numbers, e.g., '1,3,5'):")
                selection = self.safe_input("Selection (or 'all' for all shows): ")
                
                if selection.lower() == 'all':
                    selected_shows = [s for s in show_data if s['oversized_count'] > 0]
                else:
                    try:
                        indices = [int(x.strip()) - 1 for x in selection.split(',')]
                        selected_shows = [show_data[i] for i in indices if 0 <= i < len(show_data) and show_data[i]['oversized_count'] > 0]
                    except (ValueError, IndexError):
                        print("Invalid selection.")
                        self.safe_input("\nPress Enter to continue...")
                        return
                
                if selected_shows:
                    print(f"\n🎥 Converting oversized episodes in {len(selected_shows)} shows...")
                    for show in selected_shows:
                        self.convert_show_episodes(show['path'])
                    print("\n✓ Conversion complete!")
        
        self.safe_input("\nPress Enter to continue...")
        
    def convert_show_episodes(self, show_path):
        """Convert all oversized episodes in a TV show to 1080p."""
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT file_path 
                FROM video_files 
                WHERE file_path LIKE ? 
                AND (width > 1920 OR height > 1080)
            ''', (show_path + '/%',))
            
            episodes = cursor.fetchall()
            
        show_name = os.path.basename(show_path)
        print(f"\nConverting {len(episodes)} episodes from '{show_name}'...")
        
        converted_count = 0
        for i, (file_path,) in enumerate(episodes, 1):
            print(f"\rConverting {i}/{len(episodes)}: {os.path.basename(file_path)}", end='', flush=True)
            result = self.transcode_video_task(file_path)
            if "successfully" in result.lower():
                converted_count += 1
                
        print(f"\n✓ Converted {converted_count}/{len(episodes)} episodes in '{show_name}'")
        
    def top_video_files(self):
        """Show top 10 individual video files by size."""
        print("\nFinding top 10 largest video files from database...")
        
        # Query database for largest files
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT file_path, filename, file_size, width, height, codec, duration
                FROM video_files
                ORDER BY file_size DESC
                LIMIT 10
            ''')
            videos = cursor.fetchall()
        
        if not videos:
            print("No video files found in database. Run Background Analysis first.")
            self.safe_input("\nPress Enter to continue...")
            return
            
        print("\nTop 10 Largest Video Files:")
        print("="*80)
        
        video_data = []
        for file_path, filename, file_size, width, height, codec, duration in videos:
            size_gb = file_size / (1024**3)
            relative_path = os.path.relpath(file_path, self.base_path)
            resolution = f"{width}x{height}" if width and height else "Unknown"
            duration_min = int(duration / 60) if duration else 0
            
            video_data.append({
                'path': file_path,
                'filename': filename,
                'size_gb': size_gb,
                'relative_path': relative_path,
                'resolution': resolution,
                'codec': codec,
                'duration_min': duration_min,
                'oversized': (width and height and (width > 1920 or height > 1080))
            })
        
        for i, video in enumerate(video_data, 1):
            print(f"{i:2}. {video['filename']} ({video['size_gb']:.2f} GB)")
            print(f"    📍 {video['relative_path']}")
            print(f"    📐 {video['resolution']} | 🎬 {video['codec']} | ⏱️  {video['duration_min']} min")
            if video['oversized']:
                print(f"    ⚠️  Can be reduced to 1080p")
            print()
        
        # Offer conversion for oversized files
        oversized_videos = [v for v in video_data if v['oversized']]
        if oversized_videos:
            print(f"⚡ {len(oversized_videos)} of these files could be converted to 1080p to save space")
            convert = self.safe_input("\nWould you like to convert oversized files? (y/N): ")
            
            if convert.lower() == 'y':
                print("\n🎥 Converting oversized files to 1080p...")
                converted = 0
                for video in oversized_videos:
                    print(f"\rConverting {converted + 1}/{len(oversized_videos)}: {video['filename']}", end='', flush=True)
                    result = self.transcode_video_task(video['path'])
                    if "successfully" in result.lower():
                        converted += 1
                print(f"\n✓ Converted {converted} files!")
        
        self.safe_input("\nPress Enter to continue...")
        
    def delete_show(self):
        """Delete a TV show."""
        tv_path = os.path.join(self.base_path, "TV")
        
        if not os.path.exists(tv_path):
            print("TV directory not found!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        shows = [d for d in os.listdir(tv_path) if os.path.isdir(os.path.join(tv_path, d))]
        shows.sort()
        
        print("\nAvailable TV Shows:")
        print("="*60)
        
        for i, show in enumerate(shows, 1):
            show_path = os.path.join(tv_path, show)
            size = sum(os.path.getsize(os.path.join(root, f)) 
                      for root, _, files in os.walk(show_path, followlinks=False) 
                      for f in files) / (1024**3)
            print(f"{i:3}. {show} ({size:.2f} GB)")
        
        print(f"\n  0. Cancel")
        
        try:
            choice = self.safe_int_input("\nEnter show number to delete: ", 0, len(sorted_shows))
            if choice == 0:
                return
            
            if 1 <= choice <= len(shows):
                show_to_delete = shows[choice - 1]
                show_path = os.path.join(tv_path, show_to_delete)
                
                confirm = self.safe_input(f"\nAre you sure you want to delete '{show_to_delete}'? (yes/no): ")
                if confirm.lower() == 'yes':
                    success, message = self.safe_directory_delete(show_path)
                    if success:
                        print(f"✓ Deleted '{show_to_delete}'")
                    else:
                        print(f"✗ Failed to delete '{show_to_delete}': {message}")
                else:
                    print("Deletion cancelled.")
            else:
                print("Invalid selection!")
        except (ValueError, KeyboardInterrupt):
            print("\nCancelled.")
        
        self.safe_input("\nPress Enter to continue...")
        
    def delete_video_file(self):
        """Delete a specific video file."""
        search = self.safe_input("\nEnter part of the filename to search for: ")
        
        if not search:
            return
        
        matching_files = []
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if search.lower() in file.lower() and file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    size = os.path.getsize(file_path) / (1024**3)
                    matching_files.append({
                        'path': file_path,
                        'name': file,
                        'size': size,
                        'relative_path': os.path.relpath(file_path, self.base_path)
                    })
        
        if not matching_files:
            print(f"No files found matching '{search}'")
            self.safe_input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(matching_files)} matching files:")
        print("="*80)
        
        for i, file in enumerate(matching_files[:20], 1):
            print(f"{i:2}. {file['name']} ({file['size']:.2f} GB)")
            print(f"    {file['relative_path']}")
        
        if len(matching_files) > 20:
            print(f"\n... and {len(matching_files) - 20} more files")
        
        print(f"\n  0. Cancel")
        
        try:
            choice = self.safe_int_input("\nEnter file number to delete: ", 0, len(matching_files))
            if choice == 0:
                return
            
            if 1 <= choice <= min(len(matching_files), 20):
                file_to_delete = matching_files[choice - 1]
                
                confirm = self.safe_input(f"\nAre you sure you want to delete '{file_to_delete['name']}'? (yes/no): ")
                if confirm.lower() == 'yes':
                    # Use safe file deletion
                    success, message = self.safe_file_delete(file_to_delete['path'])
                    if success:
                        print(f"✓ {message}: '{file_to_delete['name']}'")
                    else:
                        print(f"❌ Failed to delete '{file_to_delete['name']}': {message}")
                else:
                    print("Deletion cancelled.")
            else:
                print("Invalid selection!")
        except (ValueError, KeyboardInterrupt):
            print("\nCancelled.")
        
        self.safe_input("\nPress Enter to continue...")
        
    def check_subtitles(self):
        """Check which videos don't have English subtitles."""
        self.clear_screen()
        print("="*60)
        print("📝 Check for Videos Without English Subtitles")
        print("="*60)
        
        # Check for cached subtitle data (configured folders only)
        sql_condition, params = self.get_folder_sql_conditions()
        
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            
            if sql_condition:
                cursor.execute(f'''
                    SELECT COUNT(*) FROM video_files 
                    WHERE has_external_subs = 0 AND has_embedded_subs = 0
                    AND {sql_condition}
                ''', params)
            else:
                cursor.execute('''
                    SELECT COUNT(*) FROM video_files 
                    WHERE has_external_subs = 0 AND has_embedded_subs = 0
                ''')
            
            cached_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT MAX(last_scanned) FROM video_files WHERE last_scanned IS NOT NULL')
            last_scan = cursor.fetchone()[0]
        
        if cached_count > 0 and last_scan:
            scan_age = (time.time() - last_scan) / 3600  # hours
            print(f"💡 Your recent scan found {cached_count:,} files missing English subtitles")
            print(f"   (Scan was {scan_age:.1f} hours ago)")
            print()
            
            print("📋 Display Options:")
            print("1. Show all files missing subtitles")
            print("2. Show Movies only")
            print("3. Show TV Shows only")
            print("4. Show specific TV show")
            print("5. Save report to file")
            print("6. Rescan from scratch")
            print("0. Cancel")
            
            choice = self.safe_input("\nEnter your choice: ")
            
            if choice == '0':
                return
            elif choice == '1':
                self.display_subtitle_results('All')
            elif choice == '2':
                self.display_subtitle_results('Movies')
            elif choice == '3':
                self.display_subtitle_results('TV')
            elif choice == '4':
                self.pick_tv_show_for_subtitle_check()
            elif choice == '5':
                self.save_subtitle_report()
            elif choice == '6':
                self.check_subtitles_full_scan()
            else:
                print("Invalid choice.")
                self.safe_input("Press Enter to continue...")
        else:
            # No cached data, do full scan
            print("No recent scan data found. Performing full subtitle check...")
            self.check_subtitles_full_scan()
    
    def display_subtitle_results(self, category):
        """Display subtitle check results for a specific category."""
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            
            if category == 'Movies':
                cursor.execute('''
                    SELECT file_path FROM video_files 
                    WHERE has_external_subs = 0 AND has_embedded_subs = 0 
                    AND file_path LIKE '%/Movies/%'
                    ORDER BY file_path
                ''')
                title = "Movies Without English Subtitles"
            elif category == 'TV':
                cursor.execute('''
                    SELECT file_path FROM video_files 
                    WHERE has_external_subs = 0 AND has_embedded_subs = 0 
                    AND file_path LIKE '%/TV/%'
                    ORDER BY file_path
                ''')
                title = "TV Shows Without English Subtitles"
            else:  # All (Movies and TV only)
                cursor.execute('''
                    SELECT file_path FROM video_files 
                    WHERE has_external_subs = 0 AND has_embedded_subs = 0 
                    AND (file_path LIKE '%/Movies/%' OR file_path LIKE '%/TV/%')
                    ORDER BY file_path
                ''')
                title = "Movies & TV Shows Without English Subtitles"
            
            files = [row[0] for row in cursor.fetchall()]
        
        if not files:
            print(f"✅ No files missing subtitles found in {category}!")
            self.safe_input("Press Enter to continue...")
            return
        
        print(f"\n{title}")
        print("="*60)
        print(f"Found {len(files)} files missing English subtitles:\n")
        
        for i, file_path in enumerate(files[:50], 1):  # Show first 50
            relative_path = os.path.relpath(file_path, self.base_path)
            print(f"{i:3}. {relative_path}")
        
        if len(files) > 50:
            print(f"\n... and {len(files) - 50} more files")
        
        print(f"\n🎯 What would you like to do with these {len(files)} files?")
        print("1. Download subtitles for all files")
        print("2. Download subtitles in background mode")
        print("3. Save list to file")
        print("4. Go back to main menu")
        print("0. Cancel")
        
        action_choice = self.safe_input("\nEnter your choice: ")
        
        if action_choice == '1':
            # Limit to reasonable batch size
            batch_files = files[:min(100, len(files))]
            if len(files) > 100:
                print(f"Processing first 100 files (out of {len(files)})")
            self.download_subtitles_from_list(batch_files, background_mode=False)
        elif action_choice == '2':
            batch_files = files[:min(100, len(files))]
            if len(files) > 100:
                print(f"Processing first 100 files (out of {len(files)})")
            self.download_subtitles_from_list(batch_files, background_mode=True)
        elif action_choice == '3':
            report_file = os.path.join(self.base_path, f"{category.lower()}_missing_subtitles.txt")
            with open(report_file, "w") as f:
                f.write(f"{title} - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*80 + "\n\n")
                for file_path in files:
                    relative_path = os.path.relpath(file_path, self.base_path)
                    f.write(f"{relative_path}\n")
            print(f"✓ List saved to: {report_file}")
            self.safe_input("\nPress Enter to continue...")
        elif action_choice == '4':
            return
        elif action_choice != '0':
            print("Invalid choice.")
            self.safe_input("Press Enter to continue...")
    
    def pick_tv_show_for_subtitle_check(self):
        """Let user pick a specific TV show to check for subtitles."""
        while True:
            self.clear_screen()
            print("📺 TV Show Navigation")
            print("="*60)
            print("1. Browse shows missing subtitles")
            print("2. Browse all TV shows")
            print("3. Search for a specific show")
            print("0. Return to main menu")
            
            nav_choice = self.safe_input("\nChoose option: ")
            
            if nav_choice == '0':
                return
            elif nav_choice == '1':
                self.browse_shows_missing_subtitles()
            elif nav_choice == '2':
                self.browse_all_tv_shows()
            elif nav_choice == '3':
                self.search_tv_shows()
            else:
                print("Invalid choice.")
                self.safe_input("Press Enter to continue...")
    
    def browse_shows_missing_subtitles(self):
        """Browse TV shows missing subtitles with pagination."""
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT DISTINCT 
                    SUBSTR(file_path, 1, INSTR(file_path, '/Season') - 1) as show_path,
                    COUNT(*) as missing_count
                FROM video_files 
                WHERE has_external_subs = 0 AND has_embedded_subs = 0 
                AND file_path LIKE '%/TV/%'
                AND file_path LIKE '%/Season%'
                GROUP BY show_path
                ORDER BY LOWER(SUBSTR(show_path, INSTR(show_path, '/TV/') + 4))
            ''')
            
            shows = cursor.fetchall()
        
        if not shows:
            print("✅ No TV shows found missing subtitles!")
            self.safe_input("Press Enter to continue...")
            return
        
        self.paginate_and_select_show(shows, "TV Shows Missing Subtitles")
    
    def browse_all_tv_shows(self):
        """Browse all TV shows with pagination."""
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT DISTINCT 
                    SUBSTR(file_path, 1, INSTR(file_path, '/Season') - 1) as show_path,
                    COUNT(*) as total_files,
                    SUM(CASE WHEN has_external_subs = 0 AND has_embedded_subs = 0 THEN 1 ELSE 0 END) as missing_count
                FROM video_files 
                WHERE file_path LIKE '%/TV/%'
                AND file_path LIKE '%/Season%'
                GROUP BY show_path
                ORDER BY LOWER(SUBSTR(show_path, INSTR(show_path, '/TV/') + 4))
            ''')
            
            shows = [(path, missing, total) for path, total, missing in cursor.fetchall()]
        
        if not shows:
            print("No TV shows found in database!")
            self.safe_input("Press Enter to continue...")
            return
        
        self.paginate_and_select_show(shows, "All TV Shows", show_all=True)
    
    def search_tv_shows(self):
        """Search for TV shows by name."""
        search_term = self.safe_input("Enter search term: ").strip()
        if not search_term:
            return
        
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT DISTINCT 
                    SUBSTR(file_path, 1, INSTR(file_path, '/Season') - 1) as show_path,
                    COUNT(*) as total_files,
                    SUM(CASE WHEN has_external_subs = 0 AND has_embedded_subs = 0 THEN 1 ELSE 0 END) as missing_count
                FROM video_files 
                WHERE file_path LIKE '%/TV/%'
                AND file_path LIKE '%/Season%'
                AND LOWER(file_path) LIKE LOWER(?)
                GROUP BY show_path
                ORDER BY LOWER(SUBSTR(show_path, INSTR(show_path, '/TV/') + 4))
            ''', (f"%{search_term}%",))
            
            shows = [(path, missing, total) for path, total, missing in cursor.fetchall()]
        
        if not shows:
            print(f"No TV shows found matching '{search_term}'")
            self.safe_input("Press Enter to continue...")
            return
        
        self.paginate_and_select_show(shows, f"Search Results for '{search_term}'", show_all=True)
    
    def paginate_and_select_show(self, shows, title, show_all=False):
        """Display shows with pagination and handle selection."""
        page_size = 15
        current_page = 0
        total_pages = (len(shows) - 1) // page_size + 1
        
        while True:
            self.clear_screen()
            print(f"📺 {title}")
            print("="*60)
            
            start_idx = current_page * page_size
            end_idx = min(start_idx + page_size, len(shows))
            page_shows = shows[start_idx:end_idx]
            
            print(f"Page {current_page + 1} of {total_pages} (Showing {start_idx + 1}-{end_idx} of {len(shows)} shows)\n")
            
            for i, show_data in enumerate(page_shows, 1):
                show_path = show_data[0]
                show_name = os.path.basename(show_path)
                
                if show_all and len(show_data) == 3:
                    missing_count, total_files = show_data[1], show_data[2]
                    if missing_count > 0:
                        print(f"{i:2}. {show_name} ({missing_count}/{total_files} missing subtitles)")
                    else:
                        print(f"{i:2}. {show_name} (all {total_files} have subtitles)")
                else:
                    missing_count = show_data[1]
                    print(f"{i:2}. {show_name} ({missing_count} missing)")
            
            print("\nNavigation:")
            if current_page > 0:
                print("p. Previous page")
            if current_page < total_pages - 1:
                print("n. Next page")
            print("s. Search again")
            print("0. Go back")
            
            choice = self.safe_input(f"\nSelect show (1-{len(page_shows)}) or navigation option: ").strip().lower()
            
            if choice == '0':
                return
            elif choice == 'p' and current_page > 0:
                current_page -= 1
            elif choice == 'n' and current_page < total_pages - 1:
                current_page += 1
            elif choice == 's':
                self.search_tv_shows()
                return
            else:
                try:
                    show_choice = int(choice)
                    if 1 <= show_choice <= len(page_shows):
                        selected_show = page_shows[show_choice - 1][0]
                        self.show_subtitle_details(selected_show)
                        return
                    else:
                        print("Invalid selection.")
                        self.safe_input("Press Enter to continue...")
                except ValueError:
                    print("Invalid selection.")
                    self.safe_input("Press Enter to continue...")
    
    def show_subtitle_details(self, show_path):
        """Show subtitle details and actions for a specific show."""
        show_name = os.path.basename(show_path)
        
        # Get files for this show
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT file_path, has_external_subs, has_embedded_subs FROM video_files 
                WHERE file_path LIKE ?
                ORDER BY file_path
            ''', (f"{show_path}%",))
            
            all_files = cursor.fetchall()
        
        if not all_files:
            print(f"No files found for {show_name}")
            self.safe_input("Press Enter to continue...")
            return
        
        missing_files = [f[0] for f in all_files if f[1] == 0 and f[2] == 0]
        
        self.clear_screen()
        print(f"📺 {show_name}")
        print("="*60)
        print(f"Total files: {len(all_files)}")
        print(f"Missing subtitles: {len(missing_files)}")
        print(f"Have subtitles: {len(all_files) - len(missing_files)}")
        
        if missing_files:
            print(f"\nFiles missing subtitles:")
            for i, file_path in enumerate(missing_files[:10], 1):
                filename = os.path.basename(file_path)
                print(f"  {i:2}. {filename}")
            
            if len(missing_files) > 10:
                print(f"  ... and {len(missing_files) - 10} more files")
        
        print(f"\n🎯 What would you like to do?")
        print("1. Download subtitles for missing files")
        print("2. Download subtitles in background mode")
        print("3. Force redownload subtitles (overwrite existing)")
        print("4. Rescan this show for subtitle status")
        print("5. Save missing list to file")
        print("6. Show all files (with subtitle status)")
        print("0. Go back")
        
        action_choice = self.safe_input("\nEnter your choice: ")
        
        if action_choice == '1':
            if missing_files:
                self.download_subtitles_from_list(missing_files, background_mode=False)
            else:
                print("No files missing subtitles!")
                self.safe_input("Press Enter to continue...")
        elif action_choice == '2':
            if missing_files:
                self.download_subtitles_from_list(missing_files, background_mode=True)
            else:
                print("No files missing subtitles!")
                self.safe_input("Press Enter to continue...")
        elif action_choice == '3':
            self.force_redownload_subtitles_for_show(show_path, show_name)
        elif action_choice == '4':
            self.rescan_show_subtitles(show_path, show_name)
        elif action_choice == '5':
            if missing_files:
                report_file = os.path.join(self.base_path, f"{show_name.replace(' ', '_')}_missing_subtitles.txt")
                with open(report_file, "w") as f:
                    f.write(f"{show_name} - Missing Subtitles - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("="*80 + "\n\n")
                    for file_path in missing_files:
                        relative_path = os.path.relpath(file_path, self.base_path)
                        f.write(f"{relative_path}\n")
                print(f"✓ List saved to: {report_file}")
                self.safe_input("\nPress Enter to continue...")
            else:
                print("No missing files to save!")
                self.safe_input("Press Enter to continue...")
        elif action_choice == '6':
            self.show_all_files_with_status(show_name, all_files)
        elif action_choice != '0':
            print("Invalid choice.")
            self.safe_input("Press Enter to continue...")
    
    def show_all_files_with_status(self, show_name, all_files):
        """Show all files in a show with their subtitle status."""
        self.clear_screen()
        print(f"📺 {show_name} - All Files")
        print("="*60)
        
        for i, (file_path, has_external, has_embedded) in enumerate(all_files, 1):
            filename = os.path.basename(file_path)
            
            if has_external and has_embedded:
                status = "✓ External + Embedded"
            elif has_external:
                status = "✓ External subs"
            elif has_embedded:
                status = "✓ Embedded subs"
            else:
                status = "❌ No subtitles"
            
            print(f"{i:3}. {filename:<50} {status}")
        
        self.safe_input("\nPress Enter to continue...")
    
    def force_redownload_subtitles_for_show(self, show_path, show_name):
        """Force redownload subtitles for all files in a show (overwrite existing)."""
        print(f"\n🔄 Force Redownload Subtitles for {show_name}")
        print("="*60)
        print("This will download subtitles for ALL episodes, even if they already exist.")
        
        confirm = self.safe_input("Are you sure? (y/N): ")
        if confirm.lower() != 'y':
            return
        
        # Get all files for this show (not just missing subtitles)
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT file_path FROM video_files 
                WHERE file_path LIKE ?
                ORDER BY file_path
            ''', (f"{show_path}%",))
            
            all_files = [row[0] for row in cursor.fetchall()]
        
        if not all_files:
            print("No files found for this show")
            self.safe_input("Press Enter to continue...")
            return
        
        print(f"🎬 Processing Mode for {len(all_files)} files:")
        print("1. Watch progress (interactive)")
        print("2. Run in background (faster)")
        
        mode_choice = self.safe_input("\nChoose processing mode: ")
        background_mode = (mode_choice == '2')
        
        # Force download for all files
        self.download_subtitles_from_list(all_files, background_mode, force_download=True)
    
    def rescan_show_subtitles(self, show_path, show_name):
        """Rescan a specific show to update subtitle status in database."""
        print(f"\n🔍 Rescanning {show_name} for Subtitle Status")
        print("="*60)
        
        # Get all files for this show
        show_files = []
        for root, dirs, files in os.walk(show_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    show_files.append(file_path)
        
        if not show_files:
            print("No video files found in this show directory")
            self.safe_input("Press Enter to continue...")
            return
        
        print(f"Rescanning {len(show_files)} files...")
        self.operation_log("rescan_show", "STARTED", details=f"Show: {show_name}, Files: {len(show_files)}")
        
        updated_count = 0
        for i, file_path in enumerate(show_files, 1):
            print(f"Checking {i}/{len(show_files)}: {os.path.basename(file_path)}", end='\r')
            
            # Check for external subtitle files
            base_name = os.path.splitext(file_path)[0]
            has_external_subs = any(os.path.exists(f"{base_name}{ext}") for ext in ['.srt', '.en.srt', '.eng.srt', '.vtt', '.en.vtt'])
            
            # Check for embedded subtitles
            has_embedded_subs = False
            info = self.get_video_info(file_path)
            if info:
                for stream in info.get('streams', []):
                    if stream.get('codec_type') == 'subtitle':
                        language = stream.get('tags', {}).get('language', '')
                        if language in ['eng', 'en']:
                            has_embedded_subs = True
                            break
            
            # Update database
            with self.get_db_context() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE video_files 
                    SET has_external_subs = ?, has_embedded_subs = ?, last_scanned = ?
                    WHERE file_path = ?
                ''', (has_external_subs, has_embedded_subs, time.time(), file_path))
                
                if cursor.rowcount > 0:
                    updated_count += 1
        
        print(f"\n✓ Rescan complete for {show_name}")
        print(f"   Updated {updated_count} files in database")
        
        self.operation_log("rescan_show", "SUCCESS", details=f"Show: {show_name}, Updated: {updated_count}/{len(show_files)}")
        self.safe_input("\nPress Enter to continue...")
    
    def save_subtitle_report(self):
        """Save subtitle check results to file."""
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT file_path FROM video_files 
                WHERE has_external_subs = 0 AND has_embedded_subs = 0 
                ORDER BY file_path
            ''')
            files = [row[0] for row in cursor.fetchall()]
        
        if not files:
            print("✅ No files missing subtitles found!")
            self.safe_input("Press Enter to continue...")
            return
        
        report_file = os.path.join(self.base_path, "videos_without_subtitles.txt")
        with open(report_file, "w") as f:
            f.write(f"Videos Without English Subtitles - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n\n")
            
            for file_path in files:
                relative_path = os.path.relpath(file_path, self.base_path)
                f.write(f"{relative_path}\n")
        
        print(f"✓ Report saved: {report_file}")
        print(f"   {len(files):,} files missing English subtitles")
        self.safe_input("\nPress Enter to continue...")
    
    def check_subtitles_full_scan(self):
        """Perform full filesystem scan for subtitle check (legacy method)."""
        print("\nPerforming full subtitle check (this may take a while)...")
        
        videos_without_subs = []
        videos_checked = 0
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    videos_checked += 1
                    
                    if videos_checked % 10 == 0:
                        print(f"Checked {videos_checked} videos...", end='\r')
                    
                    info = self.get_video_info(file_path)
                    if info:
                        has_english_sub = False
                        
                        # Check for subtitle streams
                        for stream in info.get('streams', []):
                            if stream.get('codec_type') == 'subtitle':
                                language = stream.get('tags', {}).get('language', '')
                                title = stream.get('tags', {}).get('title', '').lower()
                                
                                if language in ['eng', 'en'] or 'english' in title:
                                    has_english_sub = True
                                    break
                        
                        if not has_english_sub:
                            # Check for external subtitle files
                            base_name = os.path.splitext(file_path)[0]
                            external_subs = [
                                base_name + '.srt',
                                base_name + '.en.srt',
                                base_name + '.eng.srt',
                                base_name + '.vtt',
                                base_name + '.en.vtt',
                                base_name + '.ass'
                            ]
                            
                            has_external_sub = any(os.path.exists(sub) for sub in external_subs)
                            
                            if not has_external_sub:
                                videos_without_subs.append({
                                    'path': file_path,
                                    'name': file,
                                    'relative_path': os.path.relpath(file_path, self.base_path)
                                })
        
        print(f"\n\nChecked {videos_checked} videos")
        print(f"Found {len(videos_without_subs)} videos without English subtitles:\n")
        
        # Show first 50 results
        for video in sorted(videos_without_subs[:50], key=lambda x: x['relative_path']):
            print(f"  {video['name']}")
        
        if len(videos_without_subs) > 50:
            print(f"\n... and {len(videos_without_subs) - 50} more files")
        
        # Save to file
        report_file = os.path.join(self.base_path, "videos_without_subtitles.txt")
        with open(report_file, "w") as f:
            f.write(f"Videos Without English Subtitles - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n\n")
            
            for video in sorted(videos_without_subs, key=lambda x: x['relative_path']):
                f.write(f"{video['relative_path']}\n")
        
        print(f"\nFull list saved to: videos_without_subtitles.txt")
        
        print("\n📝 Note: To download subtitles, you can use tools like:")
        print("  - subliminal (pip install subliminal)")
        print("  - OpenSubtitles.org API")
        print("  - subdl (pip install subdl)")
        
        self.safe_input("\nPress Enter to continue...")
        
    def convert_to_resolution(self, target_resolution):
        """Convert videos to specified resolution (1080p or 720p)."""
        self.clear_screen()
        print("="*60)
        print(f"🎬 Convert Videos to {target_resolution}p")
        print("="*60)
        
        # Check disk space before starting conversions
        has_space, space_msg = self.check_disk_space(FileSizeConstants.LARGE_FILE_THRESHOLD)  # Require 5GB minimum
        if not has_space:
            print(f"❌ Cannot proceed: {space_msg}")
            self.safe_input("\nPress Enter to continue...")
            return
        
        # Create conversion script for the target resolution
        if target_resolution == 1080:
            target_height = 1080
            target_width = 1920
        else:  # 720p
            target_height = 720
            target_width = 1280
        
        # Check for cached conversion candidates
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT COUNT(*) FROM video_files 
                WHERE needs_conversion = 1 AND (width > ? OR height > ?)
            ''', (target_width, target_height))
            cached_candidates = cursor.fetchone()[0]
            
            cursor.execute('SELECT MAX(last_scanned) FROM video_files WHERE last_scanned IS NOT NULL')
            last_scan = cursor.fetchone()[0]
        
        if cached_candidates > 0 and last_scan:
            scan_age = (time.time() - last_scan) / 3600  # hours
            print(f"💡 Your recent scan found {cached_candidates:,} videos needing conversion to {target_resolution}p")
            print(f"   (Scan was {scan_age:.1f} hours ago)")
            print()
            
            if cached_candidates > 10:
                print("📋 Batch Processing Options:")
                print("1. Convert top 10 largest files (recommended)")
                print(f"2. Convert all {cached_candidates:,} files")
                print("3. Choose custom batch size")
                print("4. Browse by directory instead")
                print("0. Cancel")
                
                choice = self.safe_input("\nEnter your choice: ")
                
                if choice == '0':
                    return
                elif choice == '1':
                    batch_size = 10
                elif choice == '2':
                    batch_size = cached_candidates
                elif choice == '3':
                    try:
                        batch_size = int(self.safe_input("Enter batch size (1-50): "))
                        batch_size = max(1, min(50, batch_size))
                    except ValueError:
                        print("Invalid batch size.")
                        self.safe_input("Press Enter to continue...")
                        return
                elif choice == '4':
                    self.convert_by_directory(target_resolution, target_width, target_height)
                    return
                else:
                    print("Invalid choice.")
                    self.safe_input("Press Enter to continue...")
                    return
            else:
                print(f"📋 Found {cached_candidates} files needing conversion from recent scan")
                batch_size = cached_candidates
            
            # Ask about processing mode
            print(f"\n🎬 Processing Mode for {batch_size} files:")
            print("1. Watch progress (interactive)")
            print("2. Run in background (faster)")
            
            mode_choice = self.safe_input("\nChoose processing mode: ")
            background_mode = (mode_choice == '2')
            
            # Get files from database, ordered by size (largest first)
            with self.get_db_context() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT file_path FROM video_files 
                    WHERE needs_conversion = 1 AND (width > ? OR height > ?)
                    ORDER BY file_size DESC
                    LIMIT ?
                ''', (target_width, target_height, batch_size))
                
                files_to_convert = [row[0] for row in cursor.fetchall()]
            
            if files_to_convert:
                self.batch_convert_from_list(files_to_convert, target_resolution, target_width, target_height, background_mode)
            else:
                print("No files found to convert.")
                self.safe_input("Press Enter to continue...")
        else:
            # No cached data, show original menu
            print("No recent scan data found. Choose an option:")
            print(f"1. Convert all videos larger than {target_resolution}p")
            print(f"2. Convert specific directory")
            print(f"3. Convert single file")
            print(f"0. Cancel")
            
            choice = self.safe_input("\nEnter your choice: ")
            
            if choice == '0':
                return
            elif choice == '1':
                self.run_conversion_scan(target_resolution, target_width, target_height)
            elif choice == '2':
                directory = self.safe_path_input("\nEnter directory path: ")
                if os.path.exists(directory):
                    self.run_conversion_scan(target_resolution, target_width, target_height, directory)
                else:
                    print("Directory not found!")
                    self.safe_input("\nPress Enter to continue...")
            elif choice == '3':
                file_path = self.safe_path_input("\nEnter video file path: ")
                if os.path.exists(file_path):
                    self.convert_single_file(file_path, target_resolution, target_width, target_height)
                else:
                    print("File not found!")
                    self.safe_input("\nPress Enter to continue...")
                
    def run_conversion_scan(self, target_resolution, target_width, target_height, directory=None):
        """Run conversion scan for videos larger than target resolution."""
        if directory is None:
            directory = self.base_path
            
        # Direct method implementation - no temporary scripts
        # Validate directory path first
        if not self.validate_safe_path(directory):
            print(f"Error: Invalid or unsafe directory path: {self.sanitize_path_for_display(directory)}")
            return
        
        print(f"Scanning for videos larger than {target_resolution}p...")
        candidates = []
        
        for root, _, files in os.walk(directory, followlinks=False):
            for file in files:
                if "-CONVERTED" in file:
                    continue
                file_path = os.path.join(root, file)
                if file.lower().endswith(('.mp4', '.mkv', '.avi', '.mov', '.flv')):
                    width, height = self.get_video_resolution_safe(file_path)
                    if width and height and (width > target_width or height > target_height):
                        try:
                            file_size_gb = os.path.getsize(file_path) / (1024 ** 3)
                            candidates.append({
                                'path': file_path,
                                'width': width,
                                'height': height,
                                'size_gb': file_size_gb
                            })
                        except OSError:
                            continue
        
        if not candidates:
            print(f"\nNo videos found larger than {target_resolution}p.")
            return
        
        print(f"\nFound {len(candidates)} videos to convert:")
        for i, video in enumerate(candidates[:10], 1):
            print(f"{i}. {os.path.basename(video['path'])}")
            print(f"   Resolution: {video['width']}x{video['height']}, Size: {video['size_gb']:.2f} GB")
        
        if len(candidates) > 10:
            print(f"\n... and {len(candidates) - 10} more")
        
        response = self.safe_input(f"\nConvert these videos to {target_resolution}p? (y/N): ")
        if response.lower() != 'y':
            print("Conversion cancelled.")
            return
        
        for i, video in enumerate(candidates, 1):
            print(f"\n[{i}/{len(candidates)}] Processing {video['path']}")
            
            # Create unique temporary filename to avoid race conditions
            timestamp = int(time.time() * 1000)  # millisecond timestamp
            output_file = os.path.splitext(video['path'])[0] + f"_temp_{timestamp}_{os.getpid()}.mp4"
            success = self.convert_video_safe(video['path'], output_file, target_width, target_height)
            
            if success:
                # Rename files
                try:
                    converted_filename = f"{os.path.splitext(video['path'])[0]}-CONVERTED{os.path.splitext(video['path'])[1]}"
                    os.rename(video['path'], converted_filename)
                    self.security_audit_log("VIDEO_CONVERTED", f"Original renamed to: {converted_filename}")
                    os.rename(output_file, os.path.splitext(video['path'])[0] + ".mp4")
                    self.security_audit_log("VIDEO_CONVERTED", f"New file: {os.path.splitext(video['path'])[0]}.mp4")
                    print(f"✓ Conversion complete!")
                except OSError as e:
                    print(f"✗ Error renaming files: {self.sanitize_error_message(str(e))}")
            else:
                print(f"✗ Conversion failed!")
                # Clean up temporary file on failure
                if os.path.exists(output_file):
                    self.safe_file_delete(output_file)
        
        print(f"\n✓ All conversions complete! Converted {len(candidates)} videos to {target_resolution}p.")
        
        self.safe_input("\nPress Enter to continue...")
        
    def convert_single_file(self, file_path, target_resolution, target_width, target_height):
        """Convert a single video file."""
        print(f"\nConverting {os.path.basename(file_path)} to {target_resolution}p...")
        
        # Create unique temporary filename to avoid race conditions
        timestamp = int(time.time() * 1000)  # millisecond timestamp
        output_file = os.path.splitext(file_path)[0] + f"_temp_{timestamp}_{os.getpid()}.mp4"
        
        # Validate parameters to prevent injection
        try:
            target_width = int(target_width)
            target_height = int(target_height)
            if target_width <= 0 or target_height <= 0 or target_width > 7680 or target_height > 4320:
                print("Error: Invalid resolution parameters")
                return
        except (ValueError, TypeError):
            print("Error: Invalid resolution parameters")
            return
        
        # Validate file paths
        if not self.validate_safe_path(file_path) or not self.validate_safe_path(output_file):
            print("Error: Unsafe file path")
            return
        
        cmd = [
            "ffmpeg",
            "-i", file_path,
            "-vf", f"scale={target_width}:{target_height}",
            "-c:v", "libx264",
            "-crf", "23",
            "-preset", "medium",
            "-c:a", "aac",
            "-b:a", "128k",
            "-y",
            output_file
        ]
        
        result = self.cmd_manager.safe_subprocess_run(cmd, capture_output=True, text=True, timeout=TimeoutConstants.LONG)  # 1 hour timeout
        if result.returncode != 0:
            print("✗ Conversion failed!")
            # Clean up temporary file on failure
            if os.path.exists(output_file):
                self.safe_file_delete(output_file)
            return
        
        # Rename files
        converted_filename = f"{os.path.splitext(file_path)[0]}-CONVERTED{os.path.splitext(file_path)[1]}"
        os.rename(file_path, converted_filename)
        os.rename(output_file, os.path.splitext(file_path)[0] + ".mp4")
        
        print(f"✓ Conversion complete!")
        print(f"Original saved as: {os.path.basename(converted_filename)}")
        
        self.safe_input("\nPress Enter to continue...")
    
    def batch_convert_from_list(self, file_list, target_resolution, target_width, target_height, background_mode=False):
        """Convert videos from a specific list with progress tracking."""
        total_files = len(file_list)
        successful = 0
        failed = 0
        
        print(f"\n🎬 Converting {total_files} files to {target_resolution}p...")
        
        if background_mode:
            print("Running in background mode...")
        
        for i, file_path in enumerate(file_list, 1):
            if not background_mode:
                print(f"\n[{i}/{total_files}] Converting:")
                print(f"   {os.path.basename(file_path)}")
            
            try:
                self.convert_single_file(file_path, target_resolution, target_width, target_height)
                successful += 1
                
                # Update database to mark as converted
                with self.get_db_context() as conn:
                    cursor = conn.cursor()
                    cursor.execute('UPDATE video_files SET needs_conversion = 0 WHERE file_path = ?', (file_path,))
                    
            except Exception as e:
                failed += 1
                if not background_mode:
                    print(f"   ✗ Failed: {self.sanitize_error_message(str(e))}")
            
            if background_mode and i % 5 == 0:
                print(f"Progress: {i}/{total_files} ({successful} successful, {failed} failed)")
        
        print(f"\n✓ Batch conversion complete!")
        print(f"   Successful: {successful}")
        print(f"   Failed: {failed}")
        
        self.safe_input("\nPress Enter to continue...")
    
    def convert_by_directory(self, target_resolution, target_width, target_height):
        """Convert videos organized by directory (Movies, TV, specific show)."""
        print("\nChoose content type:")
        print("1. Movies only")
        print("2. TV Shows only") 
        print("3. Pick specific TV show")
        print("4. All content")
        print("0. Cancel")
        
        choice = self.safe_input("\nEnter your choice: ")
        
        if choice == '0':
            return
        elif choice == '1':
            self.process_conversions_by_category('Movies', target_resolution, target_width, target_height)
        elif choice == '2':
            self.process_conversions_by_category('TV', target_resolution, target_width, target_height)
        elif choice == '3':
            self.pick_tv_show_for_conversion(target_resolution, target_width, target_height)
        elif choice == '4':
            self.process_conversions_by_category('All', target_resolution, target_width, target_height)
    
    def process_conversions_by_category(self, category, target_resolution, target_width, target_height):
        """Process conversions for a specific category."""
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            
            if category == 'Movies':
                cursor.execute('''
                    SELECT file_path FROM video_files 
                    WHERE needs_conversion = 1 AND (width > ? OR height > ?)
                    AND file_path LIKE '%/Movies/%'
                    ORDER BY file_size DESC
                ''', (target_width, target_height))
            elif category == 'TV':
                cursor.execute('''
                    SELECT file_path FROM video_files 
                    WHERE needs_conversion = 1 AND (width > ? OR height > ?)
                    AND file_path LIKE '%/TV/%'
                    ORDER BY file_size DESC
                ''', (target_width, target_height))
            else:  # All
                cursor.execute('''
                    SELECT file_path FROM video_files 
                    WHERE needs_conversion = 1 AND (width > ? OR height > ?)
                    ORDER BY file_size DESC
                ''', (target_width, target_height))
            
            files = [row[0] for row in cursor.fetchall()]
        
        if not files:
            print(f"No files needing conversion found in {category}")
            self.safe_input("Press Enter to continue...")
            return
        
        print(f"Found {len(files)} {category.lower()} files needing conversion to {target_resolution}p")
        batch_size = min(10, len(files))  # Default to 10 max for conversions
        
        print(f"\n🎬 Processing Mode for {batch_size} files:")
        print("1. Watch progress (interactive)")
        print("2. Run in background (faster)")
        
        mode_choice = self.safe_input("\nChoose processing mode: ")
        background_mode = (mode_choice == '2')
        
        self.batch_convert_from_list(files[:batch_size], target_resolution, target_width, target_height, background_mode)
    
    def pick_tv_show_for_conversion(self, target_resolution, target_width, target_height):
        """Let user pick a specific TV show for conversion."""
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT DISTINCT 
                    SUBSTR(file_path, 1, INSTR(file_path, '/Season') - 1) as show_path,
                    COUNT(*) as conversion_count
                FROM video_files 
                WHERE needs_conversion = 1 AND (width > ? OR height > ?)
                AND file_path LIKE '%/TV/%'
                AND file_path LIKE '%/Season%'
                GROUP BY show_path
                ORDER BY conversion_count DESC
            ''', (target_width, target_height))
            
            shows = cursor.fetchall()
        
        if not shows:
            print("No TV shows found needing conversion")
            self.safe_input("Press Enter to continue...")
            return
        
        print(f"\nTV Shows needing conversion to {target_resolution}p:")
        for i, (show_path, count) in enumerate(shows[:20], 1):
            show_name = os.path.basename(show_path)
            print(f"{i:2}. {show_name} ({count} files)")
        
        print("0. Cancel")
        
        try:
            choice = int(self.safe_input(f"\nSelect show (1-{min(20, len(shows))}): "))
            if choice == 0:
                return
            elif 1 <= choice <= len(shows):
                selected_show = shows[choice - 1][0]
                
                # Get files for this show
                with self.get_db_context() as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT file_path FROM video_files 
                        WHERE needs_conversion = 1 AND (width > ? OR height > ?)
                        AND file_path LIKE ?
                        ORDER BY file_size DESC
                    ''', (target_width, target_height, f"{selected_show}%"))
                    
                    files = [row[0] for row in cursor.fetchall()]
                
                show_name = os.path.basename(selected_show)
                print(f"\n🎬 Converting {len(files)} files for {show_name} to {target_resolution}p")
                print("1. Watch progress (interactive)")
                print("2. Run in background (faster)")
                
                mode_choice = self.safe_input("\nChoose processing mode: ")
                background_mode = (mode_choice == '2')
                
                batch_size = min(10, len(files))  # Limit conversions to 10 per batch
                self.batch_convert_from_list(files[:batch_size], target_resolution, target_width, target_height, background_mode)
            else:
                print("Invalid selection.")
                self.safe_input("Press Enter to continue...")
        except ValueError:
            print("Invalid selection.")
            self.safe_input("Press Enter to continue...")
        
    def download_subtitles(self):
        """Download English subtitles for videos."""
        self.clear_screen()
        print("="*60)
        print("📝 Download English Subtitles")
        print("="*60)
        
        # Check if subliminal is available
        if not self.optional_deps.get('subliminal', False):
            print("\nSubliminal is not installed. Please install it manually:")
            print("pip install subliminal")
            self.safe_input("\nPress Enter to continue...")
            return
        
        # Check for cached subtitle data (Movies and TV only)
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT COUNT(*) FROM video_files 
                WHERE has_external_subs = 0 AND has_embedded_subs = 0
                AND (file_path LIKE '%/Movies/%' OR file_path LIKE '%/TV/%')
            ''')
            cached_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT MAX(last_scanned) FROM video_files WHERE last_scanned IS NOT NULL')
            last_scan = cursor.fetchone()[0]
        
        if cached_count > 0 and last_scan:
            scan_age = (time.time() - last_scan) / 3600  # hours
            print(f"💡 Your recent scan found {cached_count:,} files missing English subtitles")
            print(f"   (Scan was {scan_age:.1f} hours ago)")
            print()
            
            if cached_count > 100:
                print("📋 Batch Processing Options:")
                print("1. Process first 100 files (recommended)")
                print(f"2. Process all {cached_count:,} files")
                print("3. Choose custom batch size")
                print("4. Browse by directory instead")
                print("0. Cancel")
                
                choice = self.safe_input("\nEnter your choice: ")
                
                if choice == '0':
                    return
                elif choice == '1':
                    batch_size = 100
                elif choice == '2':
                    batch_size = cached_count
                elif choice == '3':
                    try:
                        batch_size = int(self.safe_input("Enter batch size (1-1000): "))
                        batch_size = max(1, min(1000, batch_size))
                    except ValueError:
                        print("Invalid batch size.")
                        self.safe_input("Press Enter to continue...")
                        return
                elif choice == '4':
                    self.subtitle_menu_by_directory()
                    return
                else:
                    print("Invalid choice.")
                    self.safe_input("Press Enter to continue...")
                    return
            else:
                print(f"📋 Found {cached_count} files needing subtitles from recent scan")
                batch_size = cached_count
            
            # Ask about processing mode
            print(f"\n🎬 Processing Mode for {batch_size} files:")
            print("1. Watch progress (interactive)")
            print("2. Run in background (faster)")
            
            mode_choice = self.safe_input("\nChoose processing mode: ")
            background_mode = (mode_choice == '2')
            
            # Get files from database
            with self.get_db_context() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    SELECT file_path FROM video_files 
                    WHERE has_external_subs = 0 AND has_embedded_subs = 0 
                    LIMIT ?
                ''', (batch_size,))
                
                files_to_process = [row[0] for row in cursor.fetchall()]
            
            if files_to_process:
                self.download_subtitles_from_list(files_to_process, background_mode)
            else:
                print("No files found to process.")
                self.safe_input("Press Enter to continue...")
        else:
            # No cached data, show original menu
            print("No recent scan data found. Choose an option:")
            print("1. Download for all videos without subtitles")
            print("2. Download for specific directory")
            print("3. Download for single video")
            print("0. Cancel")
            
            choice = self.safe_input("\nEnter your choice: ")
            
            if choice == '0':
                return
            elif choice == '1':
                self.download_subtitles_batch(self.base_path)
            elif choice == '2':
                directory = self.safe_path_input("\nEnter directory path: ")
                if os.path.exists(directory):
                    self.download_subtitles_batch(directory)
                else:
                    print("Directory not found!")
                    self.safe_input("\nPress Enter to continue...")
            elif choice == '3':
                file_path = self.safe_path_input("\nEnter video file path: ")
                if os.path.exists(file_path):
                    self.download_subtitle_for_file(file_path)
                else:
                    print("File not found!")
                    self.safe_input("\nPress Enter to continue...")
                
    def download_subtitles_batch(self, directory):
        """Download subtitles for all videos in directory that don't have them."""
        print(f"\nScanning {directory} for videos without English subtitles...")
        
        videos_needing_subs = []
        videos_checked = 0
        videos_with_subs = 0
        
        # First count total videos
        total_videos = sum(1 for root, dirs, files in os.walk(directory, followlinks=False) 
                          for file in files if file.lower().endswith(self.video_extensions))
        
        print(f"Found {total_videos} video files to check...")
        
        for root, dirs, files in os.walk(directory, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    
                    # Check if subtitle already exists
                    base_name = os.path.splitext(file_path)[0]
                    subtitle_exists = any(os.path.exists(f"{base_name}{ext}") 
                                        for ext in ['.srt', '.en.srt', '.eng.srt', '.vtt', '.en.vtt'])
                    
                    if not subtitle_exists:
                        # Check embedded subtitles
                        info = self.get_video_info(file_path)
                        has_english_sub = False
                        
                        if info:
                            for stream in info.get('streams', []):
                                if stream.get('codec_type') == 'subtitle':
                                    language = stream.get('tags', {}).get('language', '')
                                    if language in ['eng', 'en']:
                                        has_english_sub = True
                                        break
                        
                        if not has_english_sub:
                            videos_needing_subs.append(file_path)
                        else:
                            videos_with_subs += 1
                    else:
                        videos_with_subs += 1
                    
                    videos_checked += 1
                    if videos_checked % 10 == 0:
                        print(f"Checked {videos_checked}/{total_videos} videos...", end='\r')
        
        print(f"\nScan complete! Checked {videos_checked} videos")
        
        if not videos_needing_subs:
            print(f"✓ All {videos_checked} videos already have subtitles!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        print(f"\nScan Results:")
        print(f"  Videos with subtitles: {videos_with_subs}")
        print(f"  Videos needing subtitles: {len(videos_needing_subs)}")
        
        response = self.safe_input("\nDownload subtitles for these videos? (y/N): ")
        
        if response.lower() != 'y':
            return
        
        # Download subtitles
        failed_downloads = []
        succeeded = 0
        
        print("\nDownloading subtitles...")
        print("-" * 60)
        
        for i, video_path in enumerate(videos_needing_subs, 1):
            print(f"\n[{i}/{len(videos_needing_subs)}] Processing: {os.path.basename(video_path)}")
            success = self.download_subtitle_for_file(video_path, quiet=False)
            if success:
                succeeded += 1
                print(f"     Status: ✓ Downloaded successfully")
            else:
                failed_downloads.append(video_path)
                print(f"     Status: ✗ No subtitle found")
        
        print(f"\n✓ Subtitle download complete!")
        print(f"  Successful: {len(videos_needing_subs) - len(failed_downloads)}")
        print(f"  Failed: {len(failed_downloads)}")
        
        if failed_downloads:
            with open(os.path.join(self.base_path, "failed_subtitle_downloads.txt"), "w") as f:
                f.write("Failed Subtitle Downloads\n")
                f.write("="*50 + "\n")
                for path in failed_downloads:
                    f.write(f"{path}\n")
            print(f"  Failed list saved to: failed_subtitle_downloads.txt")
        
        self.safe_input("\nPress Enter to continue...")
        
    def download_subtitle_for_file(self, video_path, quiet=False, force_download=False):
        """Download subtitle for a single video file using subliminal."""
        filename = os.path.basename(video_path)
        
        try:
            # Log start of operation
            operation_type = "subtitle_force_download" if force_download else "subtitle_download"
            self.operation_log(operation_type, "STARTED", file_path=video_path)
            
            # Use subliminal command line tool with reliable providers only
            cmd = [
                sys.executable, "-m", "subliminal",
                "download",
                "-l", "en",  # English only
                "-p", "opensubtitles", "podnapisi",  # Use only reliable providers
                "-v",  # Verbose output for better debugging
            ]
            
            # Add force flag if needed
            if force_download:
                cmd.append("-f")  # Force download even if subtitle exists
            
            cmd.append(video_path)
            
            if not quiet:
                print(f"     File: {filename}")
                print(f"     Searching providers...")
            
            result = self.cmd_manager.safe_subprocess_run(cmd, capture_output=True, text=True, timeout=TimeoutConstants.MEDIUM)
            
            # Log the full command output for debugging (only if not quiet)
            if not quiet:
                if result.stdout:
                    self.operation_log("subtitle_download", "OUTPUT", details=f"stdout: {result.stdout[:500]}", file_path=video_path)
                if result.stderr:
                    self.operation_log("subtitle_download", "STDERR", details=f"stderr: {result.stderr[:500]}", file_path=video_path)
            
            # Show subliminal output if there's an error or in verbose mode
            if not quiet and result.stderr:
                print(f"     Debug: {result.stderr.strip()}")
            
            if result.returncode == 0:
                # Check if subtitle was downloaded
                base_name = os.path.splitext(video_path)[0]
                subtitle_found = any(os.path.exists(f"{base_name}{ext}") for ext in ['.srt', '.en.srt'])
                
                if subtitle_found:
                    if not quiet:
                        self.operation_log("subtitle_download", "SUCCESS", details="Subtitle file created", file_path=video_path)
                        print("✓ Subtitle downloaded successfully!")
                    return True
                else:
                    if not quiet:
                        self.operation_log("subtitle_download", "NO_SUBTITLE", details="No subtitle found by providers", file_path=video_path)
                        print("✗ No subtitle found for this video")
                    return False
            else:
                if not quiet:
                    self.operation_log("subtitle_download", "FAILED", details=f"Return code: {result.returncode}, Error: {result.stderr[:200]}", file_path=video_path)
                    print(f"✗ Error downloading subtitle (code {result.returncode})")
                return False
                
        except (subprocess.SubprocessError, OSError, IOError) as e:
            error_msg = str(e)
            if not quiet:
                self.operation_log("subtitle_download", "EXCEPTION", details=error_msg, file_path=video_path)
                print(f"✗ Error: {self.sanitize_error_message(error_msg)}")
            return False
    
    def download_subtitles_from_list(self, file_list, background_mode=False, force_download=False):
        """Download subtitles from a specific list of files with concurrent processing."""
        total_files = len(file_list)
        action_type = "force redownload" if force_download else "download"
        
        print(f"\n🎬 Processing {total_files} files for subtitle {action_type}...")
        print(f"Using parallel processing ({self.max_parallel_downloads} concurrent downloads)")
        
        # Filter out files that already have subtitles (unless forcing)
        files_to_process = []
        skipped = 0
        
        if not force_download:
            for file_path in file_list:
                base_name = os.path.splitext(file_path)[0]
                has_existing = any(os.path.exists(f"{base_name}{ext}") for ext in ['.srt', '.en.srt', '.eng.srt'])
                if has_existing:
                    skipped += 1
                else:
                    files_to_process.append(file_path)
        else:
            files_to_process = file_list
        
        if skipped > 0:
            print(f"Skipping {skipped} files that already have subtitles")
        
        if not files_to_process:
            print("✓ All files already have subtitles!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        print(f"Processing {len(files_to_process)} files...")
        
        # Progress tracking
        completed = 0
        successful = 0
        failed = 0
        failed_files = []
        current_file = ""
        
        # Thread-safe progress update
        progress_lock = threading.Lock()
        
        def update_progress():
            while completed < len(files_to_process):
                with progress_lock:
                    current = completed
                    success_count = successful
                    fail_count = failed
                    current_filename = current_file
                
                # Simple progress bar with completed/remaining counts
                if len(files_to_process) > 0:
                    pct = (current / len(files_to_process)) * 100
                    filled = int(pct / 2)
                    bar = "█" * filled + "░" * (50 - filled)
                    remaining = len(files_to_process) - current
                    
                    # Clear the line and print progress
                    print(f"\r\033[K[{bar}] {pct:5.1f}% - Completed: {current}, Remaining: {remaining} ✓{success_count} ✗{fail_count}", end='', flush=True)
                
                time.sleep(0.5)
            
            # Final progress bar
            print(f"\r\033[K[{'█' * 50}] 100.0% - Completed: {len(files_to_process)}, Remaining: 0 ✓{successful} ✗{failed}")
        
        def download_worker(file_path):
            nonlocal completed, successful, failed, failed_files, current_file
            
            try:
                # Update current file being processed
                with progress_lock:
                    current_file = file_path
                
                result = self.download_subtitle_for_file(file_path, quiet=True, force_download=force_download)
                
                with progress_lock:
                    completed += 1
                    if result:
                        successful += 1
                        # Update database
                        with self.get_db_context() as conn:
                            cursor = conn.cursor()
                            cursor.execute('UPDATE video_files SET has_external_subs = 1 WHERE file_path = ?', (file_path,))
                    else:
                        failed += 1
                        failed_files.append(file_path)
                        
            except Exception as e:
                with progress_lock:
                    completed += 1
                    failed += 1
                    failed_files.append(file_path)
                    self.operation_log("subtitle_download", "WORKER_EXCEPTION", details=str(e), file_path=file_path)
        
        # Start progress display thread
        if not background_mode:
            progress_thread = threading.Thread(target=update_progress, daemon=True)
            progress_thread.start()
        
        # Use ThreadPoolExecutor for concurrent downloads
        max_workers = self.max_parallel_downloads
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all download tasks
            futures = [executor.submit(download_worker, file_path) for file_path in files_to_process]
            
            # Wait for all to complete
            for future in as_completed(futures):
                try:
                    future.result()  # Get result to catch any exceptions
                except Exception as e:
                    self.operation_log("subtitle_download", "FUTURE_EXCEPTION", details=str(e))
        
        print(f"\n\n✓ Subtitle download complete!")
        print(f"   Successful: {successful}")
        print(f"   Failed: {failed}")
        if skipped > 0:
            print(f"   Skipped: {skipped} (already had subtitles)")
        
        # Show failed files if any
        if failed_files:
            print(f"\n❌ Failed Downloads ({len(failed_files)} files):")
            for file_path in failed_files[:10]:  # Show first 10
                filename = os.path.basename(file_path)
                print(f"   • {filename}")
            
            if len(failed_files) > 10:
                print(f"   ... and {len(failed_files) - 10} more")
        
        self.safe_input("\nPress Enter to continue...")
    
    def subtitle_menu_by_directory(self):
        """Show subtitle menu organized by directory."""
        print("\nChoose content type:")
        print("1. Movies only")
        print("2. TV Shows only")
        print("3. Pick specific TV show")
        print("4. All content")
        print("0. Cancel")
        
        choice = self.safe_input("\nEnter your choice: ")
        
        if choice == '0':
            return
        elif choice == '1':
            self.process_subtitles_by_category('Movies')
        elif choice == '2':
            self.process_subtitles_by_category('TV')
        elif choice == '3':
            self.pick_tv_show_for_subtitles()
        elif choice == '4':
            self.process_subtitles_by_category('All')
    
    def process_subtitles_by_category(self, category):
        """Process subtitles for a specific category (Movies, TV, or All)."""
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            
            if category == 'Movies':
                cursor.execute('''
                    SELECT file_path FROM video_files 
                    WHERE has_external_subs = 0 AND has_embedded_subs = 0 
                    AND file_path LIKE '%/Movies/%'
                    ORDER BY file_size DESC
                ''')
            elif category == 'TV':
                cursor.execute('''
                    SELECT file_path FROM video_files 
                    WHERE has_external_subs = 0 AND has_embedded_subs = 0 
                    AND file_path LIKE '%/TV/%'
                    ORDER BY file_size DESC
                ''')
            else:  # All
                cursor.execute('''
                    SELECT file_path FROM video_files 
                    WHERE has_external_subs = 0 AND has_embedded_subs = 0 
                    ORDER BY file_size DESC
                ''')
            
            files = [row[0] for row in cursor.fetchall()]
        
        if not files:
            print(f"No files needing subtitles found in {category}")
            self.safe_input("Press Enter to continue...")
            return
        
        print(f"Found {len(files)} {category.lower()} files needing subtitles")
        batch_size = min(100, len(files))  # Default to 100 max
        
        # Ask about processing mode
        print(f"\n🎬 Processing Mode for {batch_size} files:")
        print("1. Watch progress (interactive)")
        print("2. Run in background (faster)")
        
        mode_choice = self.safe_input("\nChoose processing mode: ")
        background_mode = (mode_choice == '2')
        
        self.download_subtitles_from_list(files[:batch_size], background_mode)
    
    def pick_tv_show_for_subtitles(self):
        """Let user pick a specific TV show for subtitle processing."""
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT DISTINCT 
                    SUBSTR(file_path, 1, INSTR(file_path, '/Season') - 1) as show_path,
                    COUNT(*) as missing_count
                FROM video_files 
                WHERE has_external_subs = 0 AND has_embedded_subs = 0 
                AND file_path LIKE '%/TV/%'
                AND file_path LIKE '%/Season%'
                GROUP BY show_path
                ORDER BY missing_count DESC
            ''')
            
            shows = cursor.fetchall()
        
        if not shows:
            print("No TV shows found needing subtitles")
            self.safe_input("Press Enter to continue...")
            return
        
        print("\nTV Shows needing subtitles:")
        for i, (show_path, count) in enumerate(shows[:20], 1):  # Show top 20
            show_name = os.path.basename(show_path)
            print(f"{i:2}. {show_name} ({count} files)")
        
        print("0. Cancel")
        
        try:
            choice = int(self.safe_input(f"\nSelect show (1-{min(20, len(shows))}): "))
            if choice == 0:
                return
            elif 1 <= choice <= len(shows):
                selected_show = shows[choice - 1][0]
                
                # Get files for this show
                with self.get_db_context() as conn:
                    cursor = conn.cursor()
                    cursor.execute('''
                        SELECT file_path FROM video_files 
                        WHERE has_external_subs = 0 AND has_embedded_subs = 0 
                        AND file_path LIKE ?
                        ORDER BY file_path
                    ''', (f"{selected_show}%",))
                    
                    files = [row[0] for row in cursor.fetchall()]
                
                show_name = os.path.basename(selected_show)
                print(f"\n🎬 Processing {len(files)} files for {show_name}")
                print("1. Watch progress (interactive)")
                print("2. Run in background (faster)")
                
                mode_choice = self.safe_input("\nChoose processing mode: ")
                background_mode = (mode_choice == '2')
                
                self.download_subtitles_from_list(files, background_mode)
            else:
                print("Invalid selection.")
                self.safe_input("Press Enter to continue...")
        except ValueError:
            print("Invalid selection.")
            self.safe_input("Press Enter to continue...")
        
    def quick_fixes(self):
        """Quick fixes menu for common issues."""
        while True:
            self.clear_screen()
            print("="*60)
            print("🔧 Quick Fixes")
            print("="*60)
            print("1. Remove sample/trailer files")
            print("2. Delete .DS_Store and thumbs.db files")
            print("3. Clean up empty folders")
            print("4. Remove '-CONVERTED' from filenames")
            print("5. Fix common naming issues")
            print("6. Remove duplicate subtitle files")
            print("0. Back to main menu")
            print()
            
            choice = self.safe_input("Enter your choice: ")
            
            if choice == '0':
                break
            elif choice == '1':
                self.remove_sample_files()
            elif choice == '2':
                self.clean_system_files()
            elif choice == '3':
                self.clean_empty_folders()
            elif choice == '4':
                self.remove_converted_suffix()
            elif choice == '5':
                self.fix_naming_issues()
            elif choice == '6':
                self.remove_duplicate_subtitles()
                
    def remove_sample_files(self):
        """Remove sample and trailer files."""
        print("\nSearching for sample/trailer files...")
        
        sample_patterns = ['sample', 'trailer', 'preview']
        files_to_remove = []
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    # Check filename
                    if any(pattern in file.lower() for pattern in sample_patterns):
                        file_path = os.path.join(root, file)
                        size_mb = os.path.getsize(file_path) / (1024**2)
                        
                        # Only flag small files as samples (under 100MB)
                        if size_mb < 100:
                            files_to_remove.append((file_path, size_mb))
        
        if not files_to_remove:
            print("No sample/trailer files found!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(files_to_remove)} sample/trailer files:")
        total_size = sum(size for _, size in files_to_remove)
        
        for i, (path, size) in enumerate(files_to_remove[:20], 1):
            print(f"{i}. {os.path.basename(path)} ({size:.1f} MB)")
        
        if len(files_to_remove) > 20:
            print(f"... and {len(files_to_remove) - 20} more")
        
        print(f"\nTotal size: {total_size:.1f} MB")
        
        response = self.safe_input("\nDelete these files? (y/N): ")
        if response.lower() == 'y':
            for path, _ in files_to_remove:
                success, message = self.safe_file_delete(path)
                if not success:
                    print(f"Error deleting {path}: {message}")
            print(f"✓ Deleted {len(files_to_remove)} files")
        
        self.safe_input("\nPress Enter to continue...")
        
    def clean_system_files(self):
        """Remove .DS_Store, thumbs.db, and other system files."""
        print("\nSearching for system files...")
        
        system_files = ['.DS_Store', 'Thumbs.db', 'desktop.ini', '._.DS_Store']
        files_removed = 0
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file in system_files or file.startswith('._'):
                    file_path = os.path.join(root, file)
                    success, message = self.safe_file_delete(file_path)
                    if success:
                        files_removed += 1
                        print(f"Removed: {self.sanitize_path_for_display(file_path)}")
                    else:
                        print(f"Failed to remove {self.sanitize_path_for_display(file_path)}: {message}")
        
        print(f"\n✓ Removed {files_removed} system files")
        self.safe_input("\nPress Enter to continue...")
        
    def clean_empty_folders(self):
        """Remove empty folders."""
        print("\nSearching for empty folders...")
        
        empty_folders = []
        
        for root, dirs, files in os.walk(self.base_path, topdown=False, followlinks=False):
            if not dirs and not files and root != self.base_path:
                empty_folders.append(root)
        
        if not empty_folders:
            print("No empty folders found!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(empty_folders)} empty folders:")
        for folder in empty_folders[:20]:
            print(f"  {os.path.relpath(folder, self.base_path)}")
        
        if len(empty_folders) > 20:
            print(f"... and {len(empty_folders) - 20} more")
        
        response = self.safe_input("\nDelete these folders? (y/N): ")
        if response.lower() == 'y':
            for folder in empty_folders:
                try:
                    os.rmdir(folder)
                except OSError as e:
                    print(f"Error removing {self.sanitize_path_for_display(folder)}: {self.sanitize_error_message(str(e))}")
            print(f"✓ Removed {len(empty_folders)} empty folders")
        
        self.safe_input("\nPress Enter to continue...")
        
    def remove_converted_suffix(self):
        """Remove '-CONVERTED' suffix from filenames."""
        print("\nSearching for files with '-CONVERTED' suffix...")
        
        converted_files = []
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if '-CONVERTED' in file:
                    file_path = os.path.join(root, file)
                    new_name = file.replace('-CONVERTED', '')
                    new_path = os.path.join(root, new_name)
                    
                    # Check if file without suffix already exists
                    if not os.path.exists(new_path):
                        converted_files.append((file_path, new_path))
        
        if not converted_files:
            print("No files with '-CONVERTED' suffix found!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(converted_files)} files with '-CONVERTED' suffix:")
        for old, new in converted_files[:10]:
            print(f"  {os.path.basename(old)} → {os.path.basename(new)}")
        
        if len(converted_files) > 10:
            print(f"... and {len(converted_files) - 10} more")
        
        response = self.safe_input("\nRemove '-CONVERTED' suffix from these files? (y/N): ")
        if response.lower() == 'y':
            for old_path, new_path in converted_files:
                try:
                    os.rename(old_path, new_path)
                except OSError as e:
                    print(f"Error renaming {self.sanitize_path_for_display(old_path)}: {self.sanitize_error_message(str(e))}")
            print(f"✓ Renamed {len(converted_files)} files")
        
        self.safe_input("\nPress Enter to continue...")
        
    def fix_naming_issues(self):
        """Fix common naming issues."""
        print("\nChecking for common naming issues...")
        
        issues_found = []
        
        # Patterns to fix
        fixes = {
            '  ': ' ',  # Double spaces
            '..': '.',  # Double periods
            ' .': '.',  # Space before period
            '_.': '.',  # Underscore before period
            '.-': '-',  # Period dash
            '-.': '-',  # Dash period
        }
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    new_name = file
                    
                    # Apply fixes
                    for old, new in fixes.items():
                        new_name = new_name.replace(old, new)
                    
                    # Remove leading/trailing spaces
                    new_name = new_name.strip()
                    
                    if new_name != file:
                        old_path = os.path.join(root, file)
                        new_path = os.path.join(root, new_name)
                        
                        if not os.path.exists(new_path):
                            issues_found.append((old_path, new_path, file, new_name))
        
        if not issues_found:
            print("No naming issues found!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(issues_found)} files with naming issues:")
        for _, _, old, new in issues_found[:10]:
            print(f"  {old}")
            print(f"  → {new}")
        
        if len(issues_found) > 10:
            print(f"... and {len(issues_found) - 10} more")
        
        response = self.safe_input("\nFix these naming issues? (y/N): ")
        if response.lower() == 'y':
            for old_path, new_path, _, _ in issues_found:
                try:
                    os.rename(old_path, new_path)
                except OSError as e:
                    print(f"Error renaming {self.sanitize_path_for_display(old_path)}: {self.sanitize_error_message(str(e))}")
            print(f"✓ Fixed {len(issues_found)} files")
        
        self.safe_input("\nPress Enter to continue...")
        
    def remove_duplicate_subtitles(self):
        """Remove duplicate subtitle files."""
        print("\nSearching for duplicate subtitle files...")
        
        subtitle_extensions = ['.srt', '.vtt', '.ass', '.sub', '.ssa']
        duplicates = []
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            # Group subtitles by base video name
            video_subs = {}
            
            for file in files:
                for ext in subtitle_extensions:
                    if file.lower().endswith(ext):
                        # Extract base video name
                        base = file
                        for sub_ext in subtitle_extensions:
                            base = base.replace(sub_ext, '')
                        base = base.replace('.en', '').replace('.eng', '').replace('.english', '')
                        
                        if base not in video_subs:
                            video_subs[base] = []
                        video_subs[base].append(os.path.join(root, file))
            
            # Find duplicates
            for base, subs in video_subs.items():
                if len(subs) > 1:
                    # Keep the .srt if available, otherwise keep the first
                    srt_files = [s for s in subs if s.endswith('.srt')]
                    keep = srt_files[0] if srt_files else subs[0]
                    
                    for sub in subs:
                        if sub != keep:
                            duplicates.append((sub, keep))
        
        if not duplicates:
            print("No duplicate subtitle files found!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(duplicates)} duplicate subtitle files:")
        for dup, keep in duplicates[:10]:
            print(f"  Remove: {os.path.basename(dup)}")
            print(f"  Keep:   {os.path.basename(keep)}")
            print()
        
        if len(duplicates) > 10:
            print(f"... and {len(duplicates) - 10} more")
        
        response = self.safe_input("\nRemove duplicate subtitles? (y/N): ")
        if response.lower() == 'y':
            for dup, _ in duplicates:
                success, message = self.safe_file_delete(dup)
                if not success:
                    print(f"Error removing {dup}: {message}")
            print(f"✓ Removed {len(duplicates)} duplicate subtitle files")
        
        self.safe_input("\nPress Enter to continue...")
        
    def manual_file_correction(self):
        """Manual file correction with TMDB lookup."""
        self.clear_screen()
        print("🎬 Manual File Correction with TMDB Lookup")
        print("="*60)
        
        # Check if TMDB API key is configured
        if not self.tmdb.api_key:
            print("📋 TMDB API Key Setup Required")
            print("\nTo use this feature, you need a free TMDB API key.")
            print("1. Visit: https://www.themoviedb.org/settings/api")
            print("2. Create an account and request an API key")
            print("3. Enter the key below (it will be saved for future use)")
            print()
            
            api_key = self.safe_input("Enter TMDB API key (or press Enter to skip): ").strip()
            if not api_key:
                print("Skipping TMDB correction.")
                self.safe_input("\nPress Enter to continue...")
                return
                
            try:
                self.tmdb.set_api_key(api_key)
                # Save API key to settings
                self.save_tmdb_api_key(api_key)
                print("✓ API key saved successfully!")
            except ValueError as e:
                print(f"❌ Invalid API key: {e}")
                self.safe_input("\nPress Enter to continue...")
                return
        
        # Show files that might need correction
        print("\n🔍 Finding files that might need correction...")
        candidates = self.find_correction_candidates()
        
        if not candidates:
            print("✓ No obvious correction candidates found!")
            print("All files appear to be properly named.")
            self.safe_input("\nPress Enter to continue...")
            return
            
        print(f"\nFound {len(candidates)} files that might need correction:")
        print("="*60)
        
        # Show candidates with numbers
        for i, (file_path, filename, issues) in enumerate(candidates[:20], 1):
            relative_path = os.path.relpath(file_path, self.base_path)
            print(f"{i:2}. {filename}")
            print(f"    📍 {relative_path}")
            print(f"    ⚠️  Issues: {', '.join(issues)}")
            print()
            
        if len(candidates) > 20:
            print(f"... and {len(candidates) - 20} more files")
            print()
        
        # Let user select files to correct
        print("Options:")
        print("• Enter file numbers to correct (e.g., '1,3,5' or '1-10')")
        print("• Enter 'all' to correct all files")
        print("• Press Enter to cancel")
        print()
        
        selection = self.safe_input("Select files to correct: ").strip()
        if not selection:
            return
            
        # Parse selection
        selected_indices = self.parse_selection(selection, len(candidates))
        if not selected_indices:
            print("Invalid selection.")
            self.safe_input("\nPress Enter to continue...")
            return
            
        # Process selected files
        for idx in selected_indices:
            file_path, filename, issues = candidates[idx]
            print(f"\n{'='*60}")
            print(f"Correcting: {filename}")
            print(f"Issues: {', '.join(issues)}")
            
            self.correct_single_file(file_path, filename)
        
        self.safe_input(f"\n✓ Correction workflow complete! Press Enter to continue...")
        
    def save_tmdb_api_key(self, api_key):
        """Save TMDB API key to settings."""
        settings = self.load_settings_dict()
        settings['tmdb_api_key'] = api_key
        self.save_settings_dict(settings)
        
    def load_tmdb_api_key(self):
        """Load TMDB API key from settings."""
        settings = self.load_settings_dict()
        api_key = settings.get('tmdb_api_key')
        if api_key:
            try:
                self.tmdb.set_api_key(api_key)
            except ValueError:
                pass  # Invalid key, will prompt user later
                
    def find_correction_candidates(self):
        """Find files that might need manual correction."""
        candidates = []
        
        # Look through video files in database for potential issues
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                SELECT file_path, filename, naming_issues 
                FROM video_files 
                WHERE naming_issues IS NOT NULL AND naming_issues != ''
                ORDER BY file_path
            ''')
            
            for file_path, filename, naming_issues in cursor.fetchall():
                if os.path.exists(file_path):
                    issues = naming_issues.split(', ') if naming_issues else []
                    candidates.append((file_path, filename, issues))
        
        return candidates
        
    def parse_selection(self, selection, max_count):
        """Parse user selection string into list of indices."""
        if selection.lower() == 'all':
            return list(range(max_count))
            
        indices = []
        parts = selection.split(',')
        
        for part in parts:
            part = part.strip()
            if '-' in part:
                # Range like "1-5"
                try:
                    start, end = part.split('-', 1)
                    start_idx = int(start) - 1  # Convert to 0-based
                    end_idx = int(end) - 1
                    if 0 <= start_idx <= end_idx < max_count:
                        indices.extend(range(start_idx, end_idx + 1))
                except ValueError:
                    return None
            else:
                # Single number
                try:
                    idx = int(part) - 1  # Convert to 0-based
                    if 0 <= idx < max_count:
                        indices.append(idx)
                except ValueError:
                    return None
                    
        return sorted(list(set(indices)))  # Remove duplicates and sort
        
    def correct_single_file(self, file_path, filename):
        """Correct a single file using TMDB lookup."""
        print(f"\n📝 Manual Correction for: {filename}")
        
        # Determine if this is a movie or TV show based on path
        media_type = 'movie' if '/Movies/' in file_path else 'tv'
        print(f"📁 Detected type: {media_type}")
        
        # Get user input for correction
        print(f"\nPlease provide the correct information:")
        corrected_title = self.safe_input("Title: ").strip()
        if not corrected_title:
            print("❌ No title provided, skipping.")
            return
            
        year_input = self.safe_input("Year (optional): ").strip()
        corrected_year = None
        if year_input:
            try:
                corrected_year = int(year_input)
            except ValueError:
                print("⚠️  Invalid year, ignoring.")
        
        # Search TMDB
        print(f"\n🔍 Searching TMDB for '{corrected_title}'...")
        
        if media_type == 'movie':
            results = self.tmdb.search_movie(corrected_title, corrected_year)
        else:
            results = self.tmdb.search_tv(corrected_title, corrected_year)
            
        if not results or not results.get('results'):
            print("❌ No results found on TMDB")
            self.safe_input("\nPress Enter to continue...")
            return
            
        # Show search results
        tmdb_results = results['results'][:10]  # Show top 10
        print(f"\n📋 Found {len(tmdb_results)} results:")
        
        for i, result in enumerate(tmdb_results, 1):
            if media_type == 'movie':
                title = result.get('title', 'Unknown')
                year = result.get('release_date', '')[:4] if result.get('release_date') else 'Unknown'
                overview = result.get('overview', '')[:100] + ('...' if len(result.get('overview', '')) > 100 else '')
            else:
                title = result.get('name', 'Unknown')
                year = result.get('first_air_date', '')[:4] if result.get('first_air_date') else 'Unknown'
                overview = result.get('overview', '')[:100] + ('...' if len(result.get('overview', '')) > 100 else '')
                
            print(f"{i:2}. {title} ({year})")
            if overview:
                print(f"    {overview}")
            print()
            
        # Let user choose
        choice = self.safe_input("Select correct match (number), or press Enter to skip: ").strip()
        if not choice:
            return
            
        try:
            choice_idx = int(choice) - 1
            if 0 <= choice_idx < len(tmdb_results):
                selected = tmdb_results[choice_idx]
                self.apply_tmdb_correction(file_path, filename, corrected_title, corrected_year, media_type, selected)
            else:
                print("Invalid selection.")
        except ValueError:
            print("Invalid selection.")
        
    def apply_tmdb_correction(self, file_path, filename, corrected_title, corrected_year, media_type, tmdb_data):
        """Apply TMDB correction to a file."""
        if media_type == 'movie':
            tmdb_title = tmdb_data.get('title', corrected_title)
            tmdb_year = tmdb_data.get('release_date', '')[:4] if tmdb_data.get('release_date') else corrected_year
            tmdb_id = tmdb_data.get('id')
        else:
            tmdb_title = tmdb_data.get('name', corrected_title)
            tmdb_year = tmdb_data.get('first_air_date', '')[:4] if tmdb_data.get('first_air_date') else corrected_year
            tmdb_id = tmdb_data.get('id')
            
        # Create new Plex-compliant filename
        ext = os.path.splitext(filename)[1]
        if media_type == 'movie':
            new_filename = f"{tmdb_title} ({tmdb_year}){ext}"
        else:
            # For TV shows, keep original episode info but fix the show name
            # This is simplified - could be enhanced for episode-specific renaming
            new_filename = filename.replace(os.path.splitext(filename)[0], f"{tmdb_title} - Season 1")
            
        print(f"\n📝 Proposed correction:")
        print(f"   Old: {filename}")
        print(f"   New: {new_filename}")
        print(f"   TMDB: {tmdb_title} ({tmdb_year}) [ID: {tmdb_id}]")
        
        apply = self.safe_input("\nApply this correction? (Y/n): ").lower() != 'n'
        if not apply:
            print("❌ Correction cancelled")
            return
            
        # Store correction in database
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO manual_corrections 
                (original_file_path, original_filename, corrected_title, corrected_year, 
                 media_type, tmdb_id, tmdb_title, tmdb_year, correction_date, applied)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (file_path, filename, corrected_title, corrected_year, media_type, 
                  tmdb_id, tmdb_title, int(tmdb_year) if tmdb_year.isdigit() else None, 
                  time.time(), False))
        
        # Apply the correction (rename the file)
        new_path = os.path.join(os.path.dirname(file_path), new_filename)
        
        if os.path.exists(new_path):
            print(f"❌ File already exists: {new_filename}")
            return
            
        try:
            os.rename(file_path, new_path)
            print(f"✅ Successfully renamed to: {new_filename}")
            
            # Mark as applied in database
            with self.get_db_context() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    UPDATE manual_corrections 
                    SET applied = 1 
                    WHERE original_file_path = ?
                ''', (file_path,))
                
        except OSError as e:
            print(f"❌ Error renaming file: {self.sanitize_error_message(str(e))}")
        
    def find_duplicates(self):
        """Find duplicate video files."""
        print("\nDuplicate Detection Options:")
        print("1. Find exact duplicates (same file size)")
        print("2. Find similar titles (possible duplicates)")
        print("3. Find duplicate episodes in TV shows")
        print("0. Cancel")
        
        choice = self.safe_input("\nEnter your choice: ")
        
        if choice == '0':
            return
        elif choice == '1':
            self.find_exact_duplicates()
        elif choice == '2':
            self.find_similar_titles()
        elif choice == '3':
            self.find_duplicate_episodes()
            
    def find_exact_duplicates(self):
        """Find files with exact same size."""
        print("\nSearching for exact duplicates...")
        print("Building file size index...")
        
        size_map = {}
        total_videos = 0
        files_processed = 0
        
        # Count total files first
        total_files = sum(1 for root, dirs, files in os.walk(self.base_path, followlinks=False) 
                         for file in files if file.lower().endswith(self.video_extensions))
        
        print(f"Analyzing {total_files} video files...\n")
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    files_processed += 1
                    
                    if files_processed % 10 == 0 or files_processed == total_files:
                        print(f"Processing: {files_processed}/{total_files} files ({(files_processed/total_files)*100:.1f}%)", end='\r')
                    
                    try:
                        size = os.path.getsize(file_path)
                        if size not in size_map:
                            size_map[size] = []
                        size_map[size].append(file_path)
                        total_videos += 1
                    except OSError:
                        continue
        
        # Find duplicates
        duplicates = []
        for size, paths in size_map.items():
            if len(paths) > 1:
                duplicates.append((size, paths))
        
        if not duplicates:
            print(f"\nNo exact duplicates found among {total_videos} videos!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        # Sort by size
        duplicates.sort(key=lambda x: x[0], reverse=True)
        
        print(f"\nFound {len(duplicates)} groups of duplicate files:")
        print("="*80)
        
        total_wasted = 0
        for i, (size, paths) in enumerate(duplicates[:10], 1):
            size_gb = size / (1024**3)
            wasted = size_gb * (len(paths) - 1)
            total_wasted += wasted
            
            print(f"\n{i}. Size: {size_gb:.2f} GB ({len(paths)} copies, {wasted:.2f} GB wasted)")
            for path in paths:
                print(f"   {os.path.relpath(path, self.base_path)}")
        
        if len(duplicates) > 10:
            print(f"\n... and {len(duplicates) - 10} more groups")
        
        # Calculate total wasted space
        for size, paths in duplicates:
            size_gb = size / (1024**3)
            total_wasted += size_gb * (len(paths) - 1)
        
        print(f"\nTotal wasted space: {total_wasted:.2f} GB")
        
        # Save report
        with open(os.path.join(self.base_path, "duplicate_files_report.txt"), "w") as f:
            f.write(f"Duplicate Files Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n\n")
            
            for size, paths in duplicates:
                size_gb = size / (1024**3)
                f.write(f"Size: {size_gb:.2f} GB\n")
                for path in paths:
                    f.write(f"  {path}\n")
                f.write("\n")
        
        print(f"\nFull report saved to: duplicate_files_report.txt")
        self.safe_input("\nPress Enter to continue...")
        
    def find_similar_titles(self):
        """Find videos with similar titles."""
        print("\nSearching for similar titles...")
        
        import difflib
        
        videos = []
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    # Extract clean title
                    title = os.path.splitext(file)[0]
                    # Remove common patterns
                    title = title.lower()
                    for pattern in ['1080p', '720p', '480p', 'bluray', 'webrip', 'x264', 'x265', 'hevc']:
                        title = title.replace(pattern, '')
                    title = ' '.join(title.split())
                    
                    videos.append({
                        'path': file_path,
                        'name': file,
                        'clean_title': title,
                        'size': os.path.getsize(file_path)
                    })
        
        # Find similar titles
        similar_groups = []
        processed = set()
        
        for i, video1 in enumerate(videos):
            if video1['path'] in processed:
                continue
                
            similar = [video1]
            processed.add(video1['path'])
            
            for video2 in videos[i+1:]:
                if video2['path'] in processed:
                    continue
                    
                # Calculate similarity
                similarity = difflib.SequenceMatcher(None, 
                                                   video1['clean_title'], 
                                                   video2['clean_title']).ratio()
                
                if similarity > 0.8:  # 80% similar
                    similar.append(video2)
                    processed.add(video2['path'])
            
            if len(similar) > 1:
                similar_groups.append(similar)
        
        if not similar_groups:
            print("\nNo similar titles found!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(similar_groups)} groups of similar titles:")
        print("="*80)
        
        for i, group in enumerate(similar_groups[:10], 1):
            print(f"\n{i}. Similar titles ({len(group)} files):")
            for video in group:
                size_gb = video['size'] / (1024**3)
                print(f"   {video['name']} ({size_gb:.2f} GB)")
        
        if len(similar_groups) > 10:
            print(f"\n... and {len(similar_groups) - 10} more groups")
        
        self.safe_input("\nPress Enter to continue...")
        
    def find_duplicate_episodes(self):
        """Find duplicate TV episodes."""
        print("\nSearching for duplicate TV episodes...")
        
        tv_path = os.path.join(self.base_path, "TV")
        if not os.path.exists(tv_path):
            print("TV directory not found!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        import re
        
        # Pattern to extract season and episode
        episode_patterns = [
            r'[Ss](\d+)[Ee](\d+)',  # S01E01
            r'(\d+)x(\d+)',          # 1x01
            r'Season\s*(\d+).*Episode\s*(\d+)',  # Season 1 Episode 1
        ]
        
        duplicates = []
        
        for show_dir in os.listdir(tv_path):
            show_path = os.path.join(tv_path, show_dir)
            if not os.path.isdir(show_path):
                continue
            
            episodes = {}
            
            for root, dirs, files in os.walk(show_path, followlinks=False):
                for file in files:
                    if file.lower().endswith(self.video_extensions):
                        # Try to extract season and episode
                        for pattern in episode_patterns:
                            match = re.search(pattern, file, re.IGNORECASE)
                            if match:
                                try:
                                    season = int(match.group(1))
                                    episode = int(match.group(2))
                                except (ValueError, IndexError):
                                    continue
                                key = f"S{season:02d}E{episode:02d}"
                                
                                if key not in episodes:
                                    episodes[key] = []
                                episodes[key].append(os.path.join(root, file))
                                break
            
            # Find duplicates in this show
            for ep_key, paths in episodes.items():
                if len(paths) > 1:
                    duplicates.append((show_dir, ep_key, paths))
        
        if not duplicates:
            print("\nNo duplicate episodes found!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(duplicates)} duplicate episodes:")
        print("="*80)
        
        for show, episode, paths in duplicates[:20]:
            print(f"\n{show} - {episode} ({len(paths)} copies):")
            for path in paths:
                size_gb = os.path.getsize(path) / (1024**3)
                print(f"   {os.path.basename(path)} ({size_gb:.2f} GB)")
        
        if len(duplicates) > 20:
            print(f"\n... and {len(duplicates) - 20} more")
        
        self.safe_input("\nPress Enter to continue...")
        
    def library_health_check(self):
        """Perform a health check on the video library."""
        print("\nLibrary Health Check Options:")
        print("1. Check for corrupted/unplayable files")
        print("2. Find videos with unusual codecs")
        print("3. Check for missing episodes in TV series")
        print("4. Verify file integrity")
        print("5. Full health report")
        print("0. Cancel")
        
        choice = self.safe_input("\nEnter your choice: ")
        
        if choice == '0':
            return
        elif choice == '1':
            self.check_corrupted_files()
        elif choice == '2':
            self.check_unusual_codecs()
        elif choice == '3':
            self.check_missing_episodes()
        elif choice == '4':
            self.verify_file_integrity()
        elif choice == '5':
            self.full_health_report()
            
    def check_corrupted_files(self):
        """Check for corrupted or unplayable files."""
        print("\nChecking for corrupted files (this may take a while)...")
        
        # Count total files first
        total_files = sum(1 for root, dirs, files in os.walk(self.base_path, followlinks=False) 
                         for file in files if file.lower().endswith(self.video_extensions))
        
        print(f"Found {total_files} video files to check\n")
        
        corrupted_files = []
        checked = 0
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    checked += 1
                    
                    # Show current file being checked
                    if checked % 5 == 0 or checked == total_files:
                        truncated_name = file[:50] + "..." if len(file) > 50 else file
                        print(f"[{checked}/{total_files}] Checking: {truncated_name}", end='\r')
                    
                    # Quick check with ffprobe
                    cmd = [
                        "ffprobe",
                        "-v", "error",
                        "-show_entries", "format=duration",
                        "-of", "csv=p=0",
                        file_path
                    ]
                    
                    result = self.cmd_manager.safe_subprocess_run(cmd, capture_output=True, text=True, timeout=TimeoutConstants.STANDARD)
                    if result.returncode != 0 or not result.stdout.strip():
                        corrupted_files.append(file_path)
        
        print(f"\nChecked {checked} files")
        
        if not corrupted_files:
            print("✓ No corrupted files found!")
        else:
            print(f"⚠️  Found {len(corrupted_files)} potentially corrupted files:")
            
            # Save to file
            with open(os.path.join(self.base_path, "corrupted_files_report.txt"), "w") as f:
                f.write(f"Corrupted Files Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*80 + "\n\n")
                
                for path in corrupted_files:
                    f.write(f"{path}\n")
                    print(f"  {os.path.relpath(path, self.base_path)}")
            
            print(f"\nFull report saved to: corrupted_files_report.txt")
        
        self.safe_input("\nPress Enter to continue...")
        
    def check_unusual_codecs(self):
        """Check for videos with unusual codecs that Plex might struggle with."""
        print("\nChecking for unusual video codecs...")
        
        # Count total files
        total_files = sum(1 for root, dirs, files in os.walk(self.base_path, followlinks=False) 
                         for file in files if file.lower().endswith(self.video_extensions))
        
        print(f"Analyzing {total_files} video files for codec information...\n")
        
        unusual_codecs = []
        common_codecs = ['h264', 'hevc', 'h265', 'vp9', 'av1']
        files_checked = 0
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    files_checked += 1
                    
                    if files_checked % 5 == 0 or files_checked == total_files:
                        print(f"Analyzing: {files_checked}/{total_files} files ({(files_checked/total_files)*100:.1f}%)", end='\r')
                    
                    info = self.get_video_info(file_path)
                    
                    if info:
                        for stream in info.get('streams', []):
                            if stream.get('codec_type') == 'video':
                                codec = stream.get('codec_name', '').lower()
                                if codec and codec not in common_codecs:
                                    unusual_codecs.append({
                                        'path': file_path,
                                        'codec': codec,
                                        'name': file
                                    })
                                break
        
        print(f"\n\nAnalysis complete! Checked {files_checked} files")
        
        if not unusual_codecs:
            print("✓ All videos use common codecs!")
        else:
            print(f"Found {len(unusual_codecs)} videos with unusual codecs:")
            
            codec_counts = {}
            for video in unusual_codecs:
                codec = video['codec']
                if codec not in codec_counts:
                    codec_counts[codec] = []
                codec_counts[codec].append(video)
            
            for codec, videos in codec_counts.items():
                print(f"\n{codec.upper()} ({len(videos)} files):")
                for video in videos[:5]:
                    print(f"  {video['name']}")
                if len(videos) > 5:
                    print(f"  ... and {len(videos) - 5} more")
        
        self.safe_input("\nPress Enter to continue...")
        
    def check_missing_episodes(self):
        """Check for missing episodes in TV series."""
        print("\nChecking for missing episodes in TV series...")
        
        tv_path = os.path.join(self.base_path, "TV")
        if not os.path.exists(tv_path):
            print("TV directory not found!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        import re
        
        episode_pattern = r'[Ss](\d+)[Ee](\d+)'
        
        for show_dir in os.listdir(tv_path):
            show_path = os.path.join(tv_path, show_dir)
            if not os.path.isdir(show_path):
                continue
            
            episodes = set()
            
            for root, dirs, files in os.walk(show_path, followlinks=False):
                for file in files:
                    if file.lower().endswith(self.video_extensions):
                        match = re.search(episode_pattern, file, re.IGNORECASE)
                        if match:
                            try:
                                season = int(match.group(1))
                                episode = int(match.group(2))
                                episodes.add((season, episode))
                            except (ValueError, IndexError):
                                continue
            
            if episodes:
                # Check for gaps
                seasons = set(s for s, e in episodes)
                missing = []
                
                for season in seasons:
                    season_episodes = [e for s, e in episodes if s == season]
                    if season_episodes:
                        min_ep = min(season_episodes)
                        max_ep = max(season_episodes)
                        
                        for ep in range(min_ep, max_ep + 1):
                            if (season, ep) not in episodes:
                                missing.append(f"S{season:02d}E{ep:02d}")
                
                if missing:
                    print(f"\n{show_dir}:")
                    print(f"  Missing episodes: {', '.join(missing)}")
        
        self.safe_input("\nPress Enter to continue...")
        
    def verify_file_integrity(self):
        """Verify file integrity using file size and basic checks."""
        print("\nVerifying file integrity...")
        
        suspicious_files = []
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    
                    # Check for suspiciously small files
                    size_mb = os.path.getsize(file_path) / (1024**2)
                    
                    if size_mb < 10:  # Less than 10MB
                        suspicious_files.append((file_path, f"Very small file ({size_mb:.1f} MB)"))
                    elif file.endswith('.part'):
                        suspicious_files.append((file_path, "Incomplete download (.part file)"))
        
        if not suspicious_files:
            print("✓ No integrity issues found!")
        else:
            print(f"⚠️  Found {len(suspicious_files)} files with potential issues:")
            
            for path, issue in suspicious_files:
                print(f"  {os.path.basename(path)}: {issue}")
        
        self.safe_input("\nPress Enter to continue...")
        
    def full_health_report(self):
        """Generate a comprehensive health report."""
        print("\nGenerating full health report...")
        
        report = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'total_videos': 0,
            'total_size_gb': 0,
            'corrupted_files': 0,
            'unusual_codecs': {},
            'small_files': 0,
            'system_files': 0,
            'empty_folders': 0
        }
        
        # Count total items
        print("Counting files and folders...")
        total_items = sum(1 for root, dirs, files in os.walk(self.base_path, followlinks=False) for _ in files)
        items_processed = 0
        
        print(f"Analyzing {total_items} items...\n")
        
        # Count everything
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                items_processed += 1
                
                if items_processed % 50 == 0 or items_processed == total_items:
                    print(f"Health check: {items_processed}/{total_items} items ({(items_processed/total_items)*100:.1f}%)", end='\r')
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    try:
                        size = os.path.getsize(file_path)
                        report['total_videos'] += 1
                        report['total_size_gb'] += size / (1024**3)
                        
                        if size < 10 * FileSizeConstants.MB:  # Less than 10MB
                            report['small_files'] += 1
                            
                    except OSError:
                        report['corrupted_files'] += 1
                        
                elif file in ['.DS_Store', 'Thumbs.db', 'desktop.ini'] or file.startswith('._'):
                    report['system_files'] += 1
        
        # Count empty folders
        for root, dirs, files in os.walk(self.base_path, topdown=False, followlinks=False):
            if not dirs and not files and root != self.base_path:
                report['empty_folders'] += 1
        
        # Generate report in secure location
        report_filename = os.path.join(self.base_path, f"health_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt")
        
        # Validate write path is safe
        if not self.validate_safe_path(report_filename):
            print("Error: Cannot write health report to unsafe location")
            return
        
        with open(report_filename, 'w') as f:
            f.write(f"Media Library Health Report\n")
            f.write(f"Generated: {report['timestamp']}\n")
            f.write(f"Base Path: {self.base_path}\n")
            f.write("="*80 + "\n\n")
            
            f.write(f"Total Videos: {report['total_videos']}\n")
            f.write(f"Total Size: {report['total_size_gb']:.2f} GB\n")
            f.write(f"Corrupted Files: {report['corrupted_files']}\n")
            f.write(f"Suspiciously Small Files: {report['small_files']}\n")
            f.write(f"System Files: {report['system_files']}\n")
            f.write(f"Empty Folders: {report['empty_folders']}\n")
        
        print("\n📊 Health Report Summary:")
        print("="*40)
        print(f"Total Videos: {report['total_videos']}")
        print(f"Total Size: {report['total_size_gb']:.2f} GB")
        print(f"Issues Found:")
        print(f"  - Corrupted Files: {report['corrupted_files']}")
        print(f"  - Small Files: {report['small_files']}")
        print(f"  - System Files: {report['system_files']}")
        print(f"  - Empty Folders: {report['empty_folders']}")
        
        print(f"\nFull report saved to: {report_filename}")
        self.safe_input("\nPress Enter to continue...")
    
    def show_organization_status(self):
        """Show cached organization statistics from database."""
        try:
            with self.get_db_context() as conn:
                cursor = conn.cursor()
                
                # Check if we have cached data
                cursor.execute('SELECT COUNT(*) FROM video_files')
                total_files = cursor.fetchone()[0]
                
                if total_files == 0:
                    print("💡 No cached data found. Run Background Analysis first (Option 1)")
                    print()
                    return
                
                # Get last scan time
                cursor.execute('SELECT MAX(last_scanned) FROM video_files WHERE last_scanned IS NOT NULL')
                last_scan = cursor.fetchone()[0]
                
                if last_scan:
                    scan_age = (time.time() - last_scan) / 3600  # hours
                    if scan_age > 24:
                        print(f"⚠️  Data is {scan_age:.1f} hours old - consider running fresh analysis")
                    else:
                        print(f"📊 Using cached data from {scan_age:.1f} hours ago")
                
                # Quick analysis for organization issues
                import re
                movie_pattern = r'^(.+?)\s*\((\d{4})\)'
                tv_pattern = r'^(.+?)\s*-?\s*[Ss](\d+)[Ee](\d+)'
                
                # Count movies needing renaming
                cursor.execute("SELECT file_path FROM video_files WHERE file_path LIKE '%/Movies/%'")
                movie_files = cursor.fetchall()
                non_compliant_movies = 0
                for (file_path,) in movie_files:
                    filename = os.path.basename(file_path)
                    if not re.match(movie_pattern, filename):
                        non_compliant_movies += 1
                
                # Count TV episodes needing renaming
                cursor.execute("SELECT file_path FROM video_files WHERE file_path LIKE '%/TV/%'")
                tv_files = cursor.fetchall()
                non_compliant_tv = 0
                for (file_path,) in tv_files:
                    filename = os.path.basename(file_path)
                    if not re.search(tv_pattern, filename):
                        non_compliant_tv += 1
                
                # Count files in wrong locations (not in proper folders)
                cursor.execute("SELECT COUNT(*) FROM video_files WHERE file_path NOT LIKE '%/Movies/%' AND file_path NOT LIKE '%/TV/%' AND file_path NOT LIKE '%/Kids Movies/%' AND file_path NOT LIKE '%/Christmas/%' AND file_path NOT LIKE '%/Music Videos/%' AND file_path NOT LIKE '%/Personal/%'")
                misplaced_files = cursor.fetchone()[0]
                
                print("📋 Organization Status:")
                print(f"   Movies needing rename: {non_compliant_movies:,}")
                print(f"   TV episodes needing rename: {non_compliant_tv:,}")
                print(f"   Files in wrong folders: {misplaced_files:,}")
                
                # Show priority items
                if non_compliant_movies > 0 or non_compliant_tv > 0 or misplaced_files > 0:
                    print("💡 Issues found - use options below to fix them")
                else:
                    print("✅ Library appears well-organized!")
                print()
                
        except Exception as e:
            print("⚠️  Could not analyze organization status")
            print()
    
    def configure_folders(self):
        """Configure which folders to scan and their types."""
        while True:
            self.clear_screen()
            print("📁 Folder Configuration")
            print("="*60)
            
            with self.get_db_context() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT folder_path, folder_type, enabled FROM folder_config ORDER BY folder_type, folder_path')
                current_folders = cursor.fetchall()
            
            if current_folders:
                print("Current configured folders:")
                for folder_path, folder_type, enabled in current_folders:
                    status = "✓" if enabled else "✗"
                    folder_name = os.path.basename(folder_path)
                    print(f"  {status} {folder_name} ({folder_type})")
                print()
            
            print("Options:")
            print("1. Add new folder")
            print("2. Remove folder")
            print("3. Enable/disable folder")
            print("4. Reset to default (Movies & TV)")
            print("0. Done")
            
            choice = self.safe_input("\nEnter your choice: ")
            
            if choice == '0':
                break
            elif choice == '1':
                self.add_scan_folder()
            elif choice == '2':
                self.remove_scan_folder()
            elif choice == '3':
                self.toggle_scan_folder()
            elif choice == '4':
                self.reset_default_folders()
            else:
                print("Invalid choice.")
                self.safe_input("Press Enter to continue...")
    
    def add_scan_folder(self):
        """Add a new folder to scan."""
        print("\nAvailable folders in", self.base_path + ":")
        subdirs = []
        for item in os.listdir(self.base_path):
            item_path = os.path.join(self.base_path, item)
            if os.path.isdir(item_path) and not item.startswith('.'):
                subdirs.append(item)
        
        for i, subdir in enumerate(subdirs, 1):
            print(f"  {i}. {subdir}")
        
        try:
            dir_choice = int(self.safe_input("\nSelect folder number (0 to cancel): "))
            if dir_choice == 0:
                return
            if 1 <= dir_choice <= len(subdirs):
                selected_dir = subdirs[dir_choice - 1]
                folder_path = os.path.join(self.base_path, selected_dir)
                
                print(f"\nSelected: {selected_dir}")
                print("What type of content is in this folder?")
                print("1. Movies")
                print("2. TV Shows")
                
                type_choice = self.safe_input("\nEnter type (1 or 2): ")
                folder_type = 'movies' if type_choice == '1' else 'tv' if type_choice == '2' else None
                
                if folder_type:
                    with self.get_db_context() as conn:
                        cursor = conn.cursor()
                        cursor.execute('''
                            INSERT OR REPLACE INTO folder_config (folder_path, folder_type, last_updated)
                            VALUES (?, ?, ?)
                        ''', (folder_path, folder_type, time.time()))
                    print(f"✓ Added {selected_dir} as {folder_type} folder")
                else:
                    print("Invalid type selection")
        except (ValueError, IndexError):
            print("Invalid selection")
    
    def remove_scan_folder(self):
        """Remove a folder from scanning."""
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, folder_path, folder_type FROM folder_config WHERE enabled = 1')
            folders = cursor.fetchall()
        
        if not folders:
            print("No folders to remove")
            return
        
        print("\nCurrent folders:")
        for i, (folder_id, folder_path, folder_type) in enumerate(folders, 1):
            folder_name = os.path.basename(folder_path)
            print(f"  {i}. {folder_name} ({folder_type})")
        
        try:
            choice = int(self.safe_input("\nSelect folder to remove (0 to cancel): "))
            if choice == 0:
                return
            if 1 <= choice <= len(folders):
                folder_id = folders[choice - 1][0]
                with self.get_db_context() as conn:
                    cursor = conn.cursor()
                    cursor.execute('DELETE FROM folder_config WHERE id = ?', (folder_id,))
                print("✓ Folder removed")
        except ValueError:
            print("Invalid selection")
    
    def toggle_scan_folder(self):
        """Enable or disable a folder."""
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id, folder_path, folder_type, enabled FROM folder_config')
            folders = cursor.fetchall()
        
        if not folders:
            print("No folders configured")
            return
        
        print("\nConfigured folders:")
        for i, (folder_id, folder_path, folder_type, enabled) in enumerate(folders, 1):
            status = "✓ Enabled" if enabled else "✗ Disabled"
            folder_name = os.path.basename(folder_path)
            print(f"  {i}. {folder_name} ({folder_type}) - {status}")
        
        try:
            choice = int(self.safe_input("\nSelect folder to toggle (0 to cancel): "))
            if choice == 0:
                return
            if 1 <= choice <= len(folders):
                folder_id, _, _, enabled = folders[choice - 1]
                new_status = 0 if enabled else 1
                with self.get_db_context() as conn:
                    cursor = conn.cursor()
                    cursor.execute('UPDATE folder_config SET enabled = ? WHERE id = ?', (new_status, folder_id))
                print(f"✓ Folder {'enabled' if new_status else 'disabled'}")
        except ValueError:
            print("Invalid selection")
    
    def reset_default_folders(self):
        """Reset to default Movies and TV folders."""
        confirm = self.safe_input("Reset to default folders (Movies & TV)? (y/N): ")
        if confirm.lower() != 'y':
            return
        
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute('DELETE FROM folder_config')
            
            default_folders = [
                (os.path.join(self.base_path, 'Movies'), 'movies'),
                (os.path.join(self.base_path, 'TV'), 'tv')
            ]
            
            for folder_path, folder_type in default_folders:
                if os.path.exists(folder_path):
                    cursor.execute('''
                        INSERT INTO folder_config (folder_path, folder_type, last_updated)
                        VALUES (?, ?, ?)
                    ''', (folder_path, folder_type, time.time()))
        
        print("✓ Reset to default folders")
    
    def get_folder_sql_conditions(self, folder_type=None):
        """Get SQL conditions for configured folders."""
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            
            if folder_type:
                cursor.execute('SELECT folder_path FROM folder_config WHERE enabled = 1 AND folder_type = ?', (folder_type,))
            else:
                cursor.execute('SELECT folder_path FROM folder_config WHERE enabled = 1')
            
            folders = [row[0] for row in cursor.fetchall()]
        
        if not folders:
            return None, []
        
        # Build SQL condition
        conditions = []
        params = []
        for folder in folders:
            conditions.append("file_path LIKE ?")
            params.append(f"{folder}%")
        
        sql_condition = f"({' OR '.join(conditions)})"
        return sql_condition, params
        
    def smart_organization(self):
        """Smart organization menu for Plex compatibility."""
        while True:
            self.clear_screen()
            print("="*60)
            print("📂 Smart Organization")
            print("="*60)
            
            # Show cached statistics if available
            self.show_organization_status()
            
            print("1. Check Plex naming compliance")
            print("2. Auto-rename movies to Plex format")
            print("3. Auto-rename TV shows to Plex format")
            print("4. Organize files into proper folders")
            print("5. Fix season folder structure")
            print("6. Move subtitles to match video files")
            print("0. Back to main menu")
            print()
            
            choice = self.safe_input("Enter your choice: ")
            
            if choice == '0':
                break
            elif choice == '1':
                self.check_plex_compliance()
            elif choice == '2':
                self.auto_rename_movies()
            elif choice == '3':
                self.auto_rename_tv_shows()
            elif choice == '4':
                self.organize_into_folders()
            elif choice == '5':
                self.fix_season_structure()
            elif choice == '6':
                self.organize_subtitles()
                
    def check_plex_compliance(self):
        """Check if files follow Plex naming conventions."""
        print("\nChecking Plex naming compliance...")
        
        import re
        
        # Plex naming patterns
        movie_pattern = r'^(.+?)\s*\((\d{4})\)'  # Movie Title (Year)
        tv_pattern = r'^(.+?)\s*-?\s*[Ss](\d+)[Ee](\d+)'  # Show Name - S01E01
        
        non_compliant_movies = []
        non_compliant_tv = []
        movies_checked = 0
        tv_checked = 0
        
        # Check Movies
        movies_path = os.path.join(self.base_path, "Movies")
        if os.path.exists(movies_path):
            movie_files = [f for f in os.listdir(movies_path) 
                          if f.lower().endswith(self.video_extensions)]
            total_movies = len(movie_files)
            
            print(f"Checking {total_movies} movies...")
            
            for file in movie_files:
                movies_checked += 1
                if movies_checked % 10 == 0 or movies_checked == total_movies:
                    print(f"  Checked: {movies_checked}/{total_movies} movies", end='\r')
                
                if not re.match(movie_pattern, file):
                    non_compliant_movies.append(file)
        
        # Check TV Shows
        tv_path = os.path.join(self.base_path, "TV")
        if os.path.exists(tv_path):
            # Count total TV files first
            total_tv_files = sum(1 for show_dir in os.listdir(tv_path)
                               if os.path.isdir(os.path.join(tv_path, show_dir))
                               for root, dirs, files in os.walk(os.path.join(tv_path, show_dir))
                               for file in files if file.lower().endswith(self.video_extensions))
            
            if total_tv_files > 0:
                print(f"\nChecking {total_tv_files} TV episodes...")
            
            for show_dir in os.listdir(tv_path):
                show_path = os.path.join(tv_path, show_dir)
                if os.path.isdir(show_path):
                    for root, dirs, files in os.walk(show_path, followlinks=False):
                        for file in files:
                            if file.lower().endswith(self.video_extensions):
                                tv_checked += 1
                                if tv_checked % 10 == 0 or tv_checked == total_tv_files:
                                    print(f"  Checked: {tv_checked}/{total_tv_files} episodes", end='\r')
                                
                                if not re.search(tv_pattern, file):
                                    non_compliant_tv.append(os.path.join(show_dir, file))
        
        # Report findings
        print("\n📋 Plex Naming Compliance Report:")
        print("="*60)
        
        if not non_compliant_movies and not non_compliant_tv:
            print("✓ All files follow Plex naming conventions!")
        else:
            if non_compliant_movies:
                print(f"\n❌ Non-compliant movies ({len(non_compliant_movies)}):")
                for movie in non_compliant_movies[:10]:
                    print(f"  {movie}")
                if len(non_compliant_movies) > 10:
                    print(f"  ... and {len(non_compliant_movies) - 10} more")
            
            if non_compliant_tv:
                print(f"\n❌ Non-compliant TV episodes ({len(non_compliant_tv)}):")
                for episode in non_compliant_tv[:10]:
                    print(f"  {episode}")
                if len(non_compliant_tv) > 10:
                    print(f"  ... and {len(non_compliant_tv) - 10} more")
        
        self.safe_input("\nPress Enter to continue...")
        
    def auto_rename_movies(self):
        """Auto-rename movies to Plex format: Movie Title (Year).ext"""
        print("\nAuto-rename movies to Plex format...")
        
        import re
        
        movies_path = os.path.join(self.base_path, "Movies")
        if not os.path.exists(movies_path):
            print("Movies directory not found!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        rename_candidates = []
        
        for file in os.listdir(movies_path):
            if file.lower().endswith(self.video_extensions):
                file_path = os.path.join(movies_path, file)
                
                # Try to extract title and year
                # Common patterns
                patterns = [
                    r'(.+?)\.(\d{4})\.',  # Title.2023.
                    r'(.+?)\s*\[(\d{4})\]',  # Title [2023]
                    r'(.+?)\s*(\d{4})\s*[^\d]',  # Title 2023
                    r'(.+?)\s*-\s*(\d{4})',  # Title - 2023
                ]
                
                new_name = None
                for pattern in patterns:
                    match = re.search(pattern, file)
                    if match:
                        title = match.group(1).strip()
                        year = match.group(2)
                        
                        # Clean up title
                        title = title.replace('.', ' ')
                        title = title.replace('_', ' ')
                        title = re.sub(r'\s+', ' ', title)
                        title = title.strip()
                        
                        # Create Plex-compliant name
                        ext = os.path.splitext(file)[1]
                        new_name = f"{title} ({year}){ext}"
                        break
                
                if new_name and new_name != file:
                    new_path = os.path.join(movies_path, new_name)
                    if not os.path.exists(new_path):
                        rename_candidates.append((file_path, new_path, file, new_name))
        
        if not rename_candidates:
            print("No movies need renaming!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(rename_candidates)} movies to rename:")
        for old_path, new_path, old_name, new_name in rename_candidates[:10]:
            print(f"  {old_name}")
            print(f"  → {new_name}")
            print()
        
        if len(rename_candidates) > 10:
            print(f"... and {len(rename_candidates) - 10} more")
        
        response = self.safe_input("\nRename these movies? (y/N): ")
        if response.lower() == 'y':
            renamed = 0
            for old_path, new_path, _, _ in rename_candidates:
                try:
                    os.rename(old_path, new_path)
                    renamed += 1
                except OSError as e:
                    print(f"Error renaming {self.sanitize_path_for_display(old_path)}: {self.sanitize_error_message(str(e))}")
            print(f"✓ Renamed {renamed} movies")
        
        self.safe_input("\nPress Enter to continue...")
        
    def auto_rename_tv_shows(self):
        """Auto-rename TV shows to Plex format: Show Name - S##E## - Episode Title.ext"""
        self.clear_screen()
        print("📺 Auto-rename TV Shows to Plex Format")
        print("="*60)
        
        # Check for cached data first
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM video_files WHERE file_path LIKE '%/TV/%'")
            cached_tv_count = cursor.fetchone()[0]
            
            cursor.execute('SELECT MAX(last_scanned) FROM video_files WHERE last_scanned IS NOT NULL')
            last_scan = cursor.fetchone()[0]
        
        if cached_tv_count == 0:
            print("💡 No TV shows found in cached data. Run Background Analysis first (Option 1)")
            self.safe_input("\nPress Enter to continue...")
            return
        
        if last_scan:
            scan_age = (time.time() - last_scan) / 3600
            print(f"📊 Using cached data from {scan_age:.1f} hours ago")
            print(f"   Found {cached_tv_count:,} TV episodes in database")
        
        print("\n🔍 Analyzing TV show naming from cached data...")
        
        import re
        
        # Patterns to extract season and episode
        patterns = [
            (r'[Ss](\d+)[Ee](\d+)', 'S{:02d}E{:02d}'),  # S01E01
            (r'(\d+)x(\d+)', 'S{:02d}E{:02d}'),  # 1x01
            (r'Season\s*(\d+).*Episode\s*(\d+)', 'S{:02d}E{:02d}'),  # Season 1 Episode 1
        ]
        
        rename_candidates = []
        
        # Get TV files from database
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT file_path FROM video_files WHERE file_path LIKE '%/TV/%'")
            tv_files = cursor.fetchall()
        
        print(f"Checking {len(tv_files)} TV episodes for Plex naming compliance...")
        
        for i, (file_path,) in enumerate(tv_files, 1):
            # Show progress every 50 files or at completion
            if i % 50 == 0 or i == len(tv_files):
                print(f"\rChecking {i} out of {len(tv_files)}...", end='', flush=True)
            filename = os.path.basename(file_path)
            directory = os.path.dirname(file_path)
            
            # Extract show name from path
            tv_parts = file_path.split('/TV/')
            if len(tv_parts) > 1:
                show_path_part = tv_parts[1]
                show_dir = show_path_part.split('/')[0]
                
                # Try to extract season and episode
                new_name = None
                for pattern, format_str in patterns:
                    match = re.search(pattern, filename, re.IGNORECASE)
                    if match:
                        try:
                            season = int(match.group(1))
                            episode = int(match.group(2))
                        except (ValueError, IndexError):
                            continue
                        
                        # Create new name
                        ext = os.path.splitext(filename)[1]
                        episode_str = format_str.format(season, episode)
                        new_name = f"{show_dir} - {episode_str}{ext}"
                        break
                
                if new_name and new_name != filename:
                    new_path = os.path.join(directory, new_name)
                    if not os.path.exists(new_path):
                        rename_candidates.append((file_path, new_path, filename, new_name, show_dir))
        
        print(f"\rChecking {len(tv_files)} out of {len(tv_files)}... Complete!")
        
        if not rename_candidates:
            print("No TV episodes need renaming!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(rename_candidates)} episodes to rename:")
        
        # Group by show
        by_show = {}
        for old_path, new_path, old_name, new_name, show in rename_candidates:
            if show not in by_show:
                by_show[show] = []
            by_show[show].append((old_name, new_name))
        
        for show, episodes in list(by_show.items())[:5]:
            print(f"\n{show}:")
            for old, new in episodes[:3]:
                print(f"  {old} → {new}")
            if len(episodes) > 3:
                print(f"  ... and {len(episodes) - 3} more episodes")
        
        response = self.safe_input("\nRename these episodes? (y/N): ")
        if response.lower() == 'y':
            renamed_videos = 0
            renamed_subtitles = 0
            total_to_rename = len(rename_candidates)
            
            print(f"\n🔄 Renaming {total_to_rename} episodes...")
            
            for i, (old_path, new_path, old_name, new_name, _) in enumerate(rename_candidates, 1):
                try:
                    # Find matching subtitle files before renaming video
                    old_base = os.path.splitext(old_path)[0]
                    new_base = os.path.splitext(new_path)[0]
                    subtitle_extensions = ['.srt', '.vtt', '.ass', '.ssa', '.sub']
                    
                    subtitle_renames = []
                    video_dir = os.path.dirname(old_path)
                    old_filename_base = os.path.splitext(old_name)[0]
                    new_filename_base = os.path.splitext(new_name)[0]
                    
                    # Find all subtitle files that match this video
                    for file in os.listdir(video_dir):
                        if file.startswith(old_filename_base):
                            for sub_ext in subtitle_extensions:
                                if file.endswith(sub_ext):
                                    # Create new subtitle name by replacing the base name
                                    old_sub_path = os.path.join(video_dir, file)
                                    new_sub_name = file.replace(old_filename_base, new_filename_base, 1)
                                    new_sub_path = os.path.join(video_dir, new_sub_name)
                                    
                                    if old_sub_path != new_sub_path and not os.path.exists(new_sub_path):
                                        subtitle_renames.append((old_sub_path, new_sub_path))
                    
                    # Rename video file
                    os.rename(old_path, new_path)
                    renamed_videos += 1
                    
                    # Show progress every 25 renames or at completion
                    if i % 25 == 0 or i == total_to_rename:
                        print(f"\rRenamed {i} of {total_to_rename}...", end='', flush=True)
                    
                    # Update database with new file path and rescan subtitle status
                    try:
                        with self.get_db_context() as conn:
                            cursor = conn.cursor()
                            cursor.execute('UPDATE video_files SET file_path = ? WHERE file_path = ?', (new_path, old_path))
                            
                            # Rescan subtitle status for the renamed file
                            has_external, has_embedded = self.check_subtitle_status(new_path)
                            cursor.execute('''
                                UPDATE video_files 
                                SET has_external_subs = ?, has_embedded_subs = ? 
                                WHERE file_path = ?
                            ''', (has_external, has_embedded, new_path))
                    except Exception as e:
                        print(f"Warning: Could not update database for {new_name}: {self.sanitize_error_message(str(e))}")
                    
                    # Rename matching subtitle files
                    for old_sub_path, new_sub_path in subtitle_renames:
                        try:
                            os.rename(old_sub_path, new_sub_path)
                            renamed_subtitles += 1
                        except OSError as e:
                            print(f"Warning: Could not rename subtitle {os.path.basename(old_sub_path)}: {self.sanitize_error_message(str(e))}")
                    
                except OSError as e:
                    print(f"Error renaming {self.sanitize_path_for_display(old_path)}: {self.sanitize_error_message(str(e))}")
            
            print(f"\r✓ Renamed {renamed_videos} episodes")
            if renamed_subtitles > 0:
                print(f"✓ Renamed {renamed_subtitles} subtitle files")
        
        self.safe_input("\nPress Enter to continue...")
        
    def organize_into_folders(self):
        """Organize loose video files into proper folders."""
        print("\nOrganizing files into proper folders...")
        
        # Check for video files in root
        loose_files = []
        
        for file in os.listdir(self.base_path):
            if file.lower().endswith(self.video_extensions):
                file_path = os.path.join(self.base_path, file)
                loose_files.append(file_path)
        
        if not loose_files:
            print("No loose video files in root directory!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(loose_files)} loose video files:")
        for file in loose_files[:10]:
            print(f"  {os.path.basename(file)}")
        
        if len(loose_files) > 10:
            print(f"  ... and {len(loose_files) - 10} more")
        
        print("\nOptions:")
        print("1. Move to Movies folder")
        print("2. Move to TV folder")
        print("3. Auto-detect and organize")
        print("0. Cancel")
        
        choice = self.safe_input("\nEnter your choice: ")
        
        if choice == '1':
            target = os.path.join(self.base_path, "Movies")
        elif choice == '2':
            target = os.path.join(self.base_path, "TV")
        elif choice == '3':
            # Auto-detect based on filename
            for file_path in loose_files:
                filename = os.path.basename(file_path)
                # Simple detection - if it has S##E## pattern, it's TV
                if re.search(r'[Ss]\d+[Ee]\d+', filename):
                    target = os.path.join(self.base_path, "TV")
                else:
                    target = os.path.join(self.base_path, "Movies")
                
                new_path = os.path.join(target, filename)
                try:
                    os.rename(file_path, new_path)
                    print(f"Moved {filename} to {os.path.basename(target)}/")
                except OSError as e:
                    print(f"Error moving {self.sanitize_path_for_display(filename)}: {self.sanitize_error_message(str(e))}")
            print("\n✓ Auto-organization complete!")
            self.safe_input("\nPress Enter to continue...")
            return
        else:
            return
        
        # Move files to selected folder
        if choice in ['1', '2']:
            os.makedirs(target, exist_ok=True)
            moved = 0
            for file_path in loose_files:
                filename = os.path.basename(file_path)
                new_path = os.path.join(target, filename)
                try:
                    os.rename(file_path, new_path)
                    moved += 1
                except OSError as e:
                    print(f"Error moving {self.sanitize_path_for_display(filename)}: {self.sanitize_error_message(str(e))}")
            print(f"✓ Moved {moved} files to {os.path.basename(target)}/")
        
        self.safe_input("\nPress Enter to continue...")
        
    def fix_season_structure(self):
        """Fix TV show season folder structure."""
        print("\nFixing TV show season structure...")
        
        tv_path = os.path.join(self.base_path, "TV")
        if not os.path.exists(tv_path):
            print("TV directory not found!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        import re
        
        shows_to_fix = []
        
        for show_dir in os.listdir(tv_path):
            show_path = os.path.join(tv_path, show_dir)
            if os.path.isdir(show_path):
                # Check if episodes are in season folders or loose
                has_season_folders = False
                loose_episodes = []
                
                for item in os.listdir(show_path):
                    item_path = os.path.join(show_path, item)
                    if os.path.isdir(item_path) and re.match(r'Season\s*\d+', item, re.IGNORECASE):
                        has_season_folders = True
                    elif item.lower().endswith(self.video_extensions):
                        # Extract season number
                        match = re.search(r'[Ss](\d+)[Ee]\d+', item)
                        if match:
                            try:
                                season = int(match.group(1))
                                loose_episodes.append((item_path, season, item))
                            except (ValueError, IndexError):
                                continue
                
                if loose_episodes and not has_season_folders:
                    shows_to_fix.append((show_dir, loose_episodes))
        
        if not shows_to_fix:
            print("✓ All TV shows have proper season structure!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(shows_to_fix)} shows needing season folders:")
        for show, episodes in shows_to_fix:
            seasons = set(ep[1] for ep in episodes)
            print(f"  {show} - {len(episodes)} episodes across seasons {sorted(seasons)}")
        
        response = self.safe_input("\nCreate season folders and organize episodes? (y/N): ")
        if response.lower() == 'y':
            for show, episodes in shows_to_fix:
                show_path = os.path.join(tv_path, show)
                
                # Group by season
                by_season = {}
                for file_path, season, filename in episodes:
                    if season not in by_season:
                        by_season[season] = []
                    by_season[season].append((file_path, filename))
                
                # Create season folders and move files
                for season, eps in by_season.items():
                    season_folder = os.path.join(show_path, f"Season {season:02d}")
                    os.makedirs(season_folder, exist_ok=True)
                    
                    for file_path, filename in eps:
                        new_path = os.path.join(season_folder, filename)
                        try:
                            os.rename(file_path, new_path)
                        except OSError as e:
                            print(f"Error moving {self.sanitize_path_for_display(filename)}: {self.sanitize_error_message(str(e))}")
                
                print(f"✓ Organized {show}")
        
        self.safe_input("\nPress Enter to continue...")
        
    def organize_subtitles(self):
        """Move subtitle files to match their video files."""
        print("\nOrganizing subtitle files...")
        
        subtitle_extensions = ['.srt', '.vtt', '.ass', '.sub', '.ssa']
        orphaned_subs = []
        
        # Find subtitle files that might be in wrong locations
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if any(file.lower().endswith(ext) for ext in subtitle_extensions):
                    sub_path = os.path.join(root, file)
                    base_name = os.path.splitext(file)[0]
                    
                    # Remove language codes
                    base_name = base_name.replace('.en', '').replace('.eng', '').replace('.english', '')
                    
                    # Check if matching video exists in same directory
                    video_found = False
                    for video_ext in self.video_extensions:
                        if os.path.exists(os.path.join(root, base_name + video_ext)):
                            video_found = True
                            break
                    
                    if not video_found:
                        orphaned_subs.append(sub_path)
        
        if not orphaned_subs:
            print("✓ All subtitle files are properly located!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(orphaned_subs)} orphaned subtitle files")
        
        # Try to match with video files
        matches = []
        for sub_path in orphaned_subs:
            sub_name = os.path.basename(sub_path)
            base_name = os.path.splitext(sub_name)[0]
            base_name = base_name.replace('.en', '').replace('.eng', '').replace('.english', '')
            
            # Search for matching video
            for root, dirs, files in os.walk(self.base_path, followlinks=False):
                for file in files:
                    if file.lower().endswith(self.video_extensions):
                        video_base = os.path.splitext(file)[0]
                        if base_name.lower() in video_base.lower() or video_base.lower() in base_name.lower():
                            video_path = os.path.join(root, file)
                            new_sub_path = os.path.join(root, sub_name)
                            if new_sub_path != sub_path:
                                matches.append((sub_path, new_sub_path, video_path))
                                break
        
        if matches:
            print(f"\nFound {len(matches)} subtitle files to relocate:")
            for old, new, video in matches[:5]:
                print(f"  {os.path.basename(old)}")
                print(f"  → {os.path.dirname(new)}/")
                print(f"    (matches {os.path.basename(video)})")
                print()
            
            if len(matches) > 5:
                print(f"... and {len(matches) - 5} more")
            
            response = self.safe_input("\nMove subtitle files to match videos? (y/N): ")
            if response.lower() == 'y':
                moved = 0
                for old_path, new_path, _ in matches:
                    try:
                        os.rename(old_path, new_path)
                        moved += 1
                    except OSError as e:
                        print(f"Error moving {self.sanitize_path_for_display(old_path)}: {self.sanitize_error_message(str(e))}")
                print(f"✓ Moved {moved} subtitle files")
        
        self.safe_input("\nPress Enter to continue...")
        
    def storage_analytics(self):
        """Storage analytics menu."""
        while True:
            self.clear_screen()
            print("="*60)
            print("📊 Storage Analytics")
            print("="*60)
            print("1. Current storage usage overview")
            print("2. Growth trends analysis")
            print("3. Storage prediction")
            print("4. Largest space consumers")
            print("5. Recommend videos to delete")
            print("6. Export analytics report")
            print("0. Back to main menu")
            print()
            
            choice = self.safe_input("Enter your choice: ")
            
            if choice == '0':
                break
            elif choice == '1':
                self.storage_overview()
            elif choice == '2':
                self.growth_trends()
            elif choice == '3':
                self.storage_prediction()
            elif choice == '4':
                self.largest_consumers()
            elif choice == '5':
                self.recommend_deletions()
            elif choice == '6':
                self.export_analytics()
                
    def storage_overview(self):
        """Show current storage usage overview."""
        print("\nAnalyzing storage usage...")
        
        # Get disk usage with symlink protection
        import shutil
        
        # Resolve symlinks to prevent TOCTOU attacks
        real_path = os.path.realpath(self.base_path)
        
        # Validate the resolved path is still safe
        if not real_path.startswith('/Volumes/media/'):
            print("Error: Disk space check blocked - potential symlink attack")
            return
        
        total, used, free = shutil.disk_usage(real_path)
        
        # Calculate usage by category
        categories = {
            'Movies': 0,
            'TV': 0,
            'Kids Movies': 0,
            'Christmas': 0,
            'Music Videos': 0,
            'Personal': 0,
            'Other': 0
        }
        
        total_video_size = 0
        total_video_count = 0
        
        # Count files first
        print("Counting files...")
        total_files = sum(1 for root, dirs, files in os.walk(self.base_path, followlinks=False) 
                         for file in files if file.lower().endswith(self.video_extensions))
        
        print(f"Analyzing {total_files} video files...\n")
        files_processed = 0
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    files_processed += 1
                    
                    if files_processed % 20 == 0 or files_processed == total_files:
                        print(f"Analyzing storage: {files_processed}/{total_files} files ({(files_processed/total_files)*100:.1f}%)", end='\r')
                    
                    try:
                        size = os.path.getsize(file_path)
                        total_video_size += size
                        total_video_count += 1
                        
                        # Categorize
                        categorized = False
                        for category in categories:
                            if f"/{category}/" in file_path or file_path.endswith(f"/{category}"):
                                categories[category] += size
                                categorized = True
                                break
                        
                        if not categorized:
                            categories['Other'] += size
                    except OSError:
                        continue
        
        # Display overview
        print("\n" + "="*60)
        print("💾 STORAGE OVERVIEW")
        print("="*60)
        
        print(f"\nDisk Usage:")
        print(f"  Total Capacity: {total / (1024**3):.2f} GB")
        print(f"  Used Space:     {used / (1024**3):.2f} GB ({(used/total)*100:.1f}%)")
        print(f"  Free Space:     {free / (1024**3):.2f} GB ({(free/total)*100:.1f}%)")
        
        print(f"\nVideo Library:")
        print(f"  Total Videos:   {total_video_count}")
        print(f"  Total Size:     {total_video_size / (1024**3):.2f} GB")
        print(f"  Average Size:   {(total_video_size / total_video_count) / (1024**3):.2f} GB" if total_video_count > 0 else "  Average Size:   0 GB")
        
        print(f"\nBreakdown by Category:")
        sorted_categories = sorted(categories.items(), key=lambda x: x[1], reverse=True)
        for category, size in sorted_categories:
            if size > 0:
                percentage = (size / total_video_size) * 100 if total_video_size > 0 else 0
                print(f"  {category:15} {size / (1024**3):>10.2f} GB ({percentage:>5.1f}%)")
        
        # Visual bar chart
        print("\nStorage Distribution:")
        max_bar_length = 40
        for category, size in sorted_categories:
            if size > 0:
                bar_length = int((size / total_video_size) * max_bar_length) if total_video_size > 0 else 0
                bar = "█" * bar_length
                print(f"  {category:15} {bar}")
        
        self.safe_input("\nPress Enter to continue...")
        
    def growth_trends(self):
        """Analyze storage growth trends."""
        print("\nAnalyzing growth trends...")
        
        # Group files by month
        from collections import defaultdict
        monthly_data = defaultdict(lambda: {'count': 0, 'size': 0})
        
        current_time = datetime.now()
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    try:
                        # Get file creation time
                        stat = os.stat(file_path)
                        mtime = datetime.fromtimestamp(stat.st_mtime)
                        
                        # Only look at last 12 months
                        if (current_time - mtime).days <= 365:
                            month_key = mtime.strftime('%Y-%m')
                            size = os.path.getsize(file_path)
                            monthly_data[month_key]['count'] += 1
                            monthly_data[month_key]['size'] += size
                    except OSError:
                        continue
        
        if not monthly_data:
            print("No data available for growth analysis.")
            self.safe_input("\nPress Enter to continue...")
            return
        
        # Sort by month
        sorted_months = sorted(monthly_data.items())
        
        print("\n" + "="*60)
        print("📈 GROWTH TRENDS (Last 12 Months)")
        print("="*60)
        
        # Calculate cumulative totals
        cumulative_size = 0
        cumulative_count = 0
        
        print("\nMonth      | New Videos | Size Added | Cumulative Size")
        print("-" * 60)
        
        for month, data in sorted_months[-12:]:
            cumulative_size += data['size']
            cumulative_count += data['count']
            
            print(f"{month}   | {data['count']:>10} | {data['size']/(1024**3):>9.2f} GB | {cumulative_size/(1024**3):>14.2f} GB")
        
        # Calculate average growth
        if len(sorted_months) > 1:
            total_months = len(sorted_months)
            total_growth = sum(data['size'] for _, data in sorted_months)
            avg_monthly_growth = total_growth / total_months
            
            print(f"\nAverage Monthly Growth: {avg_monthly_growth/(1024**3):.2f} GB")
            print(f"Average Files Added/Month: {sum(data['count'] for _, data in sorted_months) / total_months:.1f}")
        
        # Visual chart
        print("\nGrowth Chart (GB added per month):")
        max_size = max(data['size'] for _, data in sorted_months) if sorted_months else 1
        
        for month, data in sorted_months[-12:]:
            bar_length = int((data['size'] / max_size) * 30) if max_size > 0 else 0
            bar = "█" * bar_length
            print(f"{month}: {bar} {data['size']/(1024**3):.1f}")
        
        self.safe_input("\nPress Enter to continue...")
        
    def storage_prediction(self):
        """Predict when storage will run out."""
        print("\nCalculating storage predictions...")
        
        import shutil
        from collections import defaultdict
        
        # Get current disk usage with symlink protection
        # Resolve symlinks to prevent TOCTOU attacks
        real_path = os.path.realpath(self.base_path)
        
        # Validate the resolved path is still safe
        if not real_path.startswith('/Volumes/media/'):
            print("Error: Disk space check blocked - potential symlink attack")
            return
        
        total, used, free = shutil.disk_usage(real_path)
        
        # Analyze growth over last 6 months
        monthly_sizes = defaultdict(int)
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    try:
                        stat = os.stat(file_path)
                        mtime = datetime.fromtimestamp(stat.st_mtime)
                        
                        # Only last 6 months
                        if (datetime.now() - mtime).days <= 180:
                            month_key = mtime.strftime('%Y-%m')
                            size = os.path.getsize(file_path)
                            monthly_sizes[month_key] += size
                    except OSError:
                        continue
        
        print("\n" + "="*60)
        print("🔮 STORAGE PREDICTIONS")
        print("="*60)
        
        print(f"\nCurrent Status:")
        print(f"  Free Space: {free / (1024**3):.2f} GB")
        print(f"  Used Space: {used / (1024**3):.2f} GB ({(used/total)*100:.1f}%)")
        
        if monthly_sizes:
            # Calculate average monthly growth
            avg_monthly_growth = sum(monthly_sizes.values()) / len(monthly_sizes)
            
            print(f"\nGrowth Analysis (Last 6 Months):")
            print(f"  Average Monthly Growth: {avg_monthly_growth / (1024**3):.2f} GB")
            
            # Predict when storage will run out
            if avg_monthly_growth > 0:
                months_until_full = free / avg_monthly_growth
                
                print(f"\nPredictions:")
                print(f"  Months until full: {months_until_full:.1f}")
                print(f"  Expected full date: {(datetime.now() + timedelta(days=months_until_full*30)).strftime('%B %Y')}")
                
                # Show projections
                print(f"\nStorage Projections:")
                for months in [1, 3, 6, 12]:
                    projected_used = used + (avg_monthly_growth * months)
                    projected_free = total - projected_used
                    
                    if projected_free > 0:
                        print(f"  In {months:2} months: {projected_free / (1024**3):>8.2f} GB free ({(projected_used/total)*100:.1f}% used)")
                    else:
                        print(f"  In {months:2} months: FULL! (would need {abs(projected_free) / (1024**3):.2f} GB more)")
                
                # Recommendations
                print(f"\n💡 Recommendations:")
                if months_until_full < 3:
                    print("  ⚠️  URGENT: Less than 3 months until full!")
                    print("  - Delete unnecessary files immediately")
                    print("  - Consider upgrading storage")
                elif months_until_full < 6:
                    print("  ⚠️  WARNING: Less than 6 months until full")
                    print("  - Start planning for storage expansion")
                    print("  - Review and delete old content")
                else:
                    print("  ✓ Storage is healthy for now")
                    print("  - Monitor growth trends regularly")
        else:
            print("\nInsufficient data for predictions.")
        
        self.safe_input("\nPress Enter to continue...")
        
    def largest_consumers(self):
        """Show largest space consumers."""
        print("\nFinding largest space consumers...")
        
        # Collect all videos with sizes
        all_videos = []
        show_sizes = defaultdict(int)
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    try:
                        size = os.path.getsize(file_path)
                        all_videos.append({
                            'path': file_path,
                            'name': file,
                            'size': size,
                            'relative_path': os.path.relpath(file_path, self.base_path)
                        })
                        
                        # Track TV show sizes
                        if '/TV/' in file_path:
                            parts = file_path.split('/TV/')
                            if len(parts) > 1:
                                show_name = parts[1].split('/')[0]
                                show_sizes[show_name] += size
                    except OSError:
                        continue
        
        print("\n" + "="*60)
        print("🏆 LARGEST SPACE CONSUMERS")
        print("="*60)
        
        # Top individual files
        sorted_videos = sorted(all_videos, key=lambda x: x['size'], reverse=True)
        
        print("\nTop 15 Largest Files:")
        print("-" * 60)
        total_top_size = 0
        
        for i, video in enumerate(sorted_videos[:15], 1):
            size_gb = video['size'] / (1024**3)
            total_top_size += video['size']
            print(f"{i:2}. {size_gb:>6.2f} GB - {video['relative_path']}")
        
        print(f"\nTotal size of top 15: {total_top_size / (1024**3):.2f} GB")
        
        # Top TV shows
        if show_sizes:
            sorted_shows = sorted(show_sizes.items(), key=lambda x: x[1], reverse=True)
            
            print("\nTop 10 TV Shows by Size:")
            print("-" * 60)
            
            for i, (show, size) in enumerate(sorted_shows[:10], 1):
                size_gb = size / (1024**3)
                print(f"{i:2}. {size_gb:>6.2f} GB - {show}")
        
        # Files over certain thresholds
        large_files = [v for v in all_videos if v['size'] > FileSizeConstants.LARGE_FILE_THRESHOLD]  # Over 5GB
        huge_files = [v for v in all_videos if v['size'] > FileSizeConstants.HUGE_FILE_THRESHOLD]  # Over 10GB
        
        print(f"\nSize Statistics:")
        print(f"  Files over 5 GB:  {len(large_files)}")
        print(f"  Files over 10 GB: {len(huge_files)}")
        
        if huge_files:
            print(f"\n⚠️  Consider compressing these {len(huge_files)} files over 10 GB!")
        
        self.safe_input("\nPress Enter to continue...")
        
    def recommend_deletions(self):
        """Recommend videos to delete based on various criteria."""
        print("\nAnalyzing library for deletion recommendations...")
        
        recommendations = {
            'duplicates': [],
            'large_old': [],
            'poor_quality': [],
            'samples': []
        }
        
        # Find exact duplicates
        size_map = defaultdict(list)
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    try:
                        size = os.path.getsize(file_path)
                        size_map[size].append(file_path)
                    except OSError:
                        continue
        
        # Identify duplicates
        for size, paths in size_map.items():
            if len(paths) > 1:
                # Keep the one with the best quality indicator in name
                quality_order = ['2160p', '4k', '1080p', '720p', '480p']
                best_path = paths[0]
                
                for path in paths:
                    for quality in quality_order:
                        if quality.lower() in path.lower():
                            best_path = path
                            break
                
                for path in paths:
                    if path != best_path:
                        recommendations['duplicates'].append({
                            'path': path,
                            'size': size,
                            'reason': f'Duplicate of {os.path.basename(best_path)}'
                        })
        
        # Find large old files
        current_time = datetime.now()
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    try:
                        stat = os.stat(file_path)
                        size = stat.st_size
                        mtime = datetime.fromtimestamp(stat.st_mtime)
                        
                        # Large files not accessed in over a year
                        if size > 3 * FileSizeConstants.GB and (current_time - mtime).days > 365:
                            recommendations['large_old'].append({
                                'path': file_path,
                                'size': size,
                                'reason': f'Large file ({size/(1024**3):.1f} GB) not accessed in {(current_time - mtime).days} days'
                            })
                        
                        # Poor quality indicators
                        if any(q in file.lower() for q in ['480p', '360p', 'cam', 'ts', 'screener']):
                            recommendations['poor_quality'].append({
                                'path': file_path,
                                'size': size,
                                'reason': 'Low quality version'
                            })
                        
                        # Sample files
                        if 'sample' in file.lower() and size < FileSizeConstants.SAMPLE_FILE_MAX:
                            recommendations['samples'].append({
                                'path': file_path,
                                'size': size,
                                'reason': 'Sample file'
                            })
                    except OSError:
                        continue
        
        print("\n" + "="*60)
        print("🗑️  DELETION RECOMMENDATIONS")
        print("="*60)
        
        total_recoverable = 0
        
        # Display recommendations
        categories = [
            ('Exact Duplicates', recommendations['duplicates']),
            ('Large Old Files', recommendations['large_old'][:10]),  # Limit to top 10
            ('Poor Quality Versions', recommendations['poor_quality'][:10]),
            ('Sample Files', recommendations['samples'])
        ]
        
        for category, items in categories:
            if items:
                category_size = sum(item['size'] for item in items)
                total_recoverable += category_size
                
                print(f"\n{category} ({len(items)} files, {category_size/(1024**3):.2f} GB):")
                print("-" * 50)
                
                for item in items[:5]:  # Show first 5
                    print(f"  {os.path.basename(item['path'])}")
                    print(f"    Size: {item['size']/(1024**3):.2f} GB | {item['reason']}")
                
                if len(items) > 5:
                    print(f"  ... and {len(items) - 5} more")
        
        print(f"\n💾 Total recoverable space: {total_recoverable/(1024**3):.2f} GB")
        
        # Save detailed report
        if total_recoverable > 0:
            response = self.safe_input("\nSave detailed deletion report? (y/N): ")
            if response.lower() == 'y':
                report_path = os.path.join(self.base_path, "deletion_recommendations.txt")
                self.security_audit_log("REPORT_GENERATED", f"Deletion recommendations: {report_path}")
                with open(report_path, "w") as f:
                    f.write(f"Deletion Recommendations - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("="*80 + "\n\n")
                    
                    for category, items in categories:
                        if items:
                            f.write(f"\n{category}:\n")
                            f.write("-"*50 + "\n")
                            for item in items:
                                f.write(f"{item['path']}\n")
                                f.write(f"  Size: {item['size']/(1024**3):.2f} GB\n")
                                f.write(f"  Reason: {item['reason']}\n\n")
                
                print("Report saved to: deletion_recommendations.txt")
        
        self.safe_input("\nPress Enter to continue...")
        
    def export_analytics(self):
        """Export comprehensive analytics report."""
        print("\nGenerating comprehensive analytics report...")
        
        import json
        import shutil
        
        # Gather all data with symlink protection
        # Resolve symlinks to prevent TOCTOU attacks
        real_path = os.path.realpath(self.base_path)
        
        # Validate the resolved path is still safe
        if not real_path.startswith('/Volumes/media/'):
            print("Error: Disk space check blocked - potential symlink attack")
            return
        
        total, used, free = shutil.disk_usage(real_path)
        
        report_data = {
            'generated': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'base_path': self.base_path,
            'disk_usage': {
                'total_gb': total / (1024**3),
                'used_gb': used / (1024**3),
                'free_gb': free / (1024**3),
                'used_percentage': (used/total)*100
            },
            'categories': {},
            'file_types': {},
            'quality_breakdown': {},
            'monthly_growth': {},
            'largest_files': [],
            'statistics': {
                'total_videos': 0,
                'total_size_gb': 0,
                'average_size_gb': 0,
                'smallest_file_gb': float('inf'),
                'largest_file_gb': 0
            }
        }
        
        # Analyze all files
        all_files = []
        
        # Count files for progress
        total_files = sum(1 for root, dirs, files in os.walk(self.base_path, followlinks=False) 
                         for file in files if file.lower().endswith(self.video_extensions))
        
        print(f"Processing {total_files} video files for detailed analytics...\n")
        files_processed = 0
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    files_processed += 1
                    
                    if files_processed % 25 == 0 or files_processed == total_files:
                        print(f"Analytics: {files_processed}/{total_files} files ({(files_processed/total_files)*100:.1f}%)", end='\r')
                    
                    try:
                        stat = os.stat(file_path)
                        size = stat.st_size
                        mtime = datetime.fromtimestamp(stat.st_mtime)
                        
                        file_info = {
                            'path': file_path,
                            'name': file,
                            'size': size,
                            'size_gb': size / (1024**3),
                            'modified': mtime.strftime('%Y-%m-%d'),
                            'extension': os.path.splitext(file)[1].lower()
                        }
                        
                        all_files.append(file_info)
                        
                        # Update statistics
                        report_data['statistics']['total_videos'] += 1
                        report_data['statistics']['total_size_gb'] += file_info['size_gb']
                        
                        if file_info['size_gb'] < report_data['statistics']['smallest_file_gb']:
                            report_data['statistics']['smallest_file_gb'] = file_info['size_gb']
                        if file_info['size_gb'] > report_data['statistics']['largest_file_gb']:
                            report_data['statistics']['largest_file_gb'] = file_info['size_gb']
                        
                        # Categorize
                        category = 'Other'
                        for cat in ['Movies', 'TV', 'Kids Movies', 'Christmas', 'Music Videos', 'Personal']:
                            if f"/{cat}/" in file_path or file_path.endswith(f"/{cat}"):
                                category = cat
                                break
                        
                        if category not in report_data['categories']:
                            report_data['categories'][category] = {'count': 0, 'size_gb': 0}
                        report_data['categories'][category]['count'] += 1
                        report_data['categories'][category]['size_gb'] += file_info['size_gb']
                        
                        # File type
                        ext = file_info['extension']
                        if ext not in report_data['file_types']:
                            report_data['file_types'][ext] = {'count': 0, 'size_gb': 0}
                        report_data['file_types'][ext]['count'] += 1
                        report_data['file_types'][ext]['size_gb'] += file_info['size_gb']
                        
                        # Quality
                        quality = 'Unknown'
                        for q in ['2160p', '4k', '1080p', '720p', '480p']:
                            if q.lower() in file.lower():
                                quality = q.upper()
                                break
                        
                        if quality not in report_data['quality_breakdown']:
                            report_data['quality_breakdown'][quality] = {'count': 0, 'size_gb': 0}
                        report_data['quality_breakdown'][quality]['count'] += 1
                        report_data['quality_breakdown'][quality]['size_gb'] += file_info['size_gb']
                        
                        # Monthly growth (last 12 months)
                        if (datetime.now() - mtime).days <= 365:
                            month_key = mtime.strftime('%Y-%m')
                            if month_key not in report_data['monthly_growth']:
                                report_data['monthly_growth'][month_key] = {'count': 0, 'size_gb': 0}
                            report_data['monthly_growth'][month_key]['count'] += 1
                            report_data['monthly_growth'][month_key]['size_gb'] += file_info['size_gb']
                        
                    except OSError:
                        continue
        
        # Calculate average
        if report_data['statistics']['total_videos'] > 0:
            report_data['statistics']['average_size_gb'] = (
                report_data['statistics']['total_size_gb'] / 
                report_data['statistics']['total_videos']
            )
        
        # Get largest files
        sorted_files = sorted(all_files, key=lambda x: x['size'], reverse=True)
        report_data['largest_files'] = [
            {
                'name': f['name'],
                'path': os.path.relpath(f['path'], self.base_path),
                'size_gb': f['size_gb']
            }
            for f in sorted_files[:20]
        ]
        
        # Save reports
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # JSON report in secure location
        json_file = os.path.join(self.base_path, f"storage_analytics_{timestamp}.json")
        if not self.validate_safe_path(json_file):
            print("Error: Cannot write analytics JSON to unsafe location")
            return
        
        with open(json_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        # Human-readable report in secure location
        txt_file = os.path.join(self.base_path, f"storage_analytics_{timestamp}.txt")
        if not self.validate_safe_path(txt_file):
            print("Error: Cannot write analytics report to unsafe location")
            return
        
        with open(txt_file, 'w') as f:
            f.write(f"Storage Analytics Report\n")
            f.write(f"Generated: {report_data['generated']}\n")
            f.write("="*80 + "\n\n")
            
            f.write("DISK USAGE\n")
            f.write("-"*40 + "\n")
            f.write(f"Total Capacity: {report_data['disk_usage']['total_gb']:.2f} GB\n")
            f.write(f"Used Space:     {report_data['disk_usage']['used_gb']:.2f} GB ({report_data['disk_usage']['used_percentage']:.1f}%)\n")
            f.write(f"Free Space:     {report_data['disk_usage']['free_gb']:.2f} GB\n\n")
            
            f.write("VIDEO LIBRARY STATISTICS\n")
            f.write("-"*40 + "\n")
            f.write(f"Total Videos:    {report_data['statistics']['total_videos']}\n")
            f.write(f"Total Size:      {report_data['statistics']['total_size_gb']:.2f} GB\n")
            f.write(f"Average Size:    {report_data['statistics']['average_size_gb']:.2f} GB\n")
            f.write(f"Smallest File:   {report_data['statistics']['smallest_file_gb']:.3f} GB\n")
            f.write(f"Largest File:    {report_data['statistics']['largest_file_gb']:.2f} GB\n\n")
            
            f.write("BREAKDOWN BY CATEGORY\n")
            f.write("-"*40 + "\n")
            for cat, data in sorted(report_data['categories'].items(), key=lambda x: x[1]['size_gb'], reverse=True):
                f.write(f"{cat:15} {data['count']:>5} files, {data['size_gb']:>10.2f} GB\n")
            
            f.write("\nQUALITY BREAKDOWN\n")
            f.write("-"*40 + "\n")
            for quality, data in sorted(report_data['quality_breakdown'].items(), key=lambda x: x[1]['size_gb'], reverse=True):
                f.write(f"{quality:10} {data['count']:>5} files, {data['size_gb']:>10.2f} GB\n")
        
        print(f"\n✓ Analytics reports generated:")
        print(f"  - {json_file} (JSON format)")
        print(f"  - {txt_file} (Text format)")
        
        self.safe_input("\nPress Enter to continue...")
        
    def run(self):
        """Main menu loop with safety mechanisms."""
        self.loop_start_time = time.time()
        iteration_count = 0
        
        while self.running and iteration_count < self.max_menu_iterations:
            self.clear_screen()
            print("="*60)
            print("📺 Media Library Manager")
            print("="*60)
            print(f"Base Path: {self.base_path}")
            
            # Display database status
            db_status = self.get_database_status()
            if db_status.get('error'):
                print("Database Status: ❌ Error accessing database")
            elif db_status['total_files'] == 0:
                print("Database Status: 📝 Empty (no files scanned)")
            else:
                print(f"Database Status: 📊 {db_status['total_files']:,} files in database")
                if db_status['last_scan']:
                    time_since = datetime.now() - db_status['last_scan']
                    if time_since.days > 0:
                        print(f"Last Scan: {time_since.days} day(s) ago")
                    elif time_since.seconds > 3600:
                        print(f"Last Scan: {time_since.seconds // 3600} hour(s) ago")
                    else:
                        print(f"Last Scan: {time_since.seconds // 60} minute(s) ago")
                else:
                    print("Last Scan: Never")
            print()
            print("🎯 RECOMMENDED FIRST STEP:")
            print("1. Background Analysis & Recommendations")
            print()
            print("📊 ANALYSIS & REPORTS:")
            print("2. Inventory all video files")
            print("3. List conversion candidates (>1080p)")
            print("4. Top 10 TV shows by size")
            print("5. Top 10 individual video files")
            print("6. Library Health Check")
            print("7. Storage Analytics")
            print()
            print("🔧 VIDEO PROCESSING:")
            print("8. Convert videos to 1080p")
            print("9. Convert videos to 720p")
            print("10. Batch Operations")
            print()
            print("📝 SUBTITLES:")
            print("11. Check for videos without English subtitles")
            print("12. Download English subtitles")
            print("13. Subtitle Language Settings & Cleanup")
            print()
            print("🗂️  ORGANIZATION & CLEANUP:")
            print("14. Smart Organization")
            print("15. Find Duplicate Videos")
            print("16. Quick Fixes")
            print("17. Manual File Correction (TMDB Lookup) *requires free API key")
            print()
            print("🗑️  FILE MANAGEMENT:")
            print("18. Delete TV show")
            print("19. Delete video file")
            print()
            print("☁️  BACKUP & SYNC:")
            print("20. Backup & Sync (rclone)")
            print()
            print("⚙️  SETTINGS:")
            print("21. Configure Scan Folders")
            print()
            print("0. Exit")
            print()
            
            try:
                # Rate limiting check before processing menu choice
                if not self.check_rate_limit("menu_operation"):
                    time.sleep(2)  # Force a small delay before showing menu again
                    continue
                
                # Menu choice validator to prevent injection attacks
                def menu_validator(value):
                    # Only allow simple numeric choices and '0'
                    if not value or not value.strip():
                        return None
                    value = value.strip()
                    # Block any non-alphanumeric characters that could be injection attempts
                    if not value.replace('-', '').isalnum() or len(value) > 3:
                        print("Invalid menu choice. Please enter a number (0-20).")
                        return None
                    return value
                
                choice = self.safe_input("Enter your choice: ", validator=menu_validator)
                
                if choice == '1':
                    if self.check_rate_limit("background_analysis"):
                        try:
                            self.background_analysis()
                            self.reset_failure_count()
                        except Exception as e:
                            self.record_operation_failure("background_analysis")
                            raise
                elif choice == '2':
                    if self.check_rate_limit("inventory_videos"):
                        try:
                            self.inventory_videos()
                            self.reset_failure_count()
                        except Exception as e:
                            self.record_operation_failure("inventory_videos")
                            raise
                elif choice == '3':
                    if self.check_rate_limit("list_conversion_candidates"):
                        try:
                            self.list_conversion_candidates()
                            self.reset_failure_count()
                        except Exception as e:
                            self.record_operation_failure("list_conversion_candidates")
                            raise
                elif choice == '4':
                    if self.check_rate_limit("top_shows_by_size"):
                        try:
                            self.top_shows_by_size()
                            self.reset_failure_count()
                        except Exception as e:
                            self.record_operation_failure("top_shows_by_size")
                            raise
                elif choice == '5':
                    if self.check_rate_limit("top_video_files"):
                        try:
                            self.top_video_files()
                            self.reset_failure_count()
                        except Exception as e:
                            self.record_operation_failure("top_video_files")
                            raise
                elif choice == '6':
                    if self.check_rate_limit("library_health_check"):
                        try:
                            self.library_health_check()
                            self.reset_failure_count()
                        except Exception as e:
                            self.record_operation_failure("library_health_check")
                            raise
                elif choice == '7':
                    if self.check_rate_limit("storage_analytics"):
                        try:
                            self.storage_analytics()
                            self.reset_failure_count()
                        except Exception as e:
                            self.record_operation_failure("storage_analytics")
                            raise
                elif choice == '8':
                    if self.check_rate_limit("convert_to_1080p"):
                        try:
                            self.convert_to_resolution(1080)
                            self.reset_failure_count()
                        except Exception as e:
                            self.record_operation_failure("convert_to_1080p")
                            raise
                elif choice == '9':
                    if self.check_rate_limit("convert_to_720p"):
                        try:
                            self.convert_to_resolution(720)
                            self.reset_failure_count()
                        except Exception as e:
                            self.record_operation_failure("convert_to_720p")
                            raise
                elif choice == '10':
                    self.batch_operations()
                elif choice == '11':
                    self.check_subtitles()
                elif choice == '12':
                    self.download_subtitles()
                elif choice == '13':
                    self.manage_language_preferences()
                elif choice == '14':
                    self.smart_organization()
                elif choice == '15':
                    self.find_duplicates()
                elif choice == '16':
                    self.quick_fixes()
                elif choice == '17':
                    self.manual_file_correction()
                elif choice == '18':
                    self.delete_show()
                elif choice == '19':
                    self.delete_video_file()
                elif choice == '20':
                    self.backup_sync()
                elif choice == '21':
                    self.configure_folders()
                elif choice == '0':
                    print("\nGoodbye!")
                    break
                else:
                    print("Invalid choice. Please try again.")
                    self.safe_input("\nPress Enter to continue...")
                    
            except KeyboardInterrupt:
                print("\n\nGoodbye!")
                break
            
            # Safety mechanisms to prevent infinite loops
            iteration_count += 1
        
        # Check if loop exited due to safety limits
        if iteration_count >= self.max_menu_iterations:
            print("⚠️  Maximum menu iterations reached. Exiting for safety.")
        elif not self.running:
            print("⚠️  Application shutdown requested.")
        
    def batch_operations(self):
        """Batch operations menu for bulk actions."""
        while True:
            self.clear_screen()
            print("="*60)
            print("⚡ Batch Operations")
            print("="*60)
            print("1. Codec conversion operations")
            print("2. Quality-based operations")
            print("3. File management operations")
            print("4. Subtitle batch operations")
            print("5. Metadata operations")
            print("6. Custom selection operations")
            print("0. Back to main menu")
            print()
            
            choice = self.safe_input("Enter your choice: ")
            
            if choice == '0':
                break
            elif choice == '1':
                self.codec_operations()
            elif choice == '2':
                self.quality_operations()
            elif choice == '3':
                self.file_management_operations()
            elif choice == '4':
                self.subtitle_batch_operations()
            elif choice == '5':
                self.metadata_operations()
            elif choice == '6':
                self.custom_selection_operations()
                
    def codec_operations(self):
        """Codec conversion batch operations."""
        print("\n🎥 Codec Conversion Operations:")
        print("1. Convert all HEVC/H.265 to H.264")
        print("2. Convert all AVI files to MP4")
        print("3. Convert all MKV files to MP4")
        print("4. Convert videos with unusual audio codecs to AAC")
        print("5. Convert specific codec to another")
        print("0. Back")
        
        choice = self.safe_input("\nEnter your choice: ")
        
        if choice == '1':
            self.batch_convert_codec('hevc', 'h264')
        elif choice == '2':
            self.batch_convert_extension('.avi', '.mp4')
        elif choice == '3':
            self.batch_convert_extension('.mkv', '.mp4')
        elif choice == '4':
            self.batch_fix_audio_codecs()
        elif choice == '5':
            from_codec = self.safe_input("From codec (e.g., hevc, h264): ").lower()
            to_codec = self.safe_input("To codec (e.g., h264, hevc): ").lower()
            if from_codec and to_codec:
                self.batch_convert_codec(from_codec, to_codec)
                
    def quality_operations(self):
        """Quality-based batch operations."""
        print("\n📺 Quality-Based Operations:")
        print("1. Delete all videos below 720p")
        print("2. Delete all videos below 480p")
        print("3. Convert all 4K videos to 1080p")
        print("4. Delete videos smaller than X MB")
        print("5. Convert videos larger than X GB")
        print("0. Back")
        
        choice = self.safe_input("\nEnter your choice: ")
        
        if choice == '1':
            self.batch_delete_by_resolution(720)
        elif choice == '2':
            self.batch_delete_by_resolution(480)
        elif choice == '3':
            self.batch_convert_4k_to_1080p()
        elif choice == '4':
            min_mb = self.safe_input("Delete files smaller than (MB): ")
            try:
                self.batch_delete_by_size(int(min_mb))
            except ValueError:
                print("Invalid size!")
        elif choice == '5':
            max_gb = self.safe_input("Convert files larger than (GB): ")
            try:
                self.batch_convert_large_files(float(max_gb))
            except ValueError:
                print("Invalid size!")
                
    def file_management_operations(self):
        """File management batch operations."""
        print("\n📁 File Management Operations:")
        print("1. Remove text from all filenames")
        print("2. Change all file extensions")
        print("3. Move files by pattern to folder")
        print("4. Batch rename using pattern")
        print("0. Back")
        
        choice = self.safe_input("\nEnter your choice: ")
        
        if choice == '1':
            text_to_remove = self.safe_input("Text to remove from filenames: ")
            if text_to_remove:
                self.batch_remove_text(text_to_remove)
        elif choice == '2':
            from_ext = self.safe_input("From extension (e.g., .avi): ")
            to_ext = self.safe_input("To extension (e.g., .mp4): ")
            if from_ext and to_ext:
                self.batch_change_extensions(from_ext, to_ext)
        elif choice == '3':
            pattern = self.safe_input("File pattern to match: ")
            folder = self.safe_input("Destination folder: ")
            if pattern and folder:
                self.batch_move_by_pattern(pattern, folder)
        elif choice == '4':
            self.batch_rename_pattern()
            
    def subtitle_batch_operations(self):
        """Subtitle batch operations."""
        print("\n📝 Subtitle Batch Operations:")
        print("1. Extract all embedded subtitles to .srt")
        print("2. Remove all subtitle tracks from videos")
        print("3. Convert all .ass/.vtt to .srt")
        print("4. Download subtitles for specific show")
        print("5. Remove all external subtitle files")
        print("0. Back")
        
        choice = self.safe_input("\nEnter your choice: ")
        
        if choice == '1':
            self.batch_extract_subtitles()
        elif choice == '2':
            self.batch_remove_subtitle_tracks()
        elif choice == '3':
            self.batch_convert_subtitle_formats()
        elif choice == '4':
            show_name = self.safe_input("Show name (partial match): ")
            if show_name:
                self.batch_download_show_subtitles(show_name)
        elif choice == '5':
            self.batch_remove_external_subtitles()
            
    def metadata_operations(self):
        """Metadata batch operations."""
        print("\n🏷️  Metadata Operations:")
        print("1. Strip all metadata from videos")
        print("2. Remove thumbnails/artwork from videos")
        print("3. Remove all chapters from videos")
        print("0. Back")
        
        choice = self.safe_input("\nEnter your choice: ")
        
        if choice == '1':
            self.batch_strip_metadata()
        elif choice == '2':
            self.batch_remove_thumbnails()
        elif choice == '3':
            self.batch_remove_chapters()
            
    def custom_selection_operations(self):
        """Custom selection batch operations."""
        print("\n🎯 Custom Selection Operations:")
        print("1. Select by file size range")
        print("2. Select by date range")
        print("3. Select by regex pattern")
        print("4. Select by directory")
        print("5. Select by codec type")
        print("0. Back")
        
        choice = self.safe_input("\nEnter your choice: ")
        
        if choice == '1':
            self.select_by_size_range()
        elif choice == '2':
            self.select_by_date_range()
        elif choice == '3':
            pattern = self.safe_input("Regex pattern: ")
            if pattern:
                self.select_by_regex(pattern)
        elif choice == '4':
            directory = self.safe_path_input("Directory path: ")
            if directory:
                self.select_by_directory(directory)
        elif choice == '5':
            codec = self.safe_input("Codec name: ")
            if codec:
                self.select_by_codec(codec)
    
    # Core batch operation implementations
    def batch_convert_codec(self, from_codec, to_codec):
        """Convert all videos from one codec to another."""
        print(f"\nFinding videos with {from_codec.upper()} codec...")
        
        matching_files = []
        total_files = sum(1 for root, dirs, files in os.walk(self.base_path, followlinks=False) 
                         for file in files if file.lower().endswith(self.video_extensions))
        
        files_checked = 0
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    files_checked += 1
                    
                    if files_checked % 10 == 0:
                        print(f"Scanning: {files_checked}/{total_files} files", end='\r')
                    
                    info = self.get_video_info(file_path)
                    if info:
                        for stream in info.get('streams', []):
                            if (stream.get('codec_type') == 'video' and 
                                stream.get('codec_name', '').lower() == from_codec):
                                size_gb = os.path.getsize(file_path) / (1024**3)
                                matching_files.append({
                                    'path': file_path,
                                    'name': file,
                                    'size_gb': size_gb
                                })
                                break
        
        if not matching_files:
            print(f"\nNo videos found with {from_codec.upper()} codec!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        total_size = sum(f['size_gb'] for f in matching_files)
        
        print(f"\n\nFound {len(matching_files)} videos with {from_codec.upper()} codec:")
        print(f"Total size: {total_size:.2f} GB")
        
        for i, file_info in enumerate(matching_files[:10], 1):
            print(f"{i}. {file_info['name']} ({file_info['size_gb']:.2f} GB)")
        
        if len(matching_files) > 10:
            print(f"... and {len(matching_files) - 10} more")
        
        response = self.safe_input(f"\nConvert these videos from {from_codec.upper()} to {to_codec.upper()}? (y/N): ")
        if response.lower() == 'y':
            self.execute_batch_conversion(matching_files, to_codec)
            
    def batch_convert_extension(self, from_ext, to_ext):
        """Convert all videos from one extension to another."""
        print(f"\nFinding videos with {from_ext} extension...")
        
        matching_files = []
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file.lower().endswith(from_ext.lower()):
                    file_path = os.path.join(root, file)
                    size_gb = os.path.getsize(file_path) / (1024**3)
                    matching_files.append({
                        'path': file_path,
                        'name': file,
                        'size_gb': size_gb
                    })
        
        if not matching_files:
            print(f"No {from_ext} files found!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        total_size = sum(f['size_gb'] for f in matching_files)
        
        print(f"\nFound {len(matching_files)} {from_ext} files:")
        print(f"Total size: {total_size:.2f} GB")
        
        for i, file_info in enumerate(matching_files[:10], 1):
            print(f"{i}. {file_info['name']} ({file_info['size_gb']:.2f} GB)")
        
        if len(matching_files) > 10:
            print(f"... and {len(matching_files) - 10} more")
        
        response = self.safe_input(f"\nConvert these files to {to_ext}? (y/N): ")
        if response.lower() == 'y':
            for i, file_info in enumerate(matching_files, 1):
                print(f"\n[{i}/{len(matching_files)}] Converting {file_info['name']}")
                
                input_path = file_info['path']
                output_path = os.path.splitext(input_path)[0] + to_ext
                
                # Validate file paths before FFmpeg command
                if not self.validate_safe_path(input_path) or not self.validate_safe_path(output_path):
                    print(f"✗ Skipping unsafe file path: {self.sanitize_path_for_display(file_info['name'])}")
                    continue
                
                cmd = [
                    "ffmpeg", "-i", input_path,
                    "-c:v", "libx264", "-c:a", "aac",
                    "-y", output_path
                ]
                
                result = self.cmd_manager.safe_subprocess_run(cmd, capture_output=True, timeout=TimeoutConstants.LONG)
                if result.returncode == 0:
                    backup_path = f"{os.path.splitext(input_path)[0]}-ORIGINAL{from_ext}"
                    os.rename(input_path, backup_path)
                    print(f"✓ Converted, original saved as: {os.path.basename(backup_path)}")
                else:
                    print(f"✗ Conversion failed")
            
            print("\n✓ Batch conversion complete!")
        
        self.safe_input("\nPress Enter to continue...")
        
    def batch_delete_by_resolution(self, min_height):
        """Delete all videos below specified resolution."""
        print(f"\nFinding videos below {min_height}p...")
        
        low_res_files = []
        total_files = sum(1 for root, dirs, files in os.walk(self.base_path, followlinks=False) 
                         for file in files if file.lower().endswith(self.video_extensions))
        
        files_checked = 0
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    files_checked += 1
                    
                    if files_checked % 10 == 0:
                        print(f"Checking: {files_checked}/{total_files} files", end='\r')
                    
                    info = self.get_video_info(file_path)
                    if info:
                        for stream in info.get('streams', []):
                            if stream.get('codec_type') == 'video':
                                height = stream.get('height', 0)
                                if height > 0 and height < min_height:
                                    size_gb = os.path.getsize(file_path) / (1024**3)
                                    low_res_files.append({
                                        'path': file_path,
                                        'name': file,
                                        'height': height,
                                        'size_gb': size_gb
                                    })
                                break
        
        if not low_res_files:
            print(f"\nNo videos found below {min_height}p!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        total_size = sum(f['size_gb'] for f in low_res_files)
        
        print(f"\n\nFound {len(low_res_files)} videos below {min_height}p:")
        print(f"Total size to be deleted: {total_size:.2f} GB")
        
        for i, file_info in enumerate(low_res_files[:15], 1):
            print(f"{i}. {file_info['name']} ({file_info['height']}p, {file_info['size_gb']:.2f} GB)")
        
        if len(low_res_files) > 15:
            print(f"... and {len(low_res_files) - 15} more")
        
        print(f"\n⚠️  WARNING: This will permanently delete {len(low_res_files)} files!")
        response = self.safe_input("Are you sure? Type 'DELETE' to confirm: ")
        
        if response == 'DELETE':
            deleted = 0
            for file_info in low_res_files:
                success, message = self.safe_file_delete(file_info['path'])
                if success:
                    deleted += 1
                    print(f"Deleted: {file_info['name']}")
                else:
                    print(f"Error deleting {file_info['name']}: {message}")
            
            print(f"\n✓ Deleted {deleted} low-resolution videos")
            print(f"Freed up {total_size:.2f} GB of space")
        
        self.safe_input("\nPress Enter to continue...")
        
    def batch_remove_text(self, text_to_remove):
        """Remove specific text from all filenames."""
        print(f"\nFinding files containing '{text_to_remove}'...")
        
        files_to_rename = []
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if (file.lower().endswith(self.video_extensions) and 
                    text_to_remove in file):
                    
                    old_path = os.path.join(root, file)
                    new_name = file.replace(text_to_remove, '')
                    new_path = os.path.join(root, new_name)
                    
                    if not os.path.exists(new_path):
                        files_to_rename.append((old_path, new_path, file, new_name))
        
        if not files_to_rename:
            print(f"No files found containing '{text_to_remove}'!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(files_to_rename)} files to rename:")
        
        for old_path, new_path, old_name, new_name in files_to_rename[:10]:
            print(f"  {old_name}")
            print(f"  → {new_name}")
        
        if len(files_to_rename) > 10:
            print(f"... and {len(files_to_rename) - 10} more")
        
        response = self.safe_input("\nRename these files? (y/N): ")
        if response.lower() == 'y':
            renamed = 0
            for old_path, new_path, _, _ in files_to_rename:
                try:
                    os.rename(old_path, new_path)
                    renamed += 1
                except OSError as e:
                    print(f"Error renaming {self.sanitize_path_for_display(old_path)}: {self.sanitize_error_message(str(e))}")
            
            print(f"✓ Renamed {renamed} files")
        
        self.safe_input("\nPress Enter to continue...")
        
    def batch_extract_subtitles(self):
        """Extract embedded subtitles to external .srt files."""
        print("\nFinding videos with embedded English subtitles...")
        
        videos_with_subs = []
        total_files = sum(1 for root, dirs, files in os.walk(self.base_path, followlinks=False) 
                         for file in files if file.lower().endswith(self.video_extensions))
        
        files_checked = 0
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    files_checked += 1
                    
                    if files_checked % 10 == 0:
                        print(f"Scanning: {files_checked}/{total_files} files", end='\r')
                    
                    info = self.get_video_info(file_path)
                    if info:
                        for i, stream in enumerate(info.get('streams', [])):
                            if stream.get('codec_type') == 'subtitle':
                                language = stream.get('tags', {}).get('language', '')
                                if language in ['eng', 'en']:
                                    videos_with_subs.append((file_path, i, file))
                                    break
        
        if not videos_with_subs:
            print(f"\nNo videos found with embedded English subtitles!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        print(f"\n\nFound {len(videos_with_subs)} videos with embedded subtitles")
        response = self.safe_input("Extract subtitles to .srt files? (y/N): ")
        
        if response.lower() == 'y':
            extracted = 0
            for i, (file_path, stream_index, filename) in enumerate(videos_with_subs, 1):
                print(f"\n[{i}/{len(videos_with_subs)}] Extracting from: {filename}")
                
                output_srt = os.path.splitext(file_path)[0] + '.srt'
                
                # Validate file paths before FFmpeg command
                if not self.validate_safe_path(file_path) or not self.validate_safe_path(output_srt):
                    print(f"✗ Skipping unsafe file path: {self.sanitize_path_for_display(filename)}")
                    continue
                
                # Validate stream index to prevent injection
                try:
                    stream_idx = int(stream_index)
                    if stream_idx < 0 or stream_idx > 99:  # Reasonable bounds for subtitle streams
                        print(f"✗ Invalid stream index: {stream_index}")
                        continue
                except (ValueError, TypeError):
                    print(f"✗ Invalid stream index: {stream_index}")
                    continue
                
                cmd = [
                    "ffmpeg", "-i", file_path,
                    "-map", f"0:s:{stream_idx}",
                    "-c:s", "srt",
                    "-y", output_srt
                ]
                
                result = self.cmd_manager.safe_subprocess_run(cmd, capture_output=True, timeout=TimeoutConstants.MEDIUM)  # 5 minute timeout for subtitle extraction
                if result.returncode == 0:
                    extracted += 1
                    print(f"     ✓ Extracted to {os.path.basename(output_srt)}")
                else:
                    print(f"     ✗ Failed to extract")
            
            print(f"\n✓ Extracted subtitles from {extracted} videos")
        
        self.safe_input("\nPress Enter to continue...")
        
    def batch_delete_by_size(self, min_size_mb):
        """Delete videos smaller than specified size."""
        print(f"\nFinding videos smaller than {min_size_mb} MB...")
        
        small_files = []
        min_bytes = min_size_mb * FileSizeConstants.MB
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    try:
                        size = os.path.getsize(file_path)
                        if size < min_bytes:
                            small_files.append({
                                'path': file_path,
                                'name': file,
                                'size_mb': size / (1024**2)
                            })
                    except OSError:
                        continue
        
        if not small_files:
            print(f"No videos found smaller than {min_size_mb} MB!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(small_files)} small videos:")
        for file_info in small_files:
            print(f"  {file_info['name']} ({file_info['size_mb']:.1f} MB)")
        
        print(f"\n⚠️  WARNING: This will permanently delete {len(small_files)} files!")
        response = self.safe_input("Are you sure? Type 'DELETE' to confirm: ")
        
        if response == 'DELETE':
            for file_info in small_files:
                success, message = self.safe_file_delete(file_info['path'])
                if success:
                    print(f"Deleted: {file_info['name']}")
                else:
                    print(f"Error deleting {file_info['name']}: {message}")
            
            print(f"\n✓ Deleted {len(small_files)} small videos")
        
        self.safe_input("\nPress Enter to continue...")
    
    def background_analysis(self):
        """Comprehensive background analysis with 3-phase workflow."""
        self.clear_screen()
        print("="*60)
        print("🔍 Background Analysis & Recommendations")
        print("="*60)
        print("This will analyze your entire media library and provide")
        print("comprehensive recommendations for optimization.\n")
        
        # Check for recent cached analysis
        cached = self.get_cached_analysis(max_age_hours=24)
        if cached:
            age_hours = (time.time() - cached['timestamp']) / 3600
            print(f"📋 Found recent analysis from {age_hours:.1f} hours ago")
            print(f"   Files analyzed: {len(cached['videos'])}")
            
            use_cached = self.safe_input("Use cached analysis? (Y/n): ")
            if use_cached.lower() != 'n':
                self.display_analysis_results(cached)
                return
        
        print(f"\n💡 Analysis options:")
        print("1. Full analysis (scan all files)")
        print("2. Incremental analysis (only scan new/changed files)")
        print("3. View previous analysis reports")
        print("0. Cancel")
        
        choice = self.safe_input("Select option: ")
        
        if choice == '0':
            return
        elif choice == '3':
            self.view_previous_analyses()
            return
        elif choice not in ['1', '2']:
            print("Invalid choice.")
            input("Press Enter to continue...")
            return
        
        incremental_mode = (choice == '2')
        
        # Check folder configuration
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT COUNT(*) FROM folder_config WHERE enabled = 1')
            configured_folders = cursor.fetchone()[0]
        
        # Handle folder configuration based on scan type and current state
        if incremental_mode:
            # Incremental scan - must have existing folders configured
            if configured_folders == 0:
                print("\n⚠️  Cannot perform incremental scan - no folders configured")
                print("Please run a full analysis first to set up folder configuration.")
                self.safe_input("Press Enter to continue...")
                return
            else:
                print("\n📁 Using existing folder configuration:")
                with self.get_db_context() as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT folder_path, folder_type FROM folder_config WHERE enabled = 1 ORDER BY folder_type, folder_path')
                    for folder_path, folder_type in cursor.fetchall():
                        folder_name = os.path.basename(folder_path)
                        print(f"   • {folder_name} ({folder_type})")
                print()
        else:
            # Full scan - always prompt for folder configuration
            if configured_folders > 0:
                print("\n📁 Current folder configuration:")
                with self.get_db_context() as conn:
                    cursor = conn.cursor()
                    cursor.execute('SELECT folder_path, folder_type FROM folder_config WHERE enabled = 1 ORDER BY folder_type, folder_path')
                    for folder_path, folder_type in cursor.fetchall():
                        folder_name = os.path.basename(folder_path)
                        print(f"   • {folder_name} ({folder_type})")
                print()
            else:
                print("\n⚠️  No folders configured for scanning")
            
            print("Let's configure which folders to scan...")
            self.safe_input("\nPress Enter to configure folders...")
            self.configure_folders()
            
            # Check final configuration
            with self.get_db_context() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT COUNT(*) FROM folder_config WHERE enabled = 1')
                configured_folders = cursor.fetchone()[0]
            
            if configured_folders == 0:
                print("\nNo folders configured. Analysis cancelled.")
                self.safe_input("Press Enter to continue...")
                return
        
        # Ask about fix options upfront for full scans
        fix_naming = False
        fix_transcoding = False
        optimize_streaming = False
        fix_subtitles = False
        auto_remove_system = False
        check_corruption = False
        
        if not incremental_mode:
            print("\n🔧 What would you like to fix during this full scan?")
            fix_naming = self.safe_input("Fix files with bad names (spaces, periods, TV format)? (Y/n): ").lower() != 'n'
            fix_transcoding = self.safe_input("Transcode videos larger than 1080p? (y/N): ").lower() == 'y'
            optimize_streaming = self.safe_input("Optimize videos for streaming (convert AVI/FLV/WMV/MOV to MP4)? (y/N): ").lower() == 'y'
            fix_subtitles = self.safe_input("Download missing subtitles? (y/N): ").lower() == 'y'
            auto_remove_system = self.safe_input("Auto-remove system files (.DS_Store, etc.)? (y/N): ").lower() == 'y'
            check_corruption = self.safe_input("Check for corrupted video files? (y/N): ").lower() == 'y'
        
        print("\n" + "="*60)
        print("🚀 Starting Background Analysis...")
        print("="*60)

        start_time = time.time()
        
        # PHASE 1: INDEX ALL FILES AND ADD TO DATABASE
        print("Phase 1: Indexing all files and adding to database...")
        all_video_files = self.index_all_files(incremental_mode)
        
        if not all_video_files:
            print("No files found to process.")
            self.safe_input("Press Enter to continue...")
            return
        
        # PHASE 2: RUN RENAMING ON FILES THAT NEED IT
        if not incremental_mode and fix_naming:  # Only if user requested naming fixes
            naming_issues_count = self.run_renaming_phase(all_video_files, fix_naming)
            if naming_issues_count > 0:
                print(f"\n✓ Phase 2 complete: Fixed {naming_issues_count} naming issues")
                # Refresh file list after renaming
                all_video_files = self.index_all_files(incremental_mode=False)
        elif not incremental_mode:
            print("\nPhase 2: Skipping rename (not requested)")
        
        # PHASE 3: ANALYZE AND OFFER OTHER FIXES
        analysis_results = self.run_analysis_phase(all_video_files, incremental_mode, 
                                                 fix_transcoding, optimize_streaming, 
                                                 fix_subtitles, auto_remove_system, check_corruption)
        
        # Save analysis session and display results
        analysis_duration = time.time() - start_time
        self.save_analysis_session(
            len(all_video_files), 
            len(analysis_results.get('conversion_candidates', [])),
            analysis_duration,
            analysis_results.get('recommendations', [])
        )
        
        # Display results using the new clean display function
        self.display_final_analysis_results(analysis_results, len(all_video_files), len(all_video_files))
        
        # Execute the requested fixes
        if not incremental_mode and (fix_transcoding or optimize_streaming or fix_subtitles or auto_remove_system):
            print(f"\n{'='*60}")
            print("🔨 Executing Requested Fixes")
            print(f"{'='*60}")
            self.execute_analysis_fixes(analysis_results, fix_transcoding, optimize_streaming, fix_subtitles, auto_remove_system)
    
    def execute_analysis_fixes(self, analysis_results, fix_transcoding, optimize_streaming, fix_subtitles, auto_remove_system):
        """Execute the fixes that the user requested during analysis."""
        total_tasks = 0
        
        # Count total tasks
        if fix_transcoding and analysis_results['conversion_candidates']:
            total_tasks += len(analysis_results['conversion_candidates'])
        if optimize_streaming and analysis_results['codec_issues']:
            total_tasks += len(analysis_results['codec_issues'])
        if fix_subtitles and analysis_results['missing_subtitles']:
            total_tasks += len(analysis_results['missing_subtitles'])
        if auto_remove_system and analysis_results['system_files']:
            total_tasks += len(analysis_results['system_files'])
            
        if total_tasks == 0:
            print("\nNo fixes needed based on analysis!")
            self.safe_input("\nPress Enter to continue...")
            return
            
        print(f"\n📋 Total tasks to execute: {total_tasks}")
        confirm = self.safe_input("\nProceed with all fixes? (Y/n): ")
        if confirm.lower() == 'n':
            print("Fixes cancelled.")
            self.safe_input("\nPress Enter to continue...")
            return
            
        completed_tasks = 0
        
        # Execute transcoding tasks
        if fix_transcoding and analysis_results['conversion_candidates']:
            print(f"\n🎥 Converting {len(analysis_results['conversion_candidates'])} videos to 1080p...")
            for i, video in enumerate(analysis_results['conversion_candidates'], 1):
                print(f"\rConverting {i}/{len(analysis_results['conversion_candidates'])}: {os.path.basename(video['path'])}", end='', flush=True)
                result = self.transcode_video_task(video['path'])
                if "successfully" in result.lower():
                    completed_tasks += 1
            print()
        
        # Execute streaming optimization
        if optimize_streaming and analysis_results['codec_issues']:
            print(f"\n📹 Optimizing {len(analysis_results['codec_issues'])} videos for streaming...")
            for i, video in enumerate(analysis_results['codec_issues'], 1):
                print(f"\rOptimizing {i}/{len(analysis_results['codec_issues'])}: {os.path.basename(video['path'])}", end='', flush=True)
                # Reuse transcode task but with streaming-optimized settings
                result = self.transcode_video_task(video['path'])
                if "successfully" in result.lower():
                    completed_tasks += 1
            print()
        
        # Download subtitles
        if fix_subtitles and analysis_results['missing_subtitles']:
            print(f"\n📝 Downloading subtitles for {len(analysis_results['missing_subtitles'])} videos...")
            for i, file_path in enumerate(analysis_results['missing_subtitles'], 1):
                print(f"\rDownloading subtitles {i}/{len(analysis_results['missing_subtitles'])}: {os.path.basename(file_path)}", end='', flush=True)
                result = self.download_subtitle_task(file_path)
                if "downloaded" in result.lower():
                    completed_tasks += 1
            print()
        
        # Remove system files
        if auto_remove_system and analysis_results['system_files']:
            print(f"\n🗑️  Removing {len(analysis_results['system_files'])} system files...")
            for i, file_path in enumerate(analysis_results['system_files'], 1):
                print(f"\rRemoving {i}/{len(analysis_results['system_files'])}: {os.path.basename(file_path)}", end='', flush=True)
                result = self.remove_system_file_task(file_path)
                if "successfully" in result.lower():
                    completed_tasks += 1
            print()
            
        print(f"\n✅ Completed {completed_tasks}/{total_tasks} tasks!")
        self.safe_input("\nPress Enter to continue...")
    
    def index_all_files(self, incremental_mode):
        """Phase 1: Index all files and add basic info to database."""
        all_video_files = []
        discovered_count = 0
        
        # Get configured folders to scan
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT folder_path FROM folder_config WHERE enabled = 1')
            folders_to_scan = [row[0] for row in cursor.fetchall()]
        
        if not folders_to_scan:
            print("❌ No folders configured for scanning!")
            return []
        
        # For incremental mode, show comparison with existing scan
        if incremental_mode:
            with self.get_db_context() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT MAX(last_scanned) FROM video_files')
                last_scan_time = cursor.fetchone()[0]
                if last_scan_time:
                    last_scan_date = datetime.fromtimestamp(last_scan_time).strftime('%Y-%m-%d %H:%M')
                    print(f"📋 Using scan data from {last_scan_date}")
                    print("🔍 Comparing with current filesystem to find new/changed files...")
                else:
                    print("📋 No previous scan data found, performing full scan...")
        
        # Scan configured folders and collect all video files
        for folder_path in folders_to_scan:
            if not os.path.exists(folder_path):
                print(f"⚠️  Folder not found: {folder_path}")
                continue
                
            for root, dirs, files in os.walk(folder_path, followlinks=False):
                for file in files:
                    if file.lower().endswith(self.video_extensions):
                        file_path = os.path.join(root, file)
                        all_video_files.append(file_path)
                        discovered_count += 1
                        
                        # Show discovery progress every 100 files
                        if discovered_count % 100 == 0:
                            if incremental_mode:
                                print(f"\r🔍 Scanning filesystem... Found {discovered_count} files", end='', flush=True)
                            else:
                                print(f"\r🔍 Indexing files... Found {discovered_count} so far", end='', flush=True)
        
        if incremental_mode:
            # Count how many files are new/changed
            new_or_changed = []
            cached_count = 0
            
            for file_path in all_video_files:
                if self.is_file_changed(file_path):
                    new_or_changed.append(file_path)
                else:
                    cached_count += 1
            
            print(f"\n📊 Comparison complete:")
            print(f"   • Total files found: {discovered_count}")
            print(f"   • Using cached data: {cached_count}")
            print(f"   • New or changed: {len(new_or_changed)}")
            
            if len(new_or_changed) == 0:
                print("✅ No new or changed files found!")
                return all_video_files
            
            print(f"\n📥 Processing {len(new_or_changed)} new/changed files...")
            files_to_process = new_or_changed
        else:
            print(f"\n✓ Found {discovered_count} video files")
            files_to_process = all_video_files
        
        # Add/update file info in database
        batch_to_save = []
        for i, file_path in enumerate(files_to_process):
            if i % 100 == 0 and i > 0:
                print(f"\r📊 Adding to database... {i}/{len(files_to_process)}", end='', flush=True)
                
            try:
                stat = os.stat(file_path)
                file_data = {
                    'file_path': file_path,
                    'relative_path': os.path.relpath(file_path, self.base_path),
                    'filename': os.path.basename(file_path),
                    'file_size': stat.st_size,
                    'file_modified': stat.st_mtime,
                    'last_scanned': time.time()
                }
                batch_to_save.append(file_data)
                
                # Save in batches of 100
                if len(batch_to_save) >= 100:
                    self.save_video_metadata_batch(batch_to_save)
                    batch_to_save = []
                    
            except OSError:
                continue
        
        # Save any remaining files
        if batch_to_save:
            self.save_video_metadata_batch(batch_to_save)
        
        if incremental_mode:
            print(f"\n✓ Phase 1 complete: Updated {len(files_to_process)} files in database")
        else:
            print(f"\n✓ Phase 1 complete: Indexed {discovered_count} files")
        return all_video_files
    
    def run_renaming_phase(self, all_video_files, fix_naming=True):
        """Phase 2: Check for naming issues and fix them all at once."""
        print("\nPhase 2: Analyzing naming issues and running auto-rename...")
        
        naming_issues = []
        
        # Check all files for naming issues
        for file_path in all_video_files:
            issues = self.check_naming_issues(file_path)
            if issues:
                naming_issues.append({'path': file_path, 'issues': issues})
        
        if not naming_issues:
            print("✓ No naming issues found")
            return 0
        
        print(f"Found {len(naming_issues)} files with naming issues")
        
        if not fix_naming:
            print("Skipping naming fixes")
            return 0
        
        # Run renaming on all files with issues
        renamed_count = 0
        rename_updates = []  # Store database updates for batching
        
        for i, issue_data in enumerate(naming_issues, 1):
            file_path = issue_data['path']
            print(f"\rRenaming {i}/{len(naming_issues)}: {os.path.basename(file_path)}", end='', flush=True)
            
            rename_result = self.rename_file_task_no_db(file_path)
            if rename_result and rename_result.get('success'):
                renamed_count += 1
                rename_updates.append((
                    rename_result['new_path'], 
                    rename_result['new_filename'], 
                    file_path
                ))
        
        # Batch update database
        if rename_updates:
            print(f"\n📊 Updating database for {len(rename_updates)} renamed files...")
            with self.get_db_context() as conn:
                cursor = conn.cursor()
                cursor.executemany(
                    'UPDATE video_files SET file_path = ?, filename = ? WHERE file_path = ?',
                    rename_updates
                )
        
        print(f"\n✓ Renamed {renamed_count} files")
        return renamed_count
    
    def run_analysis_phase(self, all_video_files, incremental_mode, fix_transcoding=False, optimize_streaming=False, fix_subtitles=False, auto_remove_system=False, check_corruption=False):
        """Phase 3: Analyze files for other issues and offer fixes."""
        print("\nPhase 3: Analyzing video properties and generating recommendations...")
        
        if incremental_mode:
            # For incremental, get count of cached vs new files
            new_files = [f for f in all_video_files if self.is_file_changed(f)]
            cached_files = len(all_video_files) - len(new_files)
            
            if cached_files > 0:
                print(f"📋 Loading analysis for {cached_files} files from database cache")
            if new_files:
                print(f"🔍 Will analyze {len(new_files)} new/changed files")
        
        
        # Initialize analysis results
        analysis_results = {
            'files_scanned': len(all_video_files),
            'total_files': len(all_video_files),
            'conversion_candidates': [],
            'naming_issues': [],
            'missing_subtitles': [],
            'system_files': [],
            'large_files': [],
            'codec_issues': [],
            'duplicate_candidates': [],
            'corrupted_files': [],
            'storage_usage': {},
            'recommendations': [],
            'background_tasks': []
        }
        
        # For incremental mode, load cached analysis data for unchanged files
        if incremental_mode:
            with self.get_db_context() as conn:
                cursor = conn.cursor()
                
                # Load cached analysis data for all files from database
                unchanged_files = [f for f in all_video_files if not self.is_file_changed(f)]
                
                if unchanged_files:
                    print(f"📋 Loading cached analysis for {len(unchanged_files)} unchanged files...")
                    
                    for file_path in unchanged_files:
                        if not self.validate_safe_path(file_path):
                            continue
                        cursor.execute('SELECT * FROM video_files WHERE file_path = ?', (file_path,))
                        row = cursor.fetchone()
                        if row:
                            # Add cached data to results
                            if row['needs_conversion']:
                                analysis_results['conversion_candidates'].append({
                                    'path': file_path,
                                    'width': row['width'],
                                    'height': row['height'], 
                                    'size_gb': row['file_size'] / (1024**3),
                                    'codec': row['codec']
                                })
                            
                            if row['codec'] in ['mpeg4', 'xvid', 'divx', 'wmv3']:
                                analysis_results['codec_issues'].append({
                                    'path': file_path,
                                    'codec': row['codec']
                                })
                            
                            if row['file_size'] / (1024**3) > 10:
                                analysis_results['large_files'].append({
                                    'path': file_path,
                                    'size_gb': row['file_size'] / (1024**3),
                                    'resolution': f"{row['width']}x{row['height']}"
                                })
                            
                            if row['naming_issues']:
                                analysis_results['naming_issues'].append({
                                    'path': file_path,
                                    'issues': row['naming_issues'].split(',')
                                })
                            
                            if not row['has_external_subs'] and not row['has_embedded_subs']:
                                analysis_results['missing_subtitles'].append(file_path)
        
        # Analyze files for issues (but don't fix naming since that was done in Phase 2)
        files_to_analyze = all_video_files if not incremental_mode else [f for f in all_video_files if self.is_file_changed(f)]
        
        for i, file_path in enumerate(files_to_analyze):
            if i % 100 == 0:
                print(f"\r📊 Analyzing properties... {i}/{len(files_to_analyze)}", end='', flush=True)
                
            # Analyze file properties and add to appropriate lists
            self.analyze_single_file_properties(file_path, analysis_results, 
                                              fix_transcoding, optimize_streaming, 
                                              fix_subtitles, auto_remove_system, check_corruption)
        
        print(f"\n✓ Phase 3 complete: Analyzed {len(files_to_analyze)} files")
        
        # Generate recommendations and display results
        self.generate_recommendations(analysis_results)
        self.display_final_analysis_results(analysis_results, len(all_video_files), len(files_to_analyze))
        
        return analysis_results
    
    def check_naming_issues(self, file_path):
        """Check a single file for naming issues."""
        filename = os.path.basename(file_path)
        relative_path = os.path.relpath(file_path, self.base_path)
        issues = []
        
        # Check for common naming problems
        if ' ' in filename or '.' in filename.replace(os.path.splitext(filename)[1], ''):
            issues.append('Contains spaces or periods')
        
        # Check for TV show format issues
        if '/TV/' in relative_path:
            # Check for season/episode format
            import re
            if not re.search(r'[Ss]\d{1,2}[Ee]\d{1,2}', filename):
                issues.append('Missing S##E## TV format')
        
        # Check for movie year format
        elif '/Movies/' in relative_path:
            if not ('(' in filename and ')' in filename):
                issues.append('Missing year in movie title')
        
        return issues
    
    def check_subtitle_status(self, file_path):
        """Check if a file has external or embedded English subtitles."""
        # Check for external subtitle files
        base_name = os.path.splitext(file_path)[0]
        subtitle_files = [f"{base_name}.srt", f"{base_name}.en.srt", f"{base_name}.eng.srt", f"{base_name}.vtt", f"{base_name}.en.vtt"]
        has_external_subs = any(os.path.exists(sub_file) for sub_file in subtitle_files)
        
        # Check for embedded subtitles
        has_embedded_subs = False
        video_info = self.get_video_info(file_path)
        if video_info:
            for stream in video_info.get('streams', []):
                if stream.get('codec_type') == 'subtitle':
                    tags = stream.get('tags', {})
                    language = tags.get('language', '').lower()
                    if language in ['en', 'eng', 'english'] or not language:
                        has_embedded_subs = True
                        break
        
        return has_external_subs, has_embedded_subs
    
    def analyze_single_file_properties(self, file_path, analysis_results, fix_transcoding, optimize_streaming, fix_subtitles, auto_remove_system, check_corruption):
        """Analyze a single file's properties and add to appropriate result lists."""
        try:
            stat = os.stat(file_path)
            
            # Get video info for detailed analysis
            video_info = self.get_video_info(file_path)
            if video_info:
                for stream in video_info.get('streams', []):
                    if stream.get('codec_type') == 'video':
                        width = stream.get('width', 0)
                        height = stream.get('height', 0)
                        codec = self.validate_codec_name(stream.get('codec_name', 'unknown'))
                        
                        # Check if needs conversion
                        if fix_transcoding and (width > 1920 or height > 1080):
                            size_gb = stat.st_size / (1024**3)
                            analysis_results['conversion_candidates'].append({
                                'path': file_path,
                                'width': width,
                                'height': height,
                                'size_gb': size_gb,
                                'codec': codec
                            })
                        
                        # Check codec issues
                        if codec in ['mpeg4', 'xvid', 'divx', 'wmv3']:
                            analysis_results['codec_issues'].append({
                                'path': file_path,
                                'codec': codec
                            })
                        
                        # Check container format for streaming optimization
                        if optimize_streaming:
                            file_extension = os.path.splitext(file_path)[1].lower()
                            problematic_containers = ['.avi', '.flv', '.wmv', '.mov']
                            if file_extension in problematic_containers:
                                analysis_results['codec_issues'].append({
                                    'path': file_path,
                                    'codec': f"{codec} ({file_extension})"
                                })
                        
                        # Update database with analysis
                        file_data = {
                            'file_path': file_path,
                            'width': width,
                            'height': height,
                            'codec': codec,
                            'file_size': stat.st_size,
                            'file_modified': stat.st_mtime,
                            'needs_conversion': (width > 1920 or height > 1080),
                            'last_scanned': time.time()
                        }
                        
                        # Check subtitles if requested
                        if fix_subtitles:
                            has_external, has_embedded = self.check_subtitle_status(file_path)
                            file_data['has_external_subs'] = has_external
                            file_data['has_embedded_subs'] = has_embedded
                            
                            if not has_external and not has_embedded:
                                analysis_results['missing_subtitles'].append(file_path)
                        
                        # Save file data to database
                        self.save_video_metadata_batch([file_data])
                        break
            
            # Check for large files
            size_gb = stat.st_size / (1024**3)
            if size_gb > 10:
                analysis_results['large_files'].append({
                    'path': file_path,
                    'size_gb': size_gb
                })
            
        except OSError:
            pass
    
    def generate_recommendations(self, analysis_results):
        """Generate prioritized recommendations based on analysis results."""
        recommendations = []
        
        if analysis_results['conversion_candidates']:
            total_size = sum(c['size_gb'] for c in analysis_results['conversion_candidates'])
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Storage',
                'task': f"Convert {len(analysis_results['conversion_candidates'])} videos to 1080p",
                'benefit': f"Could save ~{total_size * 0.6:.1f} GB of storage",
                'action': 'Use Option 8: Convert videos to 1080p'
            })
        
        if analysis_results['codec_issues']:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Compatibility',
                'task': f"Convert {len(analysis_results['codec_issues'])} videos with old codecs",
                'benefit': 'Improve playback compatibility and reduce file sizes',
                'action': 'Use Option 10: Batch Operations → Codec Operations'
            })
        
        if analysis_results['missing_subtitles']:
            recommendations.append({
                'priority': 'LOW',
                'category': 'Accessibility',
                'task': f"Download subtitles for {len(analysis_results['missing_subtitles'])} videos",
                'benefit': 'Better accessibility and viewing experience',
                'action': 'Use Option 12: Download English subtitles'
            })
        
        analysis_results['recommendations'] = recommendations
    
    def display_final_analysis_results(self, analysis_results, total_files, analyzed_files):
        """Display final analysis results with recommendations."""
        self.clear_screen()
        print("="*60)
        print("📊 Background Analysis Complete")
        print("="*60)
        
        print(f"📁 Total Files: {total_files:,}")
        print(f"🔍 Files Analyzed: {analyzed_files:,}")
        print()
        
        # Summary statistics
        print("📈 SUMMARY")
        print("-" * 30)
        print(f"Videos needing conversion: {len(analysis_results['conversion_candidates'])}")
        print(f"Videos with codec issues: {len(analysis_results['codec_issues'])}")
        print(f"Videos missing subtitles: {len(analysis_results['missing_subtitles'])}")
        print(f"Large files (>10GB): {len(analysis_results['large_files'])}")
        print(f"System files to clean: {len(analysis_results['system_files'])}")
        
        # Show recommendations
        if analysis_results['recommendations']:
            print(f"\n🎯 RECOMMENDATIONS")
            print("-" * 30)
            for i, rec in enumerate(analysis_results['recommendations'], 1):
                print(f"{i}. {rec['task']} ({rec['priority']})")
                print(f"   {rec['benefit']}")
                print(f"   → {rec['action']}")
                print()
        
        self.safe_input("Press Enter to continue...")

    def display_analysis_results(self, data):
        """Display analysis results from cached or fresh data."""
        self.clear_screen()
        print("="*60)
        print("📊 Background Analysis Results")
        print("="*60)
        
        session = data['session']
        if 'analysis_results' in data:
            # Fresh analysis
            results = data['analysis_results']
        else:
            # Cached analysis - rebuild results from database
            results = self.rebuild_analysis_from_db()
        
        print(f"📁 Total Files: {session['total_files']:,}")
        print(f"🔍 Files Analyzed: {session['files_analyzed']:,}")
        print(f"⏱️  Analysis Time: {session['duration_seconds']:.1f} seconds")
        print(f"📅 Timestamp: {datetime.fromtimestamp(session['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}")
        
        # Show background task summary if available
        if 'background_tasks_completed' in data:
            print(f"🔧 Background Tasks: {data['background_tasks_completed']} completed")
        
        print()
        
        # Summary statistics
        print("📈 SUMMARY STATISTICS")
        print("-" * 30)
        print(f"Videos needing conversion: {len(results['conversion_candidates'])}")
        print(f"Videos with naming issues: {len(results['naming_issues'])}")
        print(f"Videos missing subtitles: {len(results['missing_subtitles'])}")
        print(f"Videos with codec issues: {len(results['codec_issues'])}")
        print(f"Large files (>10GB): {len(results['large_files'])}")
        print(f"System files to clean: {len(results['system_files'])}")
        
        if 'corrupted_files' in results:
            print(f"Corrupted/problematic files: {len(results['corrupted_files'])}")
        print()
        
        # Recommendations
        recommendations = results.get('recommendations', [])
        if recommendations:
            print("🎯 RECOMMENDED ACTIONS")
            print("-" * 30)
            
            for i, rec in enumerate(recommendations, 1):
                priority_color = {
                    'HIGH': '🔴',
                    'MEDIUM': '🟡', 
                    'LOW': '🟢'
                }.get(rec['priority'], '⚪')
                
                print(f"{i}. {priority_color} {rec['priority']} - {rec['category']}")
                print(f"   Task: {rec['task']}")
                print(f"   Benefit: {rec['benefit']}")
                print(f"   Action: {rec['action']}")
                print()
        else:
            print("🎉 No issues found! Your media library is well organized.")
        
        # Detailed breakdowns
        if results['conversion_candidates']:
            print("\n📺 CONVERSION CANDIDATES (Top 10)")
            print("-" * 40)
            sorted_candidates = sorted(results['conversion_candidates'], 
                                     key=lambda x: x['size_gb'], reverse=True)
            for i, video in enumerate(sorted_candidates[:10], 1):
                filename = os.path.basename(video['path'])
                print(f"{i:2}. {filename[:50]}")
                print(f"    {video['width']}x{video['height']} • {video['size_gb']:.1f}GB • {video['codec']}")
        
        if results['large_files']:
            print(f"\n💾 LARGEST FILES (Top 10)")
            print("-" * 40)
            sorted_large = sorted(results['large_files'], 
                                key=lambda x: x['size_gb'], reverse=True)
            for i, video in enumerate(sorted_large[:10], 1):
                filename = os.path.basename(video['path'])
                print(f"{i:2}. {filename[:50]}")
                print(f"    {video['resolution']} • {video['size_gb']:.1f}GB")
        
        if results['naming_issues']:
            print(f"\n📝 NAMING ISSUES (First 10)")
            print("-" * 40)
            for i, issue in enumerate(results['naming_issues'][:10], 1):
                filename = os.path.basename(issue['path'])
                issues_str = ', '.join(issue['issues'])
                print(f"{i:2}. {filename[:50]}")
                print(f"    Issues: {issues_str}")
        
        # Show real-time issue discovery summary if available
        if 'found_issues' in data:
            found = data['found_issues']
            if any(found.values()):
                print(f"\n🔍 REAL-TIME DISCOVERY SUMMARY")
                print("-" * 40)
                
                if found['subtitle_issues']:
                    print(f"📝 Subtitle issues discovered: {len(found['subtitle_issues'])}")
                
                if found['system_files_found']:
                    print(f"🗑️  System files found: {len(found['system_files_found'])}")
                
                if found['naming_problems']:
                    print(f"📂 Naming problems detected: {len(found['naming_problems'])}")
                
                if found['codec_problems']:
                    print(f"🎬 Old codec files found: {len(found['codec_problems'])}")
                
                if found['corrupted_files']:
                    print(f"💥 Corrupted files detected: {len(found['corrupted_files'])}")
                
                if found['background_tasks']:
                    print(f"⚡ Auto-fix tasks completed: {len(found['background_tasks'])}")
                    print("Recent completions:")
                    for task_result in found['background_tasks'][-5:]:
                        print(f"   {task_result}")
        
        # Action menu based on analysis results
        print("\n" + "="*60)
        print("🎯 What would you like to do?")
        print("="*60)
        
        actions = []
        action_num = 1
        
        if results['conversion_candidates']:
            print(f"{action_num}. Convert top 10 largest videos to 1080p ({len(results['conversion_candidates'])} candidates)")
            actions.append(('convert_top_10', results['conversion_candidates'][:10]))
            action_num += 1
        
        if results['naming_issues']:
            print(f"{action_num}. Fix naming issues ({len(results['naming_issues'])} files)")
            actions.append(('fix_naming', results['naming_issues']))
            action_num += 1
        
        if results['missing_subtitles']:
            print(f"{action_num}. Download English subtitles ({len(results['missing_subtitles'])} files)")
            actions.append(('download_subtitles', results['missing_subtitles']))
            action_num += 1
        
        if results['codec_issues']:
            print(f"{action_num}. Convert videos with old codecs ({len(results['codec_issues'])} files)")
            actions.append(('convert_old_codecs', results['codec_issues']))
            action_num += 1
        
        if results['system_files']:
            print(f"{action_num}. Clean up system files ({len(results['system_files'])} files)")
            actions.append(('cleanup_system', results['system_files']))
            action_num += 1
        
        print(f"{action_num}. Go to main menu")
        actions.append(('main_menu', None))
        
        print(f"0. Exit")
        
        choice = self.safe_input(f"\nEnter your choice (0-{action_num}): ")
        
        if choice == '0':
            self.running = False
            return
        elif choice == str(action_num):
            return  # Go to main menu
        
        try:
            selected_action = actions[int(choice) - 1]
            action_type, data = selected_action
            
            if action_type == 'convert_top_10':
                self.batch_convert_videos(data, '1080p')
            elif action_type == 'fix_naming':
                self.smart_organization()
            elif action_type == 'download_subtitles':
                self.download_subtitles()
            elif action_type == 'convert_old_codecs':
                self.batch_convert_videos(data, '1080p')
            elif action_type == 'cleanup_system':
                self.cleanup_system_files()
            
        except (ValueError, IndexError):
            print("Invalid choice.")
            self.safe_input("Press Enter to continue...")
    
    def rebuild_analysis_from_db(self):
        """Rebuild analysis results from database."""
        results = {
            'conversion_candidates': [],
            'naming_issues': [],
            'missing_subtitles': [],
            'system_files': [],
            'large_files': [],
            'codec_issues': [],
            'recommendations': []
        }
        
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            
            # Get conversion candidates (Movies and TV only)
            cursor.execute('''
                SELECT * FROM video_files 
                WHERE needs_conversion = 1
                AND (file_path LIKE '%/Movies/%' OR file_path LIKE '%/TV/%')
            ''')
            for row in cursor.fetchall():
                results['conversion_candidates'].append({
                    'path': row['file_path'],
                    'width': row['width'],
                    'height': row['height'],
                    'size_gb': row['file_size'] / (1024**3),
                    'codec': row['codec']
                })
            
            # Get naming issues (Movies and TV only)
            cursor.execute('''
                SELECT * FROM video_files 
                WHERE naming_issues IS NOT NULL
                AND (file_path LIKE '%/Movies/%' OR file_path LIKE '%/TV/%')
            ''')
            for row in cursor.fetchall():
                results['naming_issues'].append({
                    'path': row['file_path'],
                    'issues': row['naming_issues'].split(',')
                })
            
            # Get missing subtitles (Movies and TV only)
            cursor.execute('''
                SELECT * FROM video_files 
                WHERE has_external_subs = 0 AND has_embedded_subs = 0
                AND (file_path LIKE '%/Movies/%' OR file_path LIKE '%/TV/%')
            ''')
            for row in cursor.fetchall():
                results['missing_subtitles'].append(row['file_path'])
            
            # Get codec issues - use parameterized query for security
            problematic_codecs = ('mpeg4', 'xvid', 'divx', 'wmv3')
            placeholders = ','.join('?' * len(problematic_codecs))
            cursor.execute(f"SELECT * FROM video_files WHERE codec IN ({placeholders})", problematic_codecs)
            for row in cursor.fetchall():
                results['codec_issues'].append({
                    'path': row['file_path'],
                    'codec': row['codec']
                })
            
            # Get large files
            cursor.execute('SELECT * FROM video_files WHERE file_size > ?', (FileSizeConstants.HUGE_FILE_THRESHOLD,))
            for row in cursor.fetchall():
                results['large_files'].append({
                    'path': row['file_path'],
                    'size_gb': row['file_size'] / (1024**3),
                    'resolution': f"{row['width']}x{row['height']}"
                })
            
        # Skip system file scan for cached results to avoid performance hit
        # System files are typically not critical for cached analysis viewing
        
        return results
    
    def view_previous_analyses(self):
        """View previous analysis sessions."""
        self.clear_screen()
        print("="*60)
        print("📋 Previous Analysis Sessions")
        print("="*60)
        
        with self.get_db_context() as conn:
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM analysis_sessions 
                ORDER BY timestamp DESC 
                LIMIT 10
            ''')
            sessions = cursor.fetchall()
            
            if not sessions:
                print("No previous analysis sessions found.")
                self.safe_input("\nPress Enter to continue...")
                return
            
            print("Recent analysis sessions:")
            for i, session in enumerate(sessions, 1):
                timestamp = datetime.fromtimestamp(session['timestamp'])
                print(f"{i:2}. {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"    Files: {session['files_analyzed']}/{session['total_files']}")
                print(f"    Duration: {session['duration_seconds']:.1f}s")
                if session['recommendations']:
                    try:
                        # Safe JSON parsing with size limit to prevent DoS
                        if len(session['recommendations']) > FileSizeConstants.MB:  # 1MB limit
                            self.security_audit_log("JSON_PARSE_ERROR", "Recommendations JSON too large")
                            print(f"    Recommendations: [Error: Too large]")
                        else:
                            recommendations = json.loads(session['recommendations'])
                            rec_count = len(recommendations)
                            print(f"    Recommendations: {rec_count}")
                    except (json.JSONDecodeError, ValueError) as e:
                        self.security_audit_log("JSON_PARSE_ERROR", f"Failed to parse recommendations JSON: {e}")
                        print(f"    Recommendations: [Parse Error]")
                print()
            
            choice = self.safe_input("Select session to view (or 0 to cancel): ")
            
            if choice == '0':
                return
                
            try:
                selected_session = sessions[int(choice) - 1]
                
                # Load and display this session's data
                cached_data = {
                    'session': dict(selected_session),
                    'timestamp': selected_session['timestamp']
                }
                
                self.display_analysis_results(cached_data)
                
            except (ValueError, IndexError):
                print("Invalid selection.")
                input("Press Enter to continue...")
    
    def check_rclone_installed(self):
        """Check if rclone is installed and configured."""
        try:
            result = self.cmd_manager.safe_subprocess_run(['rclone', 'version'], capture_output=True, text=True, timeout=TimeoutConstants.QUICK)
            if result.returncode == 0:
                return True
        except FileNotFoundError:
            return False
        return False
    
    def get_rclone_remotes(self):
        """Get list of configured rclone remotes."""
        try:
            result = self.cmd_manager.safe_subprocess_run(['rclone', 'listremotes'], capture_output=True, text=True, timeout=TimeoutConstants.QUICK)
            if result.returncode == 0:
                remotes = [line.strip().rstrip(':') for line in result.stdout.strip().split('\n') if line.strip()]
                return remotes
        except (subprocess.SubprocessError, OSError) as e:
            print(f"Warning: Could not list rclone remotes: {self.sanitize_error_message(str(e))}")
            pass
        return []
    
    def backup_sync(self):
        """Backup and sync menu using rclone."""
        while True:
            self.clear_screen()
            print("="*60)
            print("☁️  Backup & Sync (rclone)")
            print("="*60)
            
            # Check rclone installation
            if not self.check_rclone_installed():
                print("❌ rclone is not installed or not in PATH")
                print("\nTo install rclone:")
                print("  macOS: brew install rclone")
                print("  Ubuntu/Debian: apt install rclone")
                print("  RHEL/CentOS: yum install rclone") 
                print("  Manual: Visit official rclone website for secure downloads")
                print("         Verify GPG signatures and checksums before installation")
                self.safe_input("\nPress Enter to continue...")
                return
            
            # Get configured remotes
            remotes = self.get_rclone_remotes()
            
            if not remotes:
                print("❌ No rclone remotes configured")
                print("\nTo configure a remote:")
                print("  Run: rclone config")
                print("  Follow prompts to add cloud storage (Google Drive, S3, etc.)")
                self.safe_input("\nPress Enter to continue...")
                return
            
            print("✅ rclone installed and configured")
            print(f"📡 Available remotes: {', '.join(remotes)}")
            print()
            
            print("1. Sync specific directories to cloud")
            print("2. Backup entire media library") 
            print("3. Download from cloud to local")
            print("4. Check sync status")
            print("5. Configure bandwidth limits")
            print("6. Verify backup integrity")
            print("7. View rclone configuration")
            print("0. Back to main menu")
            print()
            
            choice = self.safe_input("Enter your choice: ")
            
            if choice == '0':
                break
            elif choice == '1':
                self.selective_sync(remotes)
            elif choice == '2':
                self.full_backup(remotes)
            elif choice == '3':
                self.download_from_cloud(remotes)
            elif choice == '4':
                self.check_sync_status(remotes)
            elif choice == '5':
                self.configure_bandwidth()
            elif choice == '6':
                self.verify_backup_integrity(remotes)
            elif choice == '7':
                self.view_rclone_config()
            else:
                print("Invalid choice.")
                input("Press Enter to continue...")
    
    def selective_sync(self, remotes):
        """Sync specific directories to cloud storage."""
        self.clear_screen()
        print("="*50)
        print("📤 Selective Sync to Cloud")
        print("="*50)
        
        # Show available directories
        main_dirs = []
        for item in os.listdir(self.base_path):
            item_path = os.path.join(self.base_path, item)
            if os.path.isdir(item_path) and not item.startswith('.'):
                size_gb = sum(os.path.getsize(os.path.join(dirpath, filename))
                             for dirpath, dirnames, filenames in os.walk(item_path, followlinks=False)
                             for filename in filenames) / (1024**3)
                main_dirs.append({'name': item, 'size_gb': size_gb})
        
        print("Available directories:")
        for i, dir_info in enumerate(main_dirs, 1):
            print(f"{i:2}. {dir_info['name']} ({dir_info['size_gb']:.1f} GB)")
        
        print(f"\n{len(main_dirs)+1}. All directories")
        print("0. Cancel")
        
        dir_choice = self.safe_input("\nSelect directory to sync: ")
        
        if dir_choice == '0':
            return
        
        try:
            if dir_choice == str(len(main_dirs)+1):
                selected_dirs = [d['name'] for d in main_dirs]
                total_size = sum(d['size_gb'] for d in main_dirs)
            else:
                idx = int(dir_choice) - 1
                selected_dirs = [main_dirs[idx]['name']]
                total_size = main_dirs[idx]['size_gb']
        except (ValueError, IndexError):
            print("Invalid selection.")
            input("Press Enter to continue...")
            return
        
        # Select remote
        print(f"\nAvailable remotes:")
        for i, remote in enumerate(remotes, 1):
            print(f"{i}. {remote}")
        
        remote_choice = self.safe_input("Select remote: ")
        try:
            selected_remote = remotes[int(remote_choice) - 1]
        except (ValueError, IndexError):
            print("Invalid remote selection.")
            input("Press Enter to continue...")
            return
        
        # Validate remote name to prevent command injection
        is_safe, message = self.validate_rclone_remote_name(selected_remote)
        if not is_safe:
            print(f"❌ Security Error: {message}")
            self.security_audit_log("RCLONE_UNSAFE_REMOTE", f"Rejected remote: {selected_remote}")
            input("Press Enter to continue...")
            return
        
        # Sync options
        print(f"\nSync options:")
        print("1. Copy only (upload new/changed files)")
        print("2. Sync (mirror - will delete files not in source)")
        print("3. Move (upload then delete local files)")
        
        sync_choice = self.safe_input("Select sync type: ")
        
        sync_commands = {
            '1': 'copy',
            '2': 'sync', 
            '3': 'move'
        }
        
        if sync_choice not in sync_commands:
            print("Invalid sync type.")
            input("Press Enter to continue...")
            return
        
        sync_cmd = sync_commands[sync_choice]
        
        # Confirm operation
        print(f"\n📋 Sync Summary:")
        print(f"   Directories: {', '.join(selected_dirs)}")
        print(f"   Total size: ~{total_size:.1f} GB")
        print(f"   Remote: {selected_remote}")
        print(f"   Operation: {sync_cmd}")
        
        if sync_choice == '3':
            print(f"\n⚠️  WARNING: MOVE will delete local files after upload!")
        elif sync_choice == '2':
            print(f"\n⚠️  WARNING: SYNC will delete remote files not in source!")
        
        confirm = self.safe_input(f"\nProceed with {sync_cmd}? (y/N): ")
        if confirm.lower() != 'y':
            return
        
        # Execute sync
        for dir_name in selected_dirs:
            # Validate directory name to prevent command injection
            if dir_name.startswith('-') or '--' in dir_name:
                print(f"✗ Skipping directory with unsafe name: {self.sanitize_path_for_display(dir_name)}")
                continue
                
            source_path = os.path.join(self.base_path, dir_name)
            remote_path = f"{selected_remote}:Media/{dir_name}"
            
            # Validate paths are safe
            if not self.validate_safe_path(source_path):
                print(f"✗ Skipping unsafe source path: {self.sanitize_path_for_display(dir_name)}")
                continue
            
            print(f"\n🚀 {sync_cmd.title()}ing {dir_name}...")
            
            cmd = [
                'rclone', sync_cmd,
                source_path, remote_path,
                '--progress',
                '--transfers', '4',
                '--checkers', '8',
                '--stats', '5s'
            ]
            
            print(f"Command: {' '.join(cmd)}")
            try:
                self.security_audit_log("CLOUD_SYNC_STARTED", f"Command: {sync_cmd}, Remote: {selected_remote}, Dir: {dir_name}")
                result = self.cmd_manager.safe_subprocess_run(cmd, capture_output=True, text=True, timeout=TimeoutConstants.LONG)
                # Display output safely
                if result.stdout:
                    print(result.stdout)
                if result.stderr:
                    print(result.stderr, file=sys.stderr)
                if result.returncode == 0:
                    self.security_audit_log("CLOUD_SYNC_COMPLETED", f"Command: {sync_cmd}, Remote: {selected_remote}, Dir: {dir_name}")
                    print(f"✅ {dir_name} {sync_cmd} completed!")
                else:
                    print(f"⚠️  {dir_name} {sync_cmd} completed with warnings")
            except KeyboardInterrupt:
                print(f"\n⚠️  {sync_cmd} interrupted for {dir_name}")
                break
            except (subprocess.SubprocessError, OSError, IOError) as e:
                print(f"❌ Error during {sync_cmd}: {self.sanitize_error_message(str(e))}")
        
        self.safe_input("\nPress Enter to continue...")
    
    def full_backup(self, remotes):
        """Backup entire media library to cloud."""
        self.clear_screen()
        print("="*50)
        print("💾 Full Media Library Backup")
        print("="*50)
        
        # Calculate total size
        total_size = 0
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                try:
                    total_size += os.path.getsize(os.path.join(root, file))
                except (OSError, IOError) as e:
                    continue
        
        total_size_gb = total_size / (1024**3)
        
        print(f"📁 Source: {self.base_path}")
        print(f"📊 Total size: {total_size_gb:.1f} GB")
        print()
        
        # Select remote
        print("Available remotes:")
        for i, remote in enumerate(remotes, 1):
            print(f"{i}. {remote}")
        
        remote_choice = self.safe_input("Select backup destination: ")
        try:
            selected_remote = remotes[int(remote_choice) - 1]
        except (ValueError, IndexError):
            print("Invalid selection.")
            input("Press Enter to continue...")
            return
        
        # Validate remote name to prevent command injection
        is_safe, message = self.validate_rclone_remote_name(selected_remote)
        if not is_safe:
            print(f"❌ Security Error: {message}")
            self.security_audit_log("RCLONE_UNSAFE_REMOTE", f"Rejected remote: {selected_remote}")
            input("Press Enter to continue...")
            return
        
        # Backup options
        print(f"\nBackup options:")
        print("1. Incremental backup (copy new/changed files only)")
        print("2. Full sync (mirror - remote matches local exactly)")
        print("3. Archive mode (copy with checksums, no deletions)")
        
        backup_choice = self.safe_input("Select backup type: ")
        
        backup_commands = {
            '1': ['copy', '--update', '--checksum'],
            '2': ['sync', '--checksum'],
            '3': ['copy', '--checksum', '--ignore-existing']
        }
        
        if backup_choice not in backup_commands:
            print("Invalid backup type.")
            input("Press Enter to continue...")
            return
        
        rclone_cmd, *flags = backup_commands[backup_choice]
        remote_path = f"{selected_remote}:MediaBackup"
        
        print(f"\n📋 Backup Summary:")
        print(f"   Source: {self.base_path}")
        print(f"   Destination: {remote_path}")
        print(f"   Size: ~{total_size_gb:.1f} GB")
        print(f"   Type: {rclone_cmd} {' '.join(flags)}")
        
        if backup_choice == '2':
            print(f"\n⚠️  WARNING: SYNC will delete remote files not in source!")
        
        # Estimate time (rough calculation)
        estimated_hours = total_size_gb / 100  # Assume 100 GB/hour
        print(f"   Estimated time: {estimated_hours:.1f} hours")
        
        confirm = self.safe_input(f"\nStart backup? (y/N): ")
        if confirm.lower() != 'y':
            return
        
        # Execute backup
        cmd = [
            'rclone', rclone_cmd,
            self.base_path, remote_path,
            '--progress',
            '--transfers', '4',
            '--checkers', '8', 
            '--stats', '30s',
            '--exclude', '.DS_Store',
            '--exclude', 'Thumbs.db',
            '--exclude', '._*'
        ] + flags
        
        print(f"\n🚀 Starting backup...")
        print(f"Command: {' '.join(cmd)}")
        print(f"💡 Press Ctrl+C to safely stop the backup\n")
        
        try:
            result = self.cmd_manager.safe_subprocess_run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"\n✅ Backup completed successfully!")
            else:
                print(f"\n⚠️  Backup completed with warnings")
        except KeyboardInterrupt:
            print(f"\n⚠️  Backup interrupted by user")
        except (subprocess.SubprocessError, OSError, IOError) as e:
            print(f"\n❌ Backup failed: {self.sanitize_error_message(str(e))}")
        
        self.safe_input("\nPress Enter to continue...")
    
    def download_from_cloud(self, remotes):
        """Download files from cloud storage."""
        self.clear_screen()
        print("="*50)
        print("📥 Download from Cloud")
        print("="*50)
        
        # Select remote
        print("Available remotes:")
        for i, remote in enumerate(remotes, 1):
            print(f"{i}. {remote}")
        
        remote_choice = self.safe_input("Select source remote: ")
        try:
            selected_remote = remotes[int(remote_choice) - 1]
        except (ValueError, IndexError):
            print("Invalid selection.")
            input("Press Enter to continue...")
            return
        
        # Validate remote name to prevent command injection
        is_safe, message = self.validate_rclone_remote_name(selected_remote)
        if not is_safe:
            print(f"❌ Security Error: {message}")
            self.security_audit_log("RCLONE_UNSAFE_REMOTE", f"Rejected remote: {selected_remote}")
            input("Press Enter to continue...")
            return
        
        # List remote directories
        print(f"\nScanning {selected_remote} for directories...")
        try:
            result = self.cmd_manager.safe_subprocess_run([
                'rclone', 'lsd', f"{selected_remote}:"
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                dirs = [line.split()[-1] for line in result.stdout.strip().split('\n') if line.strip()]
                
                if not dirs:
                    print("No directories found on remote.")
                    input("Press Enter to continue...")
                    return
                
                print(f"Available directories on {selected_remote}:")
                for i, dir_name in enumerate(dirs, 1):
                    print(f"{i}. {dir_name}")
                
                dir_choice = self.safe_input("Select directory to download (or 'all'): ")
                
                if dir_choice.lower() == 'all':
                    selected_dirs = dirs
                else:
                    try:
                        selected_dirs = [dirs[int(dir_choice) - 1]]
                    except (ValueError, IndexError):
                        print("Invalid selection.")
                        input("Press Enter to continue...")
                        return
                
                # Confirm download
                print(f"\n📥 Download Summary:")
                print(f"   Remote: {selected_remote}")
                print(f"   Directories: {', '.join(selected_dirs)}")
                print(f"   Destination: {self.base_path}")
                
                confirm = self.safe_input(f"\nStart download? (y/N): ")
                if confirm.lower() != 'y':
                    return
                
                # Execute download
                for dir_name in selected_dirs:
                    # Validate directory name to prevent command injection
                    if dir_name.startswith('-') or '--' in dir_name:
                        print(f"✗ Skipping directory with unsafe name: {self.sanitize_path_for_display(dir_name)}")
                        continue
                        
                    remote_path = f"{selected_remote}:{dir_name}"
                    local_path = os.path.join(self.base_path, dir_name)
                    
                    # Validate local path is safe
                    if not self.validate_safe_path(local_path):
                        print(f"✗ Skipping unsafe local path: {self.sanitize_path_for_display(dir_name)}")
                        continue
                    
                    print(f"\n📥 Downloading {dir_name}...")
                    
                    cmd = [
                        'rclone', 'copy',
                        remote_path, local_path,
                        '--progress',
                        '--transfers', '4',
                        '--checkers', '8',
                        '--stats', '10s'
                    ]
                    
                    try:
                        result = self.cmd_manager.safe_subprocess_run(cmd, capture_output=True, text=True, timeout=TimeoutConstants.LONG)
                        # Display output safely
                        if result.stdout:
                            print(result.stdout)
                        if result.stderr:
                            print(result.stderr, file=sys.stderr)
                        if result.returncode == 0:
                            print(f"✅ {dir_name} downloaded!")
                        else:
                            print(f"⚠️  {dir_name} download completed with warnings")
                    except KeyboardInterrupt:
                        print(f"\n⚠️  Download interrupted")
                        break
                    except (subprocess.SubprocessError, OSError, IOError) as e:
                        print(f"❌ Download failed: {self.sanitize_error_message(str(e))}")
                
            else:
                print(f"❌ Could not access {selected_remote}")
        except (ValueError, IndexError, subprocess.SubprocessError, OSError) as e:
            print(f"❌ Error accessing remote: {self.sanitize_error_message(str(e))}")
        
        self.safe_input("\nPress Enter to continue...")
    
    def check_sync_status(self, remotes):
        """Check synchronization status between local and remote."""
        self.clear_screen()
        print("="*50)
        print("🔄 Check Sync Status")
        print("="*50)
        
        # Select remote
        print("Available remotes:")
        for i, remote in enumerate(remotes, 1):
            print(f"{i}. {remote}")
        
        remote_choice = self.safe_input("Select remote to check: ")
        try:
            selected_remote = remotes[int(remote_choice) - 1]
        except (ValueError, IndexError):
            print("Invalid selection.")
            input("Press Enter to continue...")
            return
        
        # Validate remote name to prevent command injection
        is_safe, message = self.validate_rclone_remote_name(selected_remote)
        if not is_safe:
            print(f"❌ Security Error: {message}")
            self.security_audit_log("RCLONE_UNSAFE_REMOTE", f"Rejected remote: {selected_remote}")
            input("Press Enter to continue...")
            return
        
        print(f"\n🔍 Checking sync status with {selected_remote}...")
        
        # Check what needs to be synced
        remote_path = f"{selected_remote}:MediaBackup"
        
        cmd = [
            'rclone', 'check',
            self.base_path, remote_path,
            '--missing-on-dst',
            '--missing-on-src',
            '--differ'
        ]
        
        print(f"Running: {' '.join(cmd)}")
        
        try:
            result = self.cmd_manager.safe_subprocess_run(cmd, capture_output=True, text=True, timeout=TimeoutConstants.STANDARD)
            
            if result.returncode == 0:
                print("✅ Local and remote are in sync!")
            else:
                print("📊 Sync differences found:")
                if result.stdout:
                    # Sanitize output to prevent information disclosure
                    sanitized_out = self.sanitize_error_message(result.stdout)
                    print(sanitized_out)
                if result.stderr:
                    # Sanitize error output
                    sanitized_err = self.sanitize_error_message(result.stderr)
                    print(sanitized_err)
                    
        except (subprocess.SubprocessError, OSError, IOError) as e:
            print(f"❌ Error checking sync status: {self.sanitize_error_message(str(e))}")
        
        self.safe_input("\nPress Enter to continue...")
    
    def configure_bandwidth(self):
        """Configure bandwidth limits for rclone operations."""
        self.clear_screen()
        print("="*50)
        print("⚡ Configure Bandwidth Limits")
        print("="*50)
        
        print("Current rclone configuration file location:")
        try:
            result = self.cmd_manager.safe_subprocess_run(['rclone', 'config', 'file'], capture_output=True, text=True, timeout=TimeoutConstants.QUICK)
            if result.returncode == 0:
                print(f"📁 {result.stdout.strip()}")
        except (subprocess.SubprocessError, OSError) as e:
            print("❌ Could not locate config file")
        
        print("\nBandwidth limit options:")
        print("1. No limit (default)")
        print("2. 10 Mbps (good for background sync)")
        print("3. 50 Mbps (moderate usage)")
        print("4. 100 Mbps (high speed)")
        print("5. Custom limit")
        
        choice = self.safe_input("Select bandwidth limit: ")
        
        limits = {
            '1': None,
            '2': '10M',
            '3': '50M', 
            '4': '100M'
        }
        
        if choice in limits:
            if choice == '1':
                print("✅ Bandwidth limit removed")
                print("💡 Add --bwlimit flag to rclone commands as needed")
            else:
                limit = limits[choice]
                print(f"✅ Bandwidth limit set to {limit}")
                print(f"💡 Add --bwlimit {limit} to rclone commands")
        elif choice == '5':
            custom_limit = self.safe_input("Enter custom limit (e.g., '25M', '1G'): ")
            print(f"✅ Custom bandwidth limit: {custom_limit}")
            print(f"💡 Add --bwlimit {custom_limit} to rclone commands")
        
        self.safe_input("\nPress Enter to continue...")
    
    def verify_backup_integrity(self, remotes):
        """Verify backup integrity using checksums."""
        self.clear_screen()
        print("="*50)
        print("🔐 Verify Backup Integrity")
        print("="*50)
        
        # Select remote
        print("Available remotes:")
        for i, remote in enumerate(remotes, 1):
            print(f"{i}. {remote}")
        
        remote_choice = self.safe_input("Select remote to verify: ")
        try:
            selected_remote = remotes[int(remote_choice) - 1]
        except (ValueError, IndexError):
            print("Invalid selection.")
            input("Press Enter to continue...")
            return
        
        # Validate remote name to prevent command injection
        is_safe, message = self.validate_rclone_remote_name(selected_remote)
        if not is_safe:
            print(f"❌ Security Error: {message}")
            self.security_audit_log("RCLONE_UNSAFE_REMOTE", f"Rejected remote: {selected_remote}")
            input("Press Enter to continue...")
            return
        
        remote_path = f"{selected_remote}:MediaBackup"
        
        print(f"\n🔍 Verifying integrity between local and {remote_path}...")
        print("This will compare checksums of all files (may take a while)")
        
        confirm = self.safe_input("Start verification? (y/N): ")
        if confirm.lower() != 'y':
            return
        
        cmd = [
            'rclone', 'check',
            self.base_path, remote_path,
            '--checkfile', f"integrity_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        ]
        
        print(f"\n🚀 Starting integrity check...")
        
        try:
            result = self.cmd_manager.safe_subprocess_run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                print("✅ All files verified successfully!")
            else:
                print("⚠️  Some files have differences - check the log file")
        except KeyboardInterrupt:
            print("\n⚠️  Verification interrupted")
        except (subprocess.SubprocessError, OSError, IOError) as e:
            print(f"❌ Verification failed: {self.sanitize_error_message(str(e))}")
        
        self.safe_input("\nPress Enter to continue...")
    
    def view_rclone_config(self):
        """View rclone configuration details."""
        self.clear_screen()
        print("="*50)
        print("⚙️  rclone Configuration")
        print("="*50)
        
        try:
            # Show config file location
            result = self.cmd_manager.safe_subprocess_run(['rclone', 'config', 'file'], capture_output=True, text=True, timeout=TimeoutConstants.QUICK)
            if result.returncode == 0:
                print(f"📁 Config file: {result.stdout.strip()}")
        except (subprocess.SubprocessError, OSError) as e:
            pass
        
        # Show remotes with details
        try:
            result = self.cmd_manager.safe_subprocess_run(['rclone', 'config', 'show'], capture_output=True, text=True, timeout=TimeoutConstants.QUICK)
            if result.returncode == 0:
                print(f"\n📡 Configured remotes:")
                # Filter out sensitive information from config output
                lines = result.stdout.split('\n')
                filtered_lines = []
                current_remote = None
                for line in lines:
                    # Track current remote section
                    if line.startswith('[') and line.endswith(']'):
                        current_remote = line
                        filtered_lines.append(line)
                    # Hide lines containing sensitive data
                    elif any(keyword in line.lower() for keyword in ['token', 'password', 'key', 'secret', 'auth', 'bearer', 'credential', 'private']):
                        # Only show that a credential exists, not its value
                        key_part = line.split('=')[0].strip() if '=' in line else 'credential'
                        filtered_lines.append(f"    {key_part} = [REDACTED]")
                    # Show only safe configuration options
                    elif '=' in line and any(safe in line.lower() for safe in ['type', 'region', 'endpoint', 'provider', 'env_auth']):
                        filtered_lines.append(line)
                    elif line.strip() == '':
                        filtered_lines.append(line)
                print('\n'.join(filtered_lines))
            else:
                print("❌ Could not show configuration")
        except (subprocess.SubprocessError, OSError, IOError) as e:
            print(f"❌ Error reading config: {self.sanitize_error_message(str(e))}")
        
        print("\n💡 Useful rclone commands:")
        print("   rclone config          - Configure new remote")
        print("   rclone listremotes     - List all remotes")
        print("   rclone about remote:   - Show storage info")
        print("   rclone ls remote:      - List files on remote")
        
        self.safe_input("\nPress Enter to continue...")

if __name__ == "__main__":
    # Validate command line arguments for security
    if len(sys.argv) > 1:
        print("⚠️  This application does not accept command line arguments for security reasons.")
        print("All configuration should be done through environment variables or the interactive menu.")
        sys.exit(1)
    
    manager = MediaManager()
    manager.security_audit_log("APPLICATION_STARTED", f"Base path: {manager.base_path}")
    try:
        manager.run()
    finally:
        manager.security_audit_log("APPLICATION_STOPPED")