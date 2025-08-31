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
import random
import signal
from concurrent.futures import ThreadPoolExecutor, as_completed

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

class DatabaseContext:
    """Context manager for safe database connections with automatic cleanup."""
    
    def __init__(self, db_path):
        self.db_path = db_path
        self.conn = None
    
    def __enter__(self):
        self.conn = sqlite3.connect(self.db_path, timeout=TimeoutConstants.DATABASE)
        self.conn.row_factory = sqlite3.Row
        # Enable WAL mode for better concurrent access
        self.conn.execute('PRAGMA journal_mode=WAL')
        return self.conn
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.conn:
            if exc_type is None:
                self.conn.commit()
            else:
                self.conn.rollback()
            self.conn.close()
        return False

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
        
        # Store database in secure application directory (not in media directory)
        if os.name == 'nt':  # Windows
            app_data = os.path.expandvars('%APPDATA%')
            db_dir = os.path.join(app_data, 'MediaLibraryManager')
        else:  # Unix-like (macOS, Linux)
            home = os.path.expanduser('~')
            db_dir = os.path.join(home, '.media-library-manager')
        
        # Create secure directory with restrictive permissions
        os.makedirs(db_dir, mode=0o700, exist_ok=True)
        
        self.db_path = os.path.join(db_dir, 'media_library.db')
        
        # Set restrictive permissions on database file if it exists
        if os.path.exists(self.db_path):
            os.chmod(self.db_path, 0o600)  # Read/write for owner only
        
        # Initialize loop safety mechanisms
        self.max_menu_iterations = 1000  # Safety limit to prevent infinite loops
        self.loop_start_time = None
        self.running = True
        
        # Set up signal handlers for graceful shutdown
        signal.signal(signal.SIGTERM, self.graceful_shutdown)
        signal.signal(signal.SIGINT, self.graceful_shutdown)
        
        # Check dependencies at startup
        self.check_dependencies()
        
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
        self.files_scanned_count = 0
        
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
            
            # Apply comprehensive security hardening PRAGMAs
            cursor.execute('PRAGMA journal_mode = WAL')  # Write-Ahead Logging for better concurrency
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
            
            # Create indexes for performance
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_path ON video_files(file_path)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_file_modified ON video_files(file_modified)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_needs_conversion ON video_files(needs_conversion)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_naming_issues ON video_files(naming_issues)')
        
        # Set secure file permissions on database (readable/writable by owner only)
        try:
            os.chmod(self.db_path, 0o600)
        except OSError as e:
            print(f"Warning: Could not set secure permissions on database: {e}")
    
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
        sanitized = re.sub(r'file://[^\s]+', 'file://[PATH]', sanitized)
        
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
            for root, dirs, files in os.walk(directory_path, followlinks=False):
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
                            
                            # Double-check the final path is safe
                            if self.validate_safe_path(file_path):
                                video_files.append(file_path)
                                self.files_scanned_count += 1
                            else:
                                print(f"Warning: Skipping unsafe file: {self.sanitize_path_for_display(file_path)}")
                        
                        self.files_scanned_count += 1
                    
                    except UnicodeError as e:
                        print(f"Warning: Unicode error processing file {file}: {e}")
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
            result = subprocess.run(['ffmpeg', '-version'], capture_output=True, text=True, timeout=TimeoutConstants.QUICK)
            if result.returncode != 0:
                missing_deps.append("FFmpeg")
        except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
            missing_deps.append("FFmpeg")
        
        # Check FFprobe
        try:
            result = subprocess.run(['ffprobe', '-version'], capture_output=True, text=True, timeout=TimeoutConstants.QUICK)
            if result.returncode != 0:
                missing_deps.append("FFprobe")
        except (subprocess.SubprocessError, FileNotFoundError, subprocess.TimeoutExpired):
            missing_deps.append("FFprobe")
        
        # Check Python virtual environment (configurable via environment variable)
        python_env_path = os.environ.get('MEDIA_MANAGER_PYTHON_ENV', 
                                        os.path.join(self.base_path, "convert_env", "bin", "python"))
        
        # Validate the Python environment path is safe
        if not self.validate_safe_path(python_env_path):
            print(f"Warning: Python environment path is unsafe: {self.sanitize_path_for_display(python_env_path)}")
            python_env_path = sys.executable  # Fallback to current Python
        elif not os.path.exists(python_env_path):
            print(f"Warning: Python virtual environment not found at {python_env_path}")
            python_env_path = sys.executable  # Fallback to current Python
        
        self.python_executable = python_env_path
        
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
            result = subprocess.run(['rclone', 'version'], capture_output=True, text=True, timeout=TimeoutConstants.QUICK)
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
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, 
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
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=TimeoutConstants.LONG)  # 1 hour timeout
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
            print(f"⚠️  Data validation failed: {e}")
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
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=TimeoutConstants.STANDARD)
            
            if result.returncode == 0:
                return "File integrity OK"
            else:
                return f"Corruption detected: {result.stderr.strip()}"
                
        except subprocess.TimeoutExpired:
            return "Timeout during check (file may be corrupted)"
        except (subprocess.SubprocessError, OSError, IOError) as e:
            return f"Error checking: {self.sanitize_error_message(str(e))}"

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
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=TimeoutConstants.STANDARD)
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
        print("\nFinding conversion candidates...")
        
        # Direct method implementation - no temporary scripts
        candidates = []
        
        # Count total files first
        total_files = 0
        for root, _, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if (file.lower().endswith(('.mp4', '.mkv', '.avi', '.mov', '.flv')) 
                    and "-CONVERTED" not in file):
                    total_files += 1
        
        print(f"Scanning {total_files} video files for resolution...")
        files_checked = 0
        
        for root, _, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if "-CONVERTED" in file:
                    continue
                    
                file_path = os.path.join(root, file)
                if file.lower().endswith(('.mp4', '.mkv', '.avi', '.mov', '.flv')):
                    files_checked += 1
                    if files_checked % 5 == 0:
                        print(f"Checked {files_checked}/{total_files} files...", end='\r')
                    
                    width, height = self.get_video_resolution_safe(file_path)
                    if width and height and (width > 1920 or height > 1080):
                        try:
                            file_size_gb = os.path.getsize(file_path) / (1024 ** 3)
                            candidates.append(f"{file_path}|{width}x{height}|{file_size_gb:.2f}")
                        except OSError:
                            continue
        
        print(f"\nScan complete! Checked {files_checked} files")
        
        if candidates:
            print(f"\nFound {len(candidates)} videos larger than 1080p:\n")
            
            # Parse candidates list 
            parsed_candidates = []
            for line in candidates:
                if '|' in line:
                    path, resolution, size = line.split('|')
                    parsed_candidates.append((path, resolution, float(size)))
            
            # Save to file in secure location
            candidates_file = os.path.join(self.base_path, "conversion_candidates.txt")
            if not self.validate_safe_path(candidates_file):
                print("Error: Cannot write candidates file to unsafe location")
                return
            
            with open(candidates_file, "w") as f:
                f.write(f"Conversion Candidates - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*80 + "\n\n")
                for path, res, size in sorted(parsed_candidates, key=lambda x: x[2], reverse=True):
                    f.write(f"{res} - {size:.2f} GB - {path}\n")
            
            # Display summary
            for i, (path, res, size) in enumerate(parsed_candidates[:10], 1):
                print(f"{i}. {os.path.basename(path)}")
                print(f"   Resolution: {res}, Size: {size:.2f} GB")
            
            if len(parsed_candidates) > 10:
                print(f"\n... and {len(parsed_candidates) - 10} more")
            
            print(f"\nFull list saved to: conversion_candidates.txt")
        else:
            print("No videos found that need conversion.")
        
        self.safe_input("\nPress Enter to continue...")
        
    def top_shows_by_size(self):
        """Show top 10 TV shows by total size."""
        print("\nCalculating top 10 shows by size...")
        
        tv_path = os.path.join(self.base_path, "TV")
        show_sizes = {}
        
        if os.path.exists(tv_path):
            for show_dir in os.listdir(tv_path):
                show_path = os.path.join(tv_path, show_dir)
                if os.path.isdir(show_path):
                    total_size = 0
                    file_count = 0
                    
                    for root, dirs, files in os.walk(show_path, followlinks=False):
                        for file in files:
                            if file.lower().endswith(self.video_extensions):
                                try:
                                    total_size += os.path.getsize(os.path.join(root, file))
                                    file_count += 1
                                except OSError:
                                    continue
                    
                    if total_size > 0:
                        show_sizes[show_dir] = {
                            'size': total_size,
                            'size_gb': total_size / (1024**3),
                            'file_count': file_count
                        }
        
        # Sort by size
        sorted_shows = sorted(show_sizes.items(), key=lambda x: x[1]['size'], reverse=True)
        
        print("\nTop 10 TV Shows by Size:")
        print("="*60)
        
        for i, (show, info) in enumerate(sorted_shows[:10], 1):
            print(f"{i:2}. {show}")
            print(f"    Size: {info['size_gb']:.2f} GB | Episodes: {info['file_count']}")
        
        total_size = sum(info['size'] for _, info in show_sizes.items())
        print(f"\nTotal TV Shows: {len(show_sizes)}")
        print(f"Total Size: {total_size / (1024**3):.2f} GB")
        
        self.safe_input("\nPress Enter to continue...")
        
    def top_video_files(self):
        """Show top 10 individual video files by size."""
        print("\nFinding top 10 largest video files...")
        
        all_videos = []
        
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
                            'size_gb': size / (1024**3),
                            'relative_path': os.path.relpath(file_path, self.base_path)
                        })
                    except OSError:
                        continue
        
        # Sort by size
        sorted_videos = sorted(all_videos, key=lambda x: x['size'], reverse=True)
        
        print("\nTop 10 Largest Video Files:")
        print("="*80)
        
        for i, video in enumerate(sorted_videos[:10], 1):
            print(f"{i:2}. {video['name']} ({video['size_gb']:.2f} GB)")
            print(f"    {video['relative_path']}")
        
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
        print("\nChecking for videos without English subtitles...")
        
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
        
        # Save to file
        with open(os.path.join(self.base_path, "videos_without_subtitles.txt"), "w") as f:
            f.write(f"Videos Without English Subtitles - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n\n")
            
            for video in sorted(videos_without_subs, key=lambda x: x['relative_path']):
                f.write(f"{video['relative_path']}\n")
                print(f"  {video['name']}")
        
        print(f"\nFull list saved to: videos_without_subtitles.txt")
        
        print("\n📝 Note: To download subtitles, you can use tools like:")
        print("  - subliminal (pip install subliminal)")
        print("  - OpenSubtitles.org API")
        print("  - subdl (pip install subdl)")
        
        self.safe_input("\nPress Enter to continue...")
        
    def convert_to_resolution(self, target_resolution):
        """Convert videos to specified resolution (1080p or 720p)."""
        print(f"\nPreparing to convert videos to {target_resolution}p...")
        
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
        
        print(f"\nOptions:")
        print(f"1. Convert all videos larger than {target_resolution}p")
        print(f"2. Convert specific directory")
        print(f"3. Convert single file")
        print(f"0. Cancel")
        
        choice = self.safe_input("\nEnter your choice: ")
        
        if choice == '0':
            return
        elif choice == '1':
            # Run scan_and_convert with modifications for target resolution
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
                    print(f"✗ Error renaming files: {e}")
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
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=TimeoutConstants.LONG)  # 1 hour timeout
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
        
    def download_subtitles(self):
        """Download English subtitles for videos."""
        print("\nSubtitle Download Options:")
        print("1. Download for all videos without subtitles")
        print("2. Download for specific directory")
        print("3. Download for single video")
        print("0. Cancel")
        
        choice = self.safe_input("\nEnter your choice: ")
        
        if choice == '0':
            return
            
        # Check if subliminal is available
        if not self.optional_deps.get('subliminal', False):
            print("\nSubliminal is not installed. Please install it manually:")
            print("pip install subliminal")
            self.safe_input("\nPress Enter to continue...")
            return
        
        if choice == '1':
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
        
    def download_subtitle_for_file(self, video_path, quiet=False):
        """Download subtitle for a single video file using subliminal."""
        try:
            # Use subliminal command line tool
            cmd = [
                sys.executable, "-m", "subliminal",
                "download",
                "-l", "en",  # English only
                "-p", "opensubtitles", "podnapisi", "tvsubtitles", "thesubdb",  # providers
                video_path
            ]
            
            if not quiet:
                print(f"     File: {os.path.basename(video_path)}")
                print(f"     Searching providers...")
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=TimeoutConstants.STANDARD)
            
            # Show subliminal output if there's an error or in verbose mode
            if not quiet and result.stderr:
                print(f"     Debug: {result.stderr.strip()}")
            
            if result.returncode == 0:
                # Check if subtitle was downloaded
                base_name = os.path.splitext(video_path)[0]
                if any(os.path.exists(f"{base_name}{ext}") for ext in ['.srt', '.en.srt']):
                    if not quiet:
                        print("✓ Subtitle downloaded successfully!")
                    return True
                else:
                    if not quiet:
                        print("✗ No subtitle found for this video")
                    return False
            else:
                if not quiet:
                    print(f"✗ Error downloading subtitle: {result.stderr}")
                return False
                
        except (subprocess.SubprocessError, OSError, IOError) as e:
            if not quiet:
                print(f"✗ Error: {self.sanitize_error_message(str(e))}")
            return False
        
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
                    print(f"Error removing {folder}: {e}")
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
                    
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=TimeoutConstants.STANDARD)
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
        
    def smart_organization(self):
        """Smart organization menu for Plex compatibility."""
        while True:
            self.clear_screen()
            print("="*60)
            print("📂 Smart Organization")
            print("="*60)
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
        print("\nAuto-rename TV shows to Plex format...")
        
        import re
        
        tv_path = os.path.join(self.base_path, "TV")
        if not os.path.exists(tv_path):
            print("TV directory not found!")
            self.safe_input("\nPress Enter to continue...")
            return
        
        rename_candidates = []
        
        # Patterns to extract season and episode
        patterns = [
            (r'[Ss](\d+)[Ee](\d+)', 'S{:02d}E{:02d}'),  # S01E01
            (r'(\d+)x(\d+)', 'S{:02d}E{:02d}'),  # 1x01
            (r'Season\s*(\d+).*Episode\s*(\d+)', 'S{:02d}E{:02d}'),  # Season 1 Episode 1
        ]
        
        for show_dir in os.listdir(tv_path):
            show_path = os.path.join(tv_path, show_dir)
            if os.path.isdir(show_path):
                for root, dirs, files in os.walk(show_path, followlinks=False):
                    for file in files:
                        if file.lower().endswith(self.video_extensions):
                            file_path = os.path.join(root, file)
                            
                            # Try to extract season and episode
                            new_name = None
                            for pattern, format_str in patterns:
                                match = re.search(pattern, file, re.IGNORECASE)
                                if match:
                                    try:
                                        season = int(match.group(1))
                                        episode = int(match.group(2))
                                    except (ValueError, IndexError):
                                        continue
                                    
                                    # Create new name
                                    ext = os.path.splitext(file)[1]
                                    episode_str = format_str.format(season, episode)
                                    new_name = f"{show_dir} - {episode_str}{ext}"
                                    break
                            
                            if new_name and new_name != file:
                                new_path = os.path.join(root, new_name)
                                if not os.path.exists(new_path):
                                    rename_candidates.append((file_path, new_path, file, new_name, show_dir))
        
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
            renamed = 0
            for old_path, new_path, _, _, _ in rename_candidates:
                try:
                    os.rename(old_path, new_path)
                    renamed += 1
                except OSError as e:
                    print(f"Error renaming {self.sanitize_path_for_display(old_path)}: {self.sanitize_error_message(str(e))}")
            print(f"✓ Renamed {renamed} episodes")
        
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
                    print(f"Error moving {filename}: {e}")
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
                    print(f"Error moving {filename}: {e}")
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
                            print(f"Error moving {filename}: {e}")
                
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
            print()
            print("🗂️  ORGANIZATION & CLEANUP:")
            print("13. Smart Organization")
            print("14. Find Duplicate Videos")
            print("15. Quick Fixes")
            print()
            print("🗑️  FILE MANAGEMENT:")
            print("16. Delete TV show")
            print("17. Delete video file")
            print()
            print("☁️  BACKUP & SYNC:")
            print("18. Backup & Sync (rclone)")
            print()
            print("0. Exit")
            print()
            
            try:
                # Rate limiting check before processing menu choice
                if not self.check_rate_limit("menu_operation"):
                    time.sleep(2)  # Force a small delay before showing menu again
                    continue
                
                choice = self.safe_input("Enter your choice: ")
                
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
                    self.smart_organization()
                elif choice == '14':
                    self.find_duplicates()
                elif choice == '15':
                    self.quick_fixes()
                elif choice == '16':
                    self.delete_show()
                elif choice == '17':
                    self.delete_video_file()
                elif choice == '18':
                    self.backup_sync()
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
            
            # Check for excessive runtime (1 hour timeout)
            if time.time() - self.loop_start_time > 3600:
                print("⚠️  Menu timeout reached after 1 hour. Exiting for safety.")
                break
        
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
                
                result = subprocess.run(cmd, capture_output=True, timeout=TimeoutConstants.LONG)
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
                
                result = subprocess.run(cmd, capture_output=True, timeout=TimeoutConstants.MEDIUM)  # 5 minute timeout for subtitle extraction
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
        """Comprehensive background analysis with progress tracking and caching."""
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
        
        print("\n" + "="*60)
        print("🚀 Starting Background Analysis...")
        print("="*60)
        
        start_time = time.time()
        
        # Initialize analysis results with real-time issue tracking
        analysis_results = {
            'files_scanned': 0,
            'total_files': 0,
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
        
        # Real-time issue discovery tracking
        found_issues = {
            'subtitle_issues': [],
            'system_files_found': [],
            'naming_problems': [],
            'codec_problems': [],
            'corrupted_files': [],
            'background_tasks': []
        }
        
        # Ask about auto-fix options
        print("🔧 Auto-fix options:")
        auto_download_subs = self.safe_input("Auto-download missing subtitles in background? (y/N): ").lower() == 'y'
        auto_remove_system = self.safe_input("Auto-remove system files (.DS_Store, etc.)? (y/N): ").lower() == 'y'
        check_corruption = self.safe_input("Check for corrupted video files? (y/N): ").lower() == 'y'
        
        # Progress tracking variables
        progress = {
            'file_scan': {'current': 0, 'total': 0, 'complete': False},
            'resolution_analysis': {'current': 0, 'total': 0, 'complete': False},
            'subtitle_check': {'current': 0, 'total': 0, 'complete': False},
            'naming_analysis': {'current': 0, 'total': 0, 'complete': False},
            'codec_analysis': {'current': 0, 'total': 0, 'complete': False},
            'corruption_check': {'current': 0, 'total': 0, 'complete': False}
        }
        
        if not check_corruption:
            with self._progress_lock:
                progress['corruption_check']['complete'] = True
        
        def update_progress_display():
            """Update progress bars with real-time issue discovery."""
            while True:
                with self._progress_lock:
                    all_complete = all(p['complete'] for p in progress.values())
                    if all_complete:
                        break
                    
                    progress_copy = {}
                    for task, data in progress.items():
                        progress_copy[task] = data.copy()
                
                print("\033[2J\033[H")  # Clear screen and go to top
                print("="*60)
                print("🔍 Background Analysis in Progress...")
                print("="*60)
                
                # Progress bars
                for task, data in progress_copy.items():
                    if data['total'] > 0:
                        pct = (data['current'] / data['total']) * 100
                        filled = int(pct / 2)
                        bar = "█" * filled + "░" * (50 - filled)
                        status = "✓" if data['complete'] else "⏳"
                        task_name = task.replace('_', ' ').title()
                        print(f"{status} {task_name:<20} [{bar}] {pct:5.1f}% ({data['current']}/{data['total']})")
                    else:
                        task_name = task.replace('_', ' ').title()
                        print(f"⏳ {task_name:<20} [{'░' * 50}]   0.0% (0/0)")
                
                # Real-time issue discovery
                if any(found_issues.values()):
                    print("\n🚨 ISSUES FOUND:")
                    
                    if found_issues['subtitle_issues']:
                        recent_subs = found_issues['subtitle_issues'][-3:]  # Show last 3
                        for issue in recent_subs:
                            print(f"   📝 {issue}")
                        if len(found_issues['subtitle_issues']) > 3:
                            print(f"   ... and {len(found_issues['subtitle_issues']) - 3} more")
                    
                    if found_issues['system_files_found']:
                        print(f"   🗑️  System files: {len(found_issues['system_files_found'])}")
                    
                    if found_issues['naming_problems']:
                        recent_naming = found_issues['naming_problems'][-2:]
                        for issue in recent_naming:
                            print(f"   📂 {issue}")
                    
                    if found_issues['codec_problems']:
                        print(f"   🎬 Old codecs: {len(found_issues['codec_problems'])}")
                    
                    if found_issues['corrupted_files']:
                        recent_corrupt = found_issues['corrupted_files'][-2:]
                        for issue in recent_corrupt:
                            print(f"   💥 {issue}")
                
                # Active background tasks
                if self.active_tasks:
                    print(f"\n⚡ ACTIVE TASKS ({len(self.active_tasks)}/{self.max_concurrent_tasks}):")
                    for task_id, task in self.active_tasks.items():
                        elapsed = time.time() - task['started_at']
                        print(f"   🔧 Task {task_id}: {task['description']} ({elapsed:.1f}s)")
                
                # Completed tasks (show last few)
                if found_issues['background_tasks']:
                    recent_completed = found_issues['background_tasks'][-3:]
                    print(f"\n✅ COMPLETED TASKS:")
                    for task_result in recent_completed:
                        print(f"   {task_result}")
                
                time.sleep(0.5 + random.uniform(0, 0.1))  # Add jitter to prevent timing attacks
        
        # Start progress display in background thread
        progress_thread = threading.Thread(target=update_progress_display, daemon=True)
        progress_thread.start()
        
        # Phase 1: Initial file scan with incremental detection
        if incremental_mode:
            print("Phase 1: Scanning for new/changed files...")
        else:
            print("Phase 1: Scanning all video files...")
            
        all_video_files = []
        files_to_analyze = []
        
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    all_video_files.append(file_path)
                    
                    # Check if file needs analysis
                    if not incremental_mode or self.is_file_changed(file_path):
                        files_to_analyze.append(file_path)
        
        with self._progress_lock:
            progress['file_scan']['total'] = len(all_video_files)
        analysis_results['total_files'] = len(all_video_files)
        
        if incremental_mode:
            print(f"Found {len(files_to_analyze)} new/changed files out of {len(all_video_files)} total")
        else:
            files_to_analyze = all_video_files
        
        for i, file_path in enumerate(all_video_files):
            with self._progress_lock:
                progress['file_scan']['current'] = i + 1
            analysis_results['files_scanned'] = i + 1
            time.sleep(0.001 + random.uniform(0, 0.0005))  # Jitter for timing attack prevention
        
        with self._progress_lock:
            progress['file_scan']['complete'] = True
        
        # Phase 2: Load cached data and analyze new/changed files
        with self._progress_lock:
            progress['resolution_analysis']['total'] = len(files_to_analyze)
            progress['codec_analysis']['total'] = len(files_to_analyze)
        
        # Load existing data from database for unchanged files
        if incremental_mode:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            # Get cached data for unchanged files
            unchanged_files = [f for f in all_video_files if f not in files_to_analyze]
            for file_path in unchanged_files:
                # Validate file path before database query
                if not self.validate_safe_path(file_path):
                    continue
                cursor.execute('SELECT * FROM video_files WHERE file_path = ?', (file_path,))
                row = cursor.fetchone()
                if row:
                    # Add to results from cache
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
            
            conn.close()
        
        # Analyze only new/changed files
        for i, file_path in enumerate(files_to_analyze):
            with self._progress_lock:
                progress['resolution_analysis']['current'] = i + 1
                progress['codec_analysis']['current'] = i + 1
            
            try:
                # Get file stats
                stat = os.stat(file_path)
                file_data = {
                    'file_path': file_path,
                    'relative_path': os.path.relpath(file_path, self.base_path),
                    'filename': os.path.basename(file_path),
                    'file_size': stat.st_size,
                    'file_modified': stat.st_mtime,
                    'naming_issues': []
                }
                
                # Get video info
                video_info = self.get_video_info(file_path)
                if video_info:
                    for stream in video_info.get('streams', []):
                        if stream.get('codec_type') == 'video':
                            width = stream.get('width', 0)
                            height = stream.get('height', 0)
                            codec = stream.get('codec_name', 'unknown')
                            duration = float(stream.get('duration', 0))
                            bitrate = int(stream.get('bit_rate', 0)) if stream.get('bit_rate') else None
                            
                            file_data.update({
                                'width': width,
                                'height': height,
                                'codec': codec,
                                'duration': duration,
                                'bitrate': bitrate
                            })
                            
                            # Check if needs conversion
                            if width > 1920 or height > 1080:
                                size_gb = stat.st_size / (1024**3)
                                file_data['needs_conversion'] = True
                                file_data['conversion_reason'] = f"Resolution {width}x{height} > 1080p"
                                
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
                            
                            # Check large files
                            size_gb = stat.st_size / (1024**3)
                            if size_gb > 10:
                                analysis_results['large_files'].append({
                                    'path': file_path,
                                    'size_gb': size_gb,
                                    'resolution': f"{width}x{height}"
                                })
                            break
                
                # Analyze naming issues
                filename = os.path.basename(file_path)
                issues = []
                
                if '  ' in filename:
                    issues.append('Double spaces')
                if '..' in filename:
                    issues.append('Double periods')
                if filename.count('.') > 2:
                    issues.append('Too many periods')
                if any(char in filename for char in ['[', ']', '{', '}', '(', ')']):
                    if not any(pattern in filename.lower() for pattern in ['1080p', '720p', '4k', 'x264', 'x265']):
                        issues.append('Unnecessary brackets')
                
                # Check Plex naming compliance
                relative_path = os.path.relpath(file_path, self.base_path)
                if '/TV/' in relative_path:
                    if not (' - S' in filename and 'E' in filename):
                        issues.append('Non-Plex TV format')
                elif '/Movies/' in relative_path:
                    if not ('(' in filename and ')' in filename):
                        issues.append('Missing year in movie title')
                
                file_data['naming_issues'] = issues
                if issues:
                    analysis_results['naming_issues'].append({
                        'path': file_path,
                        'issues': issues
                    })
                
                # Check subtitles
                base_name = os.path.splitext(file_path)[0]
                subtitle_files = [f"{base_name}.srt", f"{base_name}.en.srt", f"{base_name}.eng.srt"]
                has_external_subs = any(os.path.exists(sub_file) for sub_file in subtitle_files)
                
                has_embedded_subs = False
                if video_info:
                    for stream in video_info.get('streams', []):
                        if stream.get('codec_type') == 'subtitle':
                            tags = stream.get('tags', {})
                            language = tags.get('language', '').lower()
                            if language in ['en', 'eng', 'english'] or not language:
                                has_embedded_subs = True
                                break
                
                file_data['has_external_subs'] = has_external_subs
                file_data['has_embedded_subs'] = has_embedded_subs
                
                if not has_external_subs and not has_embedded_subs:
                    analysis_results['missing_subtitles'].append(file_path)
                    found_issues['subtitle_issues'].append(f"Missing subtitles: {os.path.basename(file_path)}")
                    
                    # Auto-queue subtitle download if enabled
                    if auto_download_subs and len(self.active_tasks) < self.max_concurrent_tasks:
                        task_desc = f"Download subtitles for {os.path.basename(file_path)}"
                        self.add_background_task('subtitle', file_path, self.download_subtitle_task, task_desc)
                
                # Check for naming issues and report
                if issues:
                    issue_desc = f"{os.path.basename(file_path)}: {', '.join(issues[:2])}"
                    found_issues['naming_problems'].append(issue_desc)
                
                # Report codec issues
                if file_data.get('codec') in ['mpeg4', 'xvid', 'divx', 'wmv3']:
                    found_issues['codec_problems'].append(f"{os.path.basename(file_path)}: {file_data['codec']}")
                
                # Save to database
                self.save_video_metadata(file_data)
                
            except (OSError, IOError, ValueError, subprocess.SubprocessError) as e:
                print(f"Error analyzing {file_path}: {self.sanitize_error_message(str(e))}")
                continue
            
            time.sleep(0.001 + random.uniform(0, 0.0005))  # Jitter for timing attack prevention
        
        with self._progress_lock:
            progress['resolution_analysis']['complete'] = True
            progress['codec_analysis']['complete'] = True
            progress['naming_analysis']['complete'] = True
            progress['subtitle_check']['complete'] = True
        
        # Phase 3: Corruption checking (if enabled)
        if check_corruption:
            with self._progress_lock:
                progress['corruption_check']['total'] = len(files_to_analyze)
            
            # Check for corruption on files that had analysis issues
            corruption_candidates = []
            for file_path in files_to_analyze:
                # Only check files that might be problematic
                if (file_path in [f['path'] for f in analysis_results['conversion_candidates']] or
                    any(os.path.basename(file_path) in issue for issue in found_issues['codec_problems'])):
                    corruption_candidates.append(file_path)
            
            for i, file_path in enumerate(corruption_candidates):
                with self._progress_lock:
                    progress['corruption_check']['current'] = i + 1
                
                # Queue corruption check as background task
                if len(self.active_tasks) < self.max_concurrent_tasks:
                    task_desc = f"Check integrity: {os.path.basename(file_path)}"
                    self.add_background_task('corruption', file_path, self.check_video_corruption_task, task_desc)
                
                time.sleep(0.001 + random.uniform(0, 0.0005))  # Jitter for timing attack prevention
        
        with self._progress_lock:
            progress['corruption_check']['complete'] = True
        
        # Wait for progress display to finish
        time.sleep(1 + random.uniform(0, 0.2))  # Add jitter to prevent timing attacks
        
        # Scan for system files with auto-remove option
        print("\n🗑️  Scanning for system files...")
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file in ['.DS_Store', 'Thumbs.db', 'desktop.ini'] or file.startswith('._'):
                    file_path = os.path.join(root, file)
                    analysis_results['system_files'].append(file_path)
                    found_issues['system_files_found'].append(f"System file: {os.path.relpath(file_path, self.base_path)}")
                    
                    # Auto-queue removal if enabled
                    if auto_remove_system and len(self.active_tasks) < self.max_concurrent_tasks:
                        task_desc = f"Remove system file: {file}"
                        self.add_background_task('cleanup', file_path, self.remove_system_file_task, task_desc)
        
        # Process any queued background tasks
        if not self.task_queue.empty():
            self.process_background_tasks(found_issues)
        
        # Calculate analysis duration
        analysis_duration = time.time() - start_time
        
        # Generate recommendations
        recommendations = []
        
        if analysis_results['conversion_candidates']:
            total_size = sum(f['size_gb'] for f in analysis_results['conversion_candidates'])
            recommendations.append({
                'priority': 'HIGH',
                'category': 'Storage Optimization',
                'task': f"Convert {len(analysis_results['conversion_candidates'])} videos from 4K+ to 1080p",
                'benefit': f"Could save ~{total_size * 0.6:.1f} GB of storage",
                'action': 'Use Option 8: Convert videos to 1080p'
            })
        
        if analysis_results['codec_issues']:
            recommendations.append({
                'priority': 'MEDIUM',
                'category': 'Compatibility',
                'task': f"Convert {len(analysis_results['codec_issues'])} videos with old codecs",
                'benefit': 'Improve playback compatibility and reduce file sizes',
                'action': 'Use Option 16: Batch Operations → Codec Operations'
            })
        
        if analysis_results['naming_issues']:
            recommendations.append({
                'priority': 'MEDIUM', 
                'category': 'Organization',
                'task': f"Fix naming issues in {len(analysis_results['naming_issues'])} files",
                'benefit': 'Better Plex media server organization and metadata',
                'action': 'Use Option 14: Smart Organization'
            })
        
        if analysis_results['missing_subtitles']:
            recommendations.append({
                'priority': 'LOW',
                'category': 'Accessibility',
                'task': f"Download subtitles for {len(analysis_results['missing_subtitles'])} videos",
                'benefit': 'Better accessibility and viewing experience',
                'action': 'Use Option 10: Download English subtitles'
            })
        
        if analysis_results['system_files']:
            recommendations.append({
                'priority': 'LOW',
                'category': 'Cleanup',
                'task': f"Remove {len(analysis_results['system_files'])} system files",
                'benefit': 'Clean up unnecessary system files',
                'action': 'Use Option 11: Quick Fixes'
            })
        
        analysis_results['recommendations'] = recommendations
        
        # Save analysis session to database
        self.save_analysis_session(
            len(all_video_files), 
            len(files_to_analyze),
            analysis_duration,
            recommendations
        )
        
        # Display results with background task info
        self.display_analysis_results({
            'session': {
                'timestamp': time.time(),
                'total_files': len(all_video_files),
                'files_analyzed': len(files_to_analyze),
                'duration_seconds': analysis_duration
            },
            'analysis_results': analysis_results,
            'found_issues': found_issues,
            'background_tasks_completed': len(self.completed_tasks)
        })
    
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
        
        self.safe_input("\nPress Enter to continue...")
    
    def rebuild_analysis_from_db(self):
        """Rebuild analysis results from database."""
        conn = self.get_db_connection()
        cursor = conn.cursor()
        
        results = {
            'conversion_candidates': [],
            'naming_issues': [],
            'missing_subtitles': [],
            'system_files': [],
            'large_files': [],
            'codec_issues': [],
            'recommendations': []
        }
        
        try:
            # Get conversion candidates
            cursor.execute('SELECT * FROM video_files WHERE needs_conversion = 1')
            for row in cursor.fetchall():
                results['conversion_candidates'].append({
                    'path': row['file_path'],
                    'width': row['width'],
                    'height': row['height'],
                    'size_gb': row['file_size'] / (1024**3),
                    'codec': row['codec']
                })
            
            # Get naming issues
            cursor.execute('SELECT * FROM video_files WHERE naming_issues IS NOT NULL')
            for row in cursor.fetchall():
                results['naming_issues'].append({
                    'path': row['file_path'],
                    'issues': row['naming_issues'].split(',')
                })
            
            # Get missing subtitles
            cursor.execute('SELECT * FROM video_files WHERE has_external_subs = 0 AND has_embedded_subs = 0')
            for row in cursor.fetchall():
                results['missing_subtitles'].append(row['file_path'])
            
            # Get codec issues
            cursor.execute("SELECT * FROM video_files WHERE codec IN ('mpeg4', 'xvid', 'divx', 'wmv3')")
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
                
        finally:
            conn.close()
            
        # Scan for system files (not cached)
        for root, dirs, files in os.walk(self.base_path, followlinks=False):
            for file in files:
                if file in ['.DS_Store', 'Thumbs.db', 'desktop.ini'] or file.startswith('._'):
                    results['system_files'].append(os.path.join(root, file))
        
        return results
    
    def view_previous_analyses(self):
        """View previous analysis sessions."""
        self.clear_screen()
        print("="*60)
        print("📋 Previous Analysis Sessions")
        print("="*60)
        
        conn = self.get_db_connection()
        cursor = conn.cursor()
        
        try:
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
                
        finally:
            conn.close()
    
    def check_rclone_installed(self):
        """Check if rclone is installed and configured."""
        try:
            result = subprocess.run(['rclone', 'version'], capture_output=True, text=True, timeout=TimeoutConstants.QUICK)
            if result.returncode == 0:
                return True
        except FileNotFoundError:
            return False
        return False
    
    def get_rclone_remotes(self):
        """Get list of configured rclone remotes."""
        try:
            result = subprocess.run(['rclone', 'listremotes'], capture_output=True, text=True, timeout=TimeoutConstants.QUICK)
            if result.returncode == 0:
                remotes = [line.strip().rstrip(':') for line in result.stdout.strip().split('\n') if line.strip()]
                return remotes
        except (subprocess.SubprocessError, OSError) as e:
            print(f"Warning: Could not list rclone remotes: {e}")
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
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=TimeoutConstants.LONG)
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
            result = subprocess.run(cmd, capture_output=True, text=True)
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
        
        # List remote directories
        print(f"\nScanning {selected_remote} for directories...")
        try:
            result = subprocess.run([
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
                        result = subprocess.run(cmd, capture_output=True, text=True, timeout=TimeoutConstants.LONG)
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
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=TimeoutConstants.STANDARD)
            
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
            result = subprocess.run(['rclone', 'config', 'file'], capture_output=True, text=True, timeout=TimeoutConstants.QUICK)
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
            result = subprocess.run(cmd, capture_output=True, text=True)
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
            result = subprocess.run(['rclone', 'config', 'file'], capture_output=True, text=True, timeout=TimeoutConstants.QUICK)
            if result.returncode == 0:
                print(f"📁 Config file: {result.stdout.strip()}")
        except (subprocess.SubprocessError, OSError) as e:
            pass
        
        # Show remotes with details
        try:
            result = subprocess.run(['rclone', 'config', 'show'], capture_output=True, text=True, timeout=TimeoutConstants.QUICK)
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