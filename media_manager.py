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

class MediaManager:
    def __init__(self, base_path="/Volumes/media/Video"):
        self.base_path = base_path
        self.video_extensions = ('.mp4', '.mkv', '.avi', '.mov', '.flv', '.m4v', '.wmv')
        self.db_path = os.path.join(base_path, 'media_library.db')
        self.init_database()
        
    def init_database(self):
        """Initialize SQLite database for video metadata caching."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
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
        
        conn.commit()
        conn.close()
    
    def get_db_connection(self):
        """Get database connection with row factory."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn
    
    def get_file_checksum(self, file_path, size_limit_gb=1):
        """Generate checksum for small files or size-based hash for large files."""
        try:
            file_size = os.path.getsize(file_path)
            
            # For large files, use size + mtime as quick hash
            if file_size > size_limit_gb * 1024**3:
                mtime = os.path.getmtime(file_path)
                return f"size_{file_size}_mtime_{int(mtime)}"
            
            # For smaller files, use actual file hash
            hash_md5 = hashlib.md5()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    hash_md5.update(chunk)
            return hash_md5.hexdigest()
            
        except:
            return None
    
    def is_file_changed(self, file_path):
        """Check if file has changed since last scan."""
        conn = self.get_db_connection()
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
            
        except:
            return True  # Error, assume changed
        finally:
            conn.close()
    
    def save_video_metadata(self, file_data):
        """Save or update video metadata in database."""
        conn = self.get_db_connection()
        cursor = conn.cursor()
        
        try:
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
            
            conn.commit()
        finally:
            conn.close()
    
    def get_cached_analysis(self, max_age_hours=24):
        """Get cached analysis results if recent enough."""
        conn = self.get_db_connection()
        cursor = conn.cursor()
        
        try:
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
            
        finally:
            conn.close()
    
    def save_analysis_session(self, total_files, files_analyzed, duration_seconds, recommendations):
        """Save analysis session metadata."""
        conn = self.get_db_connection()
        cursor = conn.cursor()
        
        try:
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
            conn.commit()
        finally:
            conn.close()

    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')
        
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
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                return json.loads(result.stdout)
        except Exception as e:
            print(f"Error getting info for {file_path}: {e}")
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
        total_files = sum(1 for root, dirs, files in os.walk(self.base_path) 
                         for file in files if file.lower().endswith(self.video_extensions))
        
        print(f"Found {total_files} video files to inventory\n")
        
        for root, dirs, files in os.walk(self.base_path):
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
        
        # Save inventory to file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        inventory_file = f"video_inventory_{timestamp}.txt"
        
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
        input("\nPress Enter to continue...")
        
    def list_conversion_candidates(self):
        """List videos that are candidates for conversion."""
        print("\nFinding conversion candidates...")
        
        # Use the scan_and_convert.py script's logic
        cmd = [
            "./convert_env/bin/python",
            "scan_and_convert.py",
            self.base_path
        ]
        
        # Create a temporary version that just lists without prompting
        temp_script = """import os
import subprocess
import sys

def get_video_resolution(file_path):
    cmd = [
        "ffprobe",
        "-v", "error",
        "-select_streams", "v:0",
        "-show_entries", "stream=width,height",
        "-of", "csv=s=x:p=0",
        file_path
    ]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode == 0:
        try:
            width, height = result.stdout.strip().split('x')
            return int(width), int(height)
        except ValueError:
            pass
    return None, None

directory = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
candidates = []

# Count total files first
total_files = sum(1 for root, _, files in os.walk(directory) 
                 for file in files 
                 if file.lower().endswith(('.mp4', '.mkv', '.avi', '.mov', '.flv')) 
                 and "-CONVERTED" not in file)

print(f"Scanning {total_files} video files for resolution...", file=sys.stderr)
files_checked = 0

for root, _, files in os.walk(directory):
    for file in files:
        if "-CONVERTED" in file:
            continue
        file_path = os.path.join(root, file)
        if file.lower().endswith(('.mp4', '.mkv', '.avi', '.mov', '.flv')):
            files_checked += 1
            if files_checked % 5 == 0:
                print(f"Checked {files_checked}/{total_files} files...", file=sys.stderr, end='\\r')
            
            width, height = get_video_resolution(file_path)
            if width and height and (width > 1920 or height > 1080):
                file_size_gb = os.path.getsize(file_path) / (1024 ** 3)
                print(f"{file_path}|{width}x{height}|{file_size_gb:.2f}")

print(f"\\nScan complete! Checked {files_checked} files", file=sys.stderr)
"""
        
        with open("temp_scan.py", "w") as f:
            f.write(temp_script)
        
        result = subprocess.run(
            ["./convert_env/bin/python", "temp_scan.py", self.base_path],
            capture_output=True,
            text=True
        )
        
        os.remove("temp_scan.py")
        
        if result.stdout:
            lines = result.stdout.strip().split('\n')
            print(f"\nFound {len(lines)} videos larger than 1080p:\n")
            
            candidates = []
            for line in lines:
                if '|' in line:
                    path, resolution, size = line.split('|')
                    candidates.append((path, resolution, float(size)))
            
            # Save to file
            with open("conversion_candidates.txt", "w") as f:
                f.write(f"Conversion Candidates - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*80 + "\n\n")
                for path, res, size in sorted(candidates, key=lambda x: x[2], reverse=True):
                    f.write(f"{res} - {size:.2f} GB - {path}\n")
            
            # Display summary
            for i, (path, res, size) in enumerate(candidates[:10], 1):
                print(f"{i}. {os.path.basename(path)}")
                print(f"   Resolution: {res}, Size: {size:.2f} GB")
            
            if len(candidates) > 10:
                print(f"\n... and {len(candidates) - 10} more")
            
            print(f"\nFull list saved to: conversion_candidates.txt")
        else:
            print("No videos found that need conversion.")
        
        input("\nPress Enter to continue...")
        
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
                    
                    for root, dirs, files in os.walk(show_path):
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
        
        input("\nPress Enter to continue...")
        
    def top_video_files(self):
        """Show top 10 individual video files by size."""
        print("\nFinding top 10 largest video files...")
        
        all_videos = []
        
        for root, dirs, files in os.walk(self.base_path):
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
        
        input("\nPress Enter to continue...")
        
    def delete_show(self):
        """Delete a TV show."""
        tv_path = os.path.join(self.base_path, "TV")
        
        if not os.path.exists(tv_path):
            print("TV directory not found!")
            input("\nPress Enter to continue...")
            return
        
        shows = [d for d in os.listdir(tv_path) if os.path.isdir(os.path.join(tv_path, d))]
        shows.sort()
        
        print("\nAvailable TV Shows:")
        print("="*60)
        
        for i, show in enumerate(shows, 1):
            show_path = os.path.join(tv_path, show)
            size = sum(os.path.getsize(os.path.join(root, f)) 
                      for root, _, files in os.walk(show_path) 
                      for f in files) / (1024**3)
            print(f"{i:3}. {show} ({size:.2f} GB)")
        
        print(f"\n  0. Cancel")
        
        try:
            choice = int(input("\nEnter show number to delete: "))
            if choice == 0:
                return
            
            if 1 <= choice <= len(shows):
                show_to_delete = shows[choice - 1]
                show_path = os.path.join(tv_path, show_to_delete)
                
                confirm = input(f"\nAre you sure you want to delete '{show_to_delete}'? (yes/no): ")
                if confirm.lower() == 'yes':
                    shutil.rmtree(show_path)
                    print(f"✓ Deleted '{show_to_delete}'")
                else:
                    print("Deletion cancelled.")
            else:
                print("Invalid selection!")
        except (ValueError, KeyboardInterrupt):
            print("\nCancelled.")
        
        input("\nPress Enter to continue...")
        
    def delete_video_file(self):
        """Delete a specific video file."""
        search = input("\nEnter part of the filename to search for: ").strip()
        
        if not search:
            return
        
        matching_files = []
        
        for root, dirs, files in os.walk(self.base_path):
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
            input("\nPress Enter to continue...")
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
            choice = int(input("\nEnter file number to delete: "))
            if choice == 0:
                return
            
            if 1 <= choice <= min(len(matching_files), 20):
                file_to_delete = matching_files[choice - 1]
                
                confirm = input(f"\nAre you sure you want to delete '{file_to_delete['name']}'? (yes/no): ")
                if confirm.lower() == 'yes':
                    os.remove(file_to_delete['path'])
                    print(f"✓ Deleted '{file_to_delete['name']}'")
                else:
                    print("Deletion cancelled.")
            else:
                print("Invalid selection!")
        except (ValueError, KeyboardInterrupt):
            print("\nCancelled.")
        
        input("\nPress Enter to continue...")
        
    def check_subtitles(self):
        """Check which videos don't have English subtitles."""
        print("\nChecking for videos without English subtitles...")
        
        videos_without_subs = []
        videos_checked = 0
        
        for root, dirs, files in os.walk(self.base_path):
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
        with open("videos_without_subtitles.txt", "w") as f:
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
        
        input("\nPress Enter to continue...")
        
    def convert_to_resolution(self, target_resolution):
        """Convert videos to specified resolution (1080p or 720p)."""
        print(f"\nPreparing to convert videos to {target_resolution}p...")
        
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
        
        choice = input("\nEnter your choice: ").strip()
        
        if choice == '0':
            return
        elif choice == '1':
            # Run scan_and_convert with modifications for target resolution
            self.run_conversion_scan(target_resolution, target_width, target_height)
        elif choice == '2':
            directory = input("\nEnter directory path: ").strip()
            if os.path.exists(directory):
                self.run_conversion_scan(target_resolution, target_width, target_height, directory)
            else:
                print("Directory not found!")
                input("\nPress Enter to continue...")
        elif choice == '3':
            file_path = input("\nEnter video file path: ").strip()
            if os.path.exists(file_path):
                self.convert_single_file(file_path, target_resolution, target_width, target_height)
            else:
                print("File not found!")
                input("\nPress Enter to continue...")
                
    def run_conversion_scan(self, target_resolution, target_width, target_height, directory=None):
        """Run conversion scan for videos larger than target resolution."""
        if directory is None:
            directory = self.base_path
            
        # Create temporary conversion script
        temp_script = f"""import os
import subprocess
import sys

def get_video_resolution(file_path):
    cmd = [
        "ffprobe",
        "-v", "error",
        "-select_streams", "v:0",
        "-show_entries", "stream=width,height",
        "-of", "csv=s=x:p=0",
        file_path
    ]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode == 0:
        try:
            width, height = result.stdout.strip().split('x')
            return int(width), int(height)
        except ValueError:
            pass
    return None, None

def convert_video(file_path, output_file, target_width, target_height):
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
    print(f"Converting: {{os.path.basename(file_path)}}")
    subprocess.run(cmd)

directory = sys.argv[1]
target_resolution = {target_resolution}
target_width = {target_width}
target_height = {target_height}

print(f"Scanning for videos larger than {{target_resolution}}p...")
candidates = []

for root, _, files in os.walk(directory):
    for file in files:
        if "-CONVERTED" in file:
            continue
        file_path = os.path.join(root, file)
        if file.lower().endswith(('.mp4', '.mkv', '.avi', '.mov', '.flv')):
            width, height = get_video_resolution(file_path)
            if width and height and (width > target_width or height > target_height):
                file_size_gb = os.path.getsize(file_path) / (1024 ** 3)
                candidates.append({{
                    'path': file_path,
                    'width': width,
                    'height': height,
                    'size_gb': file_size_gb
                }})

if not candidates:
    print(f"\\nNo videos found larger than {{target_resolution}}p.")
    sys.exit(0)

print(f"\\nFound {{len(candidates)}} videos to convert:")
for i, video in enumerate(candidates[:10], 1):
    print(f"{{i}}. {{os.path.basename(video['path'])}}")
    print(f"   Resolution: {{video['width']}}x{{video['height']}}, Size: {{video['size_gb']:.2f}} GB")

if len(candidates) > 10:
    print(f"\\n... and {{len(candidates) - 10}} more")

response = input(f"\\nConvert these videos to {{target_resolution}}p? (y/N): ")
if response.lower() != 'y':
    print("Conversion cancelled.")
    sys.exit(0)

for i, video in enumerate(candidates, 1):
    print(f"\\n[{{i}}/{{len(candidates)}}] Processing {{video['path']}}")
    
    output_file = os.path.splitext(video['path'])[0] + "_temp.mp4"
    convert_video(video['path'], output_file, target_width, target_height)
    
    # Rename files
    converted_filename = f"{{os.path.splitext(video['path'])[0]}}-CONVERTED{{os.path.splitext(video['path'])[1]}}"
    os.rename(video['path'], converted_filename)
    os.rename(output_file, os.path.splitext(video['path'])[0] + ".mp4")
    print(f"✓ Conversion complete!")

print(f"\\n✓ All conversions complete! Converted {{len(candidates)}} videos to {{target_resolution}}p.")
"""
        
        with open("temp_convert.py", "w") as f:
            f.write(temp_script)
        
        subprocess.run(["./convert_env/bin/python", "temp_convert.py", directory])
        os.remove("temp_convert.py")
        
        input("\nPress Enter to continue...")
        
    def convert_single_file(self, file_path, target_resolution, target_width, target_height):
        """Convert a single video file."""
        print(f"\nConverting {os.path.basename(file_path)} to {target_resolution}p...")
        
        output_file = os.path.splitext(file_path)[0] + "_temp.mp4"
        
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
        
        subprocess.run(cmd)
        
        # Rename files
        converted_filename = f"{os.path.splitext(file_path)[0]}-CONVERTED{os.path.splitext(file_path)[1]}"
        os.rename(file_path, converted_filename)
        os.rename(output_file, os.path.splitext(file_path)[0] + ".mp4")
        
        print(f"✓ Conversion complete!")
        print(f"Original saved as: {os.path.basename(converted_filename)}")
        
        input("\nPress Enter to continue...")
        
    def download_subtitles(self):
        """Download English subtitles for videos."""
        print("\nSubtitle Download Options:")
        print("1. Download for all videos without subtitles")
        print("2. Download for specific directory")
        print("3. Download for single video")
        print("0. Cancel")
        
        choice = input("\nEnter your choice: ").strip()
        
        if choice == '0':
            return
            
        # Check if subliminal is installed
        try:
            import subliminal
        except ImportError:
            print("\nSubliminal is not installed. Installing now...")
            subprocess.run([sys.executable, "-m", "pip", "install", "subliminal"])
            try:
                import subliminal
            except ImportError:
                print("Failed to install subliminal. Please install manually:")
                print("pip install subliminal")
                input("\nPress Enter to continue...")
                return
        
        if choice == '1':
            self.download_subtitles_batch(self.base_path)
        elif choice == '2':
            directory = input("\nEnter directory path: ").strip()
            if os.path.exists(directory):
                self.download_subtitles_batch(directory)
            else:
                print("Directory not found!")
                input("\nPress Enter to continue...")
        elif choice == '3':
            file_path = input("\nEnter video file path: ").strip()
            if os.path.exists(file_path):
                self.download_subtitle_for_file(file_path)
            else:
                print("File not found!")
                input("\nPress Enter to continue...")
                
    def download_subtitles_batch(self, directory):
        """Download subtitles for all videos in directory that don't have them."""
        print(f"\nScanning {directory} for videos without English subtitles...")
        
        videos_needing_subs = []
        videos_checked = 0
        videos_with_subs = 0
        
        # First count total videos
        total_videos = sum(1 for root, dirs, files in os.walk(directory) 
                          for file in files if file.lower().endswith(self.video_extensions))
        
        print(f"Found {total_videos} video files to check...")
        
        for root, dirs, files in os.walk(directory):
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
            input("\nPress Enter to continue...")
            return
        
        print(f"\nScan Results:")
        print(f"  Videos with subtitles: {videos_with_subs}")
        print(f"  Videos needing subtitles: {len(videos_needing_subs)}")
        
        response = input("\nDownload subtitles for these videos? (y/N): ")
        
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
            with open("failed_subtitle_downloads.txt", "w") as f:
                f.write("Failed Subtitle Downloads\n")
                f.write("="*50 + "\n")
                for path in failed_downloads:
                    f.write(f"{path}\n")
            print(f"  Failed list saved to: failed_subtitle_downloads.txt")
        
        input("\nPress Enter to continue...")
        
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
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            
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
                
        except Exception as e:
            if not quiet:
                print(f"✗ Error: {e}")
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
            
            choice = input("Enter your choice: ").strip()
            
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
        
        for root, dirs, files in os.walk(self.base_path):
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
            input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(files_to_remove)} sample/trailer files:")
        total_size = sum(size for _, size in files_to_remove)
        
        for i, (path, size) in enumerate(files_to_remove[:20], 1):
            print(f"{i}. {os.path.basename(path)} ({size:.1f} MB)")
        
        if len(files_to_remove) > 20:
            print(f"... and {len(files_to_remove) - 20} more")
        
        print(f"\nTotal size: {total_size:.1f} MB")
        
        response = input("\nDelete these files? (y/N): ")
        if response.lower() == 'y':
            for path, _ in files_to_remove:
                try:
                    os.remove(path)
                except OSError as e:
                    print(f"Error deleting {path}: {e}")
            print(f"✓ Deleted {len(files_to_remove)} files")
        
        input("\nPress Enter to continue...")
        
    def clean_system_files(self):
        """Remove .DS_Store, thumbs.db, and other system files."""
        print("\nSearching for system files...")
        
        system_files = ['.DS_Store', 'Thumbs.db', 'desktop.ini', '._.DS_Store']
        files_removed = 0
        
        for root, dirs, files in os.walk(self.base_path):
            for file in files:
                if file in system_files or file.startswith('._'):
                    file_path = os.path.join(root, file)
                    try:
                        os.remove(file_path)
                        files_removed += 1
                        print(f"Removed: {file_path}")
                    except OSError:
                        pass
        
        print(f"\n✓ Removed {files_removed} system files")
        input("\nPress Enter to continue...")
        
    def clean_empty_folders(self):
        """Remove empty folders."""
        print("\nSearching for empty folders...")
        
        empty_folders = []
        
        for root, dirs, files in os.walk(self.base_path, topdown=False):
            if not dirs and not files and root != self.base_path:
                empty_folders.append(root)
        
        if not empty_folders:
            print("No empty folders found!")
            input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(empty_folders)} empty folders:")
        for folder in empty_folders[:20]:
            print(f"  {os.path.relpath(folder, self.base_path)}")
        
        if len(empty_folders) > 20:
            print(f"... and {len(empty_folders) - 20} more")
        
        response = input("\nDelete these folders? (y/N): ")
        if response.lower() == 'y':
            for folder in empty_folders:
                try:
                    os.rmdir(folder)
                except OSError as e:
                    print(f"Error removing {folder}: {e}")
            print(f"✓ Removed {len(empty_folders)} empty folders")
        
        input("\nPress Enter to continue...")
        
    def remove_converted_suffix(self):
        """Remove '-CONVERTED' suffix from filenames."""
        print("\nSearching for files with '-CONVERTED' suffix...")
        
        converted_files = []
        
        for root, dirs, files in os.walk(self.base_path):
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
            input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(converted_files)} files with '-CONVERTED' suffix:")
        for old, new in converted_files[:10]:
            print(f"  {os.path.basename(old)} → {os.path.basename(new)}")
        
        if len(converted_files) > 10:
            print(f"... and {len(converted_files) - 10} more")
        
        response = input("\nRemove '-CONVERTED' suffix from these files? (y/N): ")
        if response.lower() == 'y':
            for old_path, new_path in converted_files:
                try:
                    os.rename(old_path, new_path)
                except OSError as e:
                    print(f"Error renaming {old_path}: {e}")
            print(f"✓ Renamed {len(converted_files)} files")
        
        input("\nPress Enter to continue...")
        
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
        
        for root, dirs, files in os.walk(self.base_path):
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
            input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(issues_found)} files with naming issues:")
        for _, _, old, new in issues_found[:10]:
            print(f"  {old}")
            print(f"  → {new}")
        
        if len(issues_found) > 10:
            print(f"... and {len(issues_found) - 10} more")
        
        response = input("\nFix these naming issues? (y/N): ")
        if response.lower() == 'y':
            for old_path, new_path, _, _ in issues_found:
                try:
                    os.rename(old_path, new_path)
                except OSError as e:
                    print(f"Error renaming {old_path}: {e}")
            print(f"✓ Fixed {len(issues_found)} files")
        
        input("\nPress Enter to continue...")
        
    def remove_duplicate_subtitles(self):
        """Remove duplicate subtitle files."""
        print("\nSearching for duplicate subtitle files...")
        
        subtitle_extensions = ['.srt', '.vtt', '.ass', '.sub', '.ssa']
        duplicates = []
        
        for root, dirs, files in os.walk(self.base_path):
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
            input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(duplicates)} duplicate subtitle files:")
        for dup, keep in duplicates[:10]:
            print(f"  Remove: {os.path.basename(dup)}")
            print(f"  Keep:   {os.path.basename(keep)}")
            print()
        
        if len(duplicates) > 10:
            print(f"... and {len(duplicates) - 10} more")
        
        response = input("\nRemove duplicate subtitles? (y/N): ")
        if response.lower() == 'y':
            for dup, _ in duplicates:
                try:
                    os.remove(dup)
                except OSError as e:
                    print(f"Error removing {dup}: {e}")
            print(f"✓ Removed {len(duplicates)} duplicate subtitle files")
        
        input("\nPress Enter to continue...")
        
    def find_duplicates(self):
        """Find duplicate video files."""
        print("\nDuplicate Detection Options:")
        print("1. Find exact duplicates (same file size)")
        print("2. Find similar titles (possible duplicates)")
        print("3. Find duplicate episodes in TV shows")
        print("0. Cancel")
        
        choice = input("\nEnter your choice: ").strip()
        
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
        total_files = sum(1 for root, dirs, files in os.walk(self.base_path) 
                         for file in files if file.lower().endswith(self.video_extensions))
        
        print(f"Analyzing {total_files} video files...\n")
        
        for root, dirs, files in os.walk(self.base_path):
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
            input("\nPress Enter to continue...")
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
        with open("duplicate_files_report.txt", "w") as f:
            f.write(f"Duplicate Files Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n\n")
            
            for size, paths in duplicates:
                size_gb = size / (1024**3)
                f.write(f"Size: {size_gb:.2f} GB\n")
                for path in paths:
                    f.write(f"  {path}\n")
                f.write("\n")
        
        print(f"\nFull report saved to: duplicate_files_report.txt")
        input("\nPress Enter to continue...")
        
    def find_similar_titles(self):
        """Find videos with similar titles."""
        print("\nSearching for similar titles...")
        
        import difflib
        
        videos = []
        for root, dirs, files in os.walk(self.base_path):
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
            input("\nPress Enter to continue...")
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
        
        input("\nPress Enter to continue...")
        
    def find_duplicate_episodes(self):
        """Find duplicate TV episodes."""
        print("\nSearching for duplicate TV episodes...")
        
        tv_path = os.path.join(self.base_path, "TV")
        if not os.path.exists(tv_path):
            print("TV directory not found!")
            input("\nPress Enter to continue...")
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
            
            for root, dirs, files in os.walk(show_path):
                for file in files:
                    if file.lower().endswith(self.video_extensions):
                        # Try to extract season and episode
                        for pattern in episode_patterns:
                            match = re.search(pattern, file, re.IGNORECASE)
                            if match:
                                season = int(match.group(1))
                                episode = int(match.group(2))
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
            input("\nPress Enter to continue...")
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
        
        input("\nPress Enter to continue...")
        
    def library_health_check(self):
        """Perform a health check on the video library."""
        print("\nLibrary Health Check Options:")
        print("1. Check for corrupted/unplayable files")
        print("2. Find videos with unusual codecs")
        print("3. Check for missing episodes in TV series")
        print("4. Verify file integrity")
        print("5. Full health report")
        print("0. Cancel")
        
        choice = input("\nEnter your choice: ").strip()
        
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
        total_files = sum(1 for root, dirs, files in os.walk(self.base_path) 
                         for file in files if file.lower().endswith(self.video_extensions))
        
        print(f"Found {total_files} video files to check\n")
        
        corrupted_files = []
        checked = 0
        
        for root, dirs, files in os.walk(self.base_path):
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
                    
                    result = subprocess.run(cmd, capture_output=True, text=True)
                    if result.returncode != 0 or not result.stdout.strip():
                        corrupted_files.append(file_path)
        
        print(f"\nChecked {checked} files")
        
        if not corrupted_files:
            print("✓ No corrupted files found!")
        else:
            print(f"⚠️  Found {len(corrupted_files)} potentially corrupted files:")
            
            # Save to file
            with open("corrupted_files_report.txt", "w") as f:
                f.write(f"Corrupted Files Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write("="*80 + "\n\n")
                
                for path in corrupted_files:
                    f.write(f"{path}\n")
                    print(f"  {os.path.relpath(path, self.base_path)}")
            
            print(f"\nFull report saved to: corrupted_files_report.txt")
        
        input("\nPress Enter to continue...")
        
    def check_unusual_codecs(self):
        """Check for videos with unusual codecs that Plex might struggle with."""
        print("\nChecking for unusual video codecs...")
        
        # Count total files
        total_files = sum(1 for root, dirs, files in os.walk(self.base_path) 
                         for file in files if file.lower().endswith(self.video_extensions))
        
        print(f"Analyzing {total_files} video files for codec information...\n")
        
        unusual_codecs = []
        common_codecs = ['h264', 'hevc', 'h265', 'vp9', 'av1']
        files_checked = 0
        
        for root, dirs, files in os.walk(self.base_path):
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
        
        input("\nPress Enter to continue...")
        
    def check_missing_episodes(self):
        """Check for missing episodes in TV series."""
        print("\nChecking for missing episodes in TV series...")
        
        tv_path = os.path.join(self.base_path, "TV")
        if not os.path.exists(tv_path):
            print("TV directory not found!")
            input("\nPress Enter to continue...")
            return
        
        import re
        
        episode_pattern = r'[Ss](\d+)[Ee](\d+)'
        
        for show_dir in os.listdir(tv_path):
            show_path = os.path.join(tv_path, show_dir)
            if not os.path.isdir(show_path):
                continue
            
            episodes = set()
            
            for root, dirs, files in os.walk(show_path):
                for file in files:
                    if file.lower().endswith(self.video_extensions):
                        match = re.search(episode_pattern, file, re.IGNORECASE)
                        if match:
                            season = int(match.group(1))
                            episode = int(match.group(2))
                            episodes.add((season, episode))
            
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
        
        input("\nPress Enter to continue...")
        
    def verify_file_integrity(self):
        """Verify file integrity using file size and basic checks."""
        print("\nVerifying file integrity...")
        
        suspicious_files = []
        
        for root, dirs, files in os.walk(self.base_path):
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
        
        input("\nPress Enter to continue...")
        
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
        total_items = sum(1 for root, dirs, files in os.walk(self.base_path) for _ in files)
        items_processed = 0
        
        print(f"Analyzing {total_items} items...\n")
        
        # Count everything
        for root, dirs, files in os.walk(self.base_path):
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
                        
                        if size < 10 * 1024 * 1024:  # Less than 10MB
                            report['small_files'] += 1
                            
                    except OSError:
                        report['corrupted_files'] += 1
                        
                elif file in ['.DS_Store', 'Thumbs.db', 'desktop.ini'] or file.startswith('._'):
                    report['system_files'] += 1
        
        # Count empty folders
        for root, dirs, files in os.walk(self.base_path, topdown=False):
            if not dirs and not files and root != self.base_path:
                report['empty_folders'] += 1
        
        # Generate report
        report_filename = f"health_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
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
        input("\nPress Enter to continue...")
        
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
            
            choice = input("Enter your choice: ").strip()
            
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
                    for root, dirs, files in os.walk(show_path):
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
        
        input("\nPress Enter to continue...")
        
    def auto_rename_movies(self):
        """Auto-rename movies to Plex format: Movie Title (Year).ext"""
        print("\nAuto-rename movies to Plex format...")
        
        import re
        
        movies_path = os.path.join(self.base_path, "Movies")
        if not os.path.exists(movies_path):
            print("Movies directory not found!")
            input("\nPress Enter to continue...")
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
            input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(rename_candidates)} movies to rename:")
        for old_path, new_path, old_name, new_name in rename_candidates[:10]:
            print(f"  {old_name}")
            print(f"  → {new_name}")
            print()
        
        if len(rename_candidates) > 10:
            print(f"... and {len(rename_candidates) - 10} more")
        
        response = input("\nRename these movies? (y/N): ")
        if response.lower() == 'y':
            renamed = 0
            for old_path, new_path, _, _ in rename_candidates:
                try:
                    os.rename(old_path, new_path)
                    renamed += 1
                except OSError as e:
                    print(f"Error renaming {old_path}: {e}")
            print(f"✓ Renamed {renamed} movies")
        
        input("\nPress Enter to continue...")
        
    def auto_rename_tv_shows(self):
        """Auto-rename TV shows to Plex format: Show Name - S##E## - Episode Title.ext"""
        print("\nAuto-rename TV shows to Plex format...")
        
        import re
        
        tv_path = os.path.join(self.base_path, "TV")
        if not os.path.exists(tv_path):
            print("TV directory not found!")
            input("\nPress Enter to continue...")
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
                for root, dirs, files in os.walk(show_path):
                    for file in files:
                        if file.lower().endswith(self.video_extensions):
                            file_path = os.path.join(root, file)
                            
                            # Try to extract season and episode
                            new_name = None
                            for pattern, format_str in patterns:
                                match = re.search(pattern, file, re.IGNORECASE)
                                if match:
                                    season = int(match.group(1))
                                    episode = int(match.group(2))
                                    
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
            input("\nPress Enter to continue...")
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
        
        response = input("\nRename these episodes? (y/N): ")
        if response.lower() == 'y':
            renamed = 0
            for old_path, new_path, _, _, _ in rename_candidates:
                try:
                    os.rename(old_path, new_path)
                    renamed += 1
                except OSError as e:
                    print(f"Error renaming {old_path}: {e}")
            print(f"✓ Renamed {renamed} episodes")
        
        input("\nPress Enter to continue...")
        
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
            input("\nPress Enter to continue...")
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
        
        choice = input("\nEnter your choice: ").strip()
        
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
            input("\nPress Enter to continue...")
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
        
        input("\nPress Enter to continue...")
        
    def fix_season_structure(self):
        """Fix TV show season folder structure."""
        print("\nFixing TV show season structure...")
        
        tv_path = os.path.join(self.base_path, "TV")
        if not os.path.exists(tv_path):
            print("TV directory not found!")
            input("\nPress Enter to continue...")
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
                            season = int(match.group(1))
                            loose_episodes.append((item_path, season, item))
                
                if loose_episodes and not has_season_folders:
                    shows_to_fix.append((show_dir, loose_episodes))
        
        if not shows_to_fix:
            print("✓ All TV shows have proper season structure!")
            input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(shows_to_fix)} shows needing season folders:")
        for show, episodes in shows_to_fix:
            seasons = set(ep[1] for ep in episodes)
            print(f"  {show} - {len(episodes)} episodes across seasons {sorted(seasons)}")
        
        response = input("\nCreate season folders and organize episodes? (y/N): ")
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
        
        input("\nPress Enter to continue...")
        
    def organize_subtitles(self):
        """Move subtitle files to match their video files."""
        print("\nOrganizing subtitle files...")
        
        subtitle_extensions = ['.srt', '.vtt', '.ass', '.sub', '.ssa']
        orphaned_subs = []
        
        # Find subtitle files that might be in wrong locations
        for root, dirs, files in os.walk(self.base_path):
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
            input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(orphaned_subs)} orphaned subtitle files")
        
        # Try to match with video files
        matches = []
        for sub_path in orphaned_subs:
            sub_name = os.path.basename(sub_path)
            base_name = os.path.splitext(sub_name)[0]
            base_name = base_name.replace('.en', '').replace('.eng', '').replace('.english', '')
            
            # Search for matching video
            for root, dirs, files in os.walk(self.base_path):
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
            
            response = input("\nMove subtitle files to match videos? (y/N): ")
            if response.lower() == 'y':
                moved = 0
                for old_path, new_path, _ in matches:
                    try:
                        os.rename(old_path, new_path)
                        moved += 1
                    except OSError as e:
                        print(f"Error moving {old_path}: {e}")
                print(f"✓ Moved {moved} subtitle files")
        
        input("\nPress Enter to continue...")
        
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
            
            choice = input("Enter your choice: ").strip()
            
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
        
        # Get disk usage
        import shutil
        
        total, used, free = shutil.disk_usage(self.base_path)
        
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
        total_files = sum(1 for root, dirs, files in os.walk(self.base_path) 
                         for file in files if file.lower().endswith(self.video_extensions))
        
        print(f"Analyzing {total_files} video files...\n")
        files_processed = 0
        
        for root, dirs, files in os.walk(self.base_path):
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
        
        input("\nPress Enter to continue...")
        
    def growth_trends(self):
        """Analyze storage growth trends."""
        print("\nAnalyzing growth trends...")
        
        # Group files by month
        from collections import defaultdict
        monthly_data = defaultdict(lambda: {'count': 0, 'size': 0})
        
        current_time = datetime.now()
        
        for root, dirs, files in os.walk(self.base_path):
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
            input("\nPress Enter to continue...")
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
        
        input("\nPress Enter to continue...")
        
    def storage_prediction(self):
        """Predict when storage will run out."""
        print("\nCalculating storage predictions...")
        
        import shutil
        from collections import defaultdict
        
        # Get current disk usage
        total, used, free = shutil.disk_usage(self.base_path)
        
        # Analyze growth over last 6 months
        monthly_sizes = defaultdict(int)
        
        for root, dirs, files in os.walk(self.base_path):
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
        
        input("\nPress Enter to continue...")
        
    def largest_consumers(self):
        """Show largest space consumers."""
        print("\nFinding largest space consumers...")
        
        # Collect all videos with sizes
        all_videos = []
        show_sizes = defaultdict(int)
        
        for root, dirs, files in os.walk(self.base_path):
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
        large_files = [v for v in all_videos if v['size'] > 5 * (1024**3)]  # Over 5GB
        huge_files = [v for v in all_videos if v['size'] > 10 * (1024**3)]  # Over 10GB
        
        print(f"\nSize Statistics:")
        print(f"  Files over 5 GB:  {len(large_files)}")
        print(f"  Files over 10 GB: {len(huge_files)}")
        
        if huge_files:
            print(f"\n⚠️  Consider compressing these {len(huge_files)} files over 10 GB!")
        
        input("\nPress Enter to continue...")
        
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
        
        for root, dirs, files in os.walk(self.base_path):
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
        
        for root, dirs, files in os.walk(self.base_path):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    try:
                        stat = os.stat(file_path)
                        size = stat.st_size
                        mtime = datetime.fromtimestamp(stat.st_mtime)
                        
                        # Large files not accessed in over a year
                        if size > 3 * (1024**3) and (current_time - mtime).days > 365:
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
                        if 'sample' in file.lower() and size < 100 * (1024**2):
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
            response = input("\nSave detailed deletion report? (y/N): ")
            if response.lower() == 'y':
                with open("deletion_recommendations.txt", "w") as f:
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
        
        input("\nPress Enter to continue...")
        
    def export_analytics(self):
        """Export comprehensive analytics report."""
        print("\nGenerating comprehensive analytics report...")
        
        import json
        import shutil
        
        # Gather all data
        total, used, free = shutil.disk_usage(self.base_path)
        
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
        total_files = sum(1 for root, dirs, files in os.walk(self.base_path) 
                         for file in files if file.lower().endswith(self.video_extensions))
        
        print(f"Processing {total_files} video files for detailed analytics...\n")
        files_processed = 0
        
        for root, dirs, files in os.walk(self.base_path):
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
        
        # JSON report
        json_file = f"storage_analytics_{timestamp}.json"
        with open(json_file, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        # Human-readable report
        txt_file = f"storage_analytics_{timestamp}.txt"
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
        
        input("\nPress Enter to continue...")
        
    def run(self):
        """Main menu loop."""
        while True:
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
                choice = input("Enter your choice: ").strip()
                
                if choice == '1':
                    self.background_analysis()
                elif choice == '2':
                    self.inventory_videos()
                elif choice == '3':
                    self.list_conversion_candidates()
                elif choice == '4':
                    self.top_shows_by_size()
                elif choice == '5':
                    self.top_video_files()
                elif choice == '6':
                    self.library_health_check()
                elif choice == '7':
                    self.storage_analytics()
                elif choice == '8':
                    self.convert_to_resolution(1080)
                elif choice == '9':
                    self.convert_to_resolution(720)
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
                    input("\nPress Enter to continue...")
                    
            except KeyboardInterrupt:
                print("\n\nGoodbye!")
                break
            except Exception as e:
                print(f"\nError: {e}")
                input("\nPress Enter to continue...")
        
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
            
            choice = input("Enter your choice: ").strip()
            
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
        
        choice = input("\nEnter your choice: ").strip()
        
        if choice == '1':
            self.batch_convert_codec('hevc', 'h264')
        elif choice == '2':
            self.batch_convert_extension('.avi', '.mp4')
        elif choice == '3':
            self.batch_convert_extension('.mkv', '.mp4')
        elif choice == '4':
            self.batch_fix_audio_codecs()
        elif choice == '5':
            from_codec = input("From codec (e.g., hevc, h264): ").strip().lower()
            to_codec = input("To codec (e.g., h264, hevc): ").strip().lower()
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
        
        choice = input("\nEnter your choice: ").strip()
        
        if choice == '1':
            self.batch_delete_by_resolution(720)
        elif choice == '2':
            self.batch_delete_by_resolution(480)
        elif choice == '3':
            self.batch_convert_4k_to_1080p()
        elif choice == '4':
            min_mb = input("Delete files smaller than (MB): ").strip()
            try:
                self.batch_delete_by_size(int(min_mb))
            except ValueError:
                print("Invalid size!")
        elif choice == '5':
            max_gb = input("Convert files larger than (GB): ").strip()
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
        
        choice = input("\nEnter your choice: ").strip()
        
        if choice == '1':
            text_to_remove = input("Text to remove from filenames: ").strip()
            if text_to_remove:
                self.batch_remove_text(text_to_remove)
        elif choice == '2':
            from_ext = input("From extension (e.g., .avi): ").strip()
            to_ext = input("To extension (e.g., .mp4): ").strip()
            if from_ext and to_ext:
                self.batch_change_extensions(from_ext, to_ext)
        elif choice == '3':
            pattern = input("File pattern to match: ").strip()
            folder = input("Destination folder: ").strip()
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
        
        choice = input("\nEnter your choice: ").strip()
        
        if choice == '1':
            self.batch_extract_subtitles()
        elif choice == '2':
            self.batch_remove_subtitle_tracks()
        elif choice == '3':
            self.batch_convert_subtitle_formats()
        elif choice == '4':
            show_name = input("Show name (partial match): ").strip()
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
        
        choice = input("\nEnter your choice: ").strip()
        
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
        
        choice = input("\nEnter your choice: ").strip()
        
        if choice == '1':
            self.select_by_size_range()
        elif choice == '2':
            self.select_by_date_range()
        elif choice == '3':
            pattern = input("Regex pattern: ").strip()
            if pattern:
                self.select_by_regex(pattern)
        elif choice == '4':
            directory = input("Directory path: ").strip()
            if directory:
                self.select_by_directory(directory)
        elif choice == '5':
            codec = input("Codec name: ").strip()
            if codec:
                self.select_by_codec(codec)
    
    # Core batch operation implementations
    def batch_convert_codec(self, from_codec, to_codec):
        """Convert all videos from one codec to another."""
        print(f"\nFinding videos with {from_codec.upper()} codec...")
        
        matching_files = []
        total_files = sum(1 for root, dirs, files in os.walk(self.base_path) 
                         for file in files if file.lower().endswith(self.video_extensions))
        
        files_checked = 0
        
        for root, dirs, files in os.walk(self.base_path):
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
            input("\nPress Enter to continue...")
            return
        
        total_size = sum(f['size_gb'] for f in matching_files)
        
        print(f"\n\nFound {len(matching_files)} videos with {from_codec.upper()} codec:")
        print(f"Total size: {total_size:.2f} GB")
        
        for i, file_info in enumerate(matching_files[:10], 1):
            print(f"{i}. {file_info['name']} ({file_info['size_gb']:.2f} GB)")
        
        if len(matching_files) > 10:
            print(f"... and {len(matching_files) - 10} more")
        
        response = input(f"\nConvert these videos from {from_codec.upper()} to {to_codec.upper()}? (y/N): ")
        if response.lower() == 'y':
            self.execute_batch_conversion(matching_files, to_codec)
            
    def batch_convert_extension(self, from_ext, to_ext):
        """Convert all videos from one extension to another."""
        print(f"\nFinding videos with {from_ext} extension...")
        
        matching_files = []
        
        for root, dirs, files in os.walk(self.base_path):
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
            input("\nPress Enter to continue...")
            return
        
        total_size = sum(f['size_gb'] for f in matching_files)
        
        print(f"\nFound {len(matching_files)} {from_ext} files:")
        print(f"Total size: {total_size:.2f} GB")
        
        for i, file_info in enumerate(matching_files[:10], 1):
            print(f"{i}. {file_info['name']} ({file_info['size_gb']:.2f} GB)")
        
        if len(matching_files) > 10:
            print(f"... and {len(matching_files) - 10} more")
        
        response = input(f"\nConvert these files to {to_ext}? (y/N): ")
        if response.lower() == 'y':
            for i, file_info in enumerate(matching_files, 1):
                print(f"\n[{i}/{len(matching_files)}] Converting {file_info['name']}")
                
                input_path = file_info['path']
                output_path = os.path.splitext(input_path)[0] + to_ext
                
                cmd = [
                    "ffmpeg", "-i", input_path,
                    "-c:v", "libx264", "-c:a", "aac",
                    "-y", output_path
                ]
                
                result = subprocess.run(cmd, capture_output=True)
                if result.returncode == 0:
                    backup_path = f"{os.path.splitext(input_path)[0]}-ORIGINAL{from_ext}"
                    os.rename(input_path, backup_path)
                    print(f"✓ Converted, original saved as: {os.path.basename(backup_path)}")
                else:
                    print(f"✗ Conversion failed")
            
            print("\n✓ Batch conversion complete!")
        
        input("\nPress Enter to continue...")
        
    def batch_delete_by_resolution(self, min_height):
        """Delete all videos below specified resolution."""
        print(f"\nFinding videos below {min_height}p...")
        
        low_res_files = []
        total_files = sum(1 for root, dirs, files in os.walk(self.base_path) 
                         for file in files if file.lower().endswith(self.video_extensions))
        
        files_checked = 0
        
        for root, dirs, files in os.walk(self.base_path):
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
            input("\nPress Enter to continue...")
            return
        
        total_size = sum(f['size_gb'] for f in low_res_files)
        
        print(f"\n\nFound {len(low_res_files)} videos below {min_height}p:")
        print(f"Total size to be deleted: {total_size:.2f} GB")
        
        for i, file_info in enumerate(low_res_files[:15], 1):
            print(f"{i}. {file_info['name']} ({file_info['height']}p, {file_info['size_gb']:.2f} GB)")
        
        if len(low_res_files) > 15:
            print(f"... and {len(low_res_files) - 15} more")
        
        print(f"\n⚠️  WARNING: This will permanently delete {len(low_res_files)} files!")
        response = input("Are you sure? Type 'DELETE' to confirm: ")
        
        if response == 'DELETE':
            deleted = 0
            for file_info in low_res_files:
                try:
                    os.remove(file_info['path'])
                    deleted += 1
                    print(f"Deleted: {file_info['name']}")
                except OSError as e:
                    print(f"Error deleting {file_info['name']}: {e}")
            
            print(f"\n✓ Deleted {deleted} low-resolution videos")
            print(f"Freed up {total_size:.2f} GB of space")
        
        input("\nPress Enter to continue...")
        
    def batch_remove_text(self, text_to_remove):
        """Remove specific text from all filenames."""
        print(f"\nFinding files containing '{text_to_remove}'...")
        
        files_to_rename = []
        
        for root, dirs, files in os.walk(self.base_path):
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
            input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(files_to_rename)} files to rename:")
        
        for old_path, new_path, old_name, new_name in files_to_rename[:10]:
            print(f"  {old_name}")
            print(f"  → {new_name}")
        
        if len(files_to_rename) > 10:
            print(f"... and {len(files_to_rename) - 10} more")
        
        response = input("\nRename these files? (y/N): ")
        if response.lower() == 'y':
            renamed = 0
            for old_path, new_path, _, _ in files_to_rename:
                try:
                    os.rename(old_path, new_path)
                    renamed += 1
                except OSError as e:
                    print(f"Error renaming {old_path}: {e}")
            
            print(f"✓ Renamed {renamed} files")
        
        input("\nPress Enter to continue...")
        
    def batch_extract_subtitles(self):
        """Extract embedded subtitles to external .srt files."""
        print("\nFinding videos with embedded English subtitles...")
        
        videos_with_subs = []
        total_files = sum(1 for root, dirs, files in os.walk(self.base_path) 
                         for file in files if file.lower().endswith(self.video_extensions))
        
        files_checked = 0
        
        for root, dirs, files in os.walk(self.base_path):
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
            input("\nPress Enter to continue...")
            return
        
        print(f"\n\nFound {len(videos_with_subs)} videos with embedded subtitles")
        response = input("Extract subtitles to .srt files? (y/N): ")
        
        if response.lower() == 'y':
            extracted = 0
            for i, (file_path, stream_index, filename) in enumerate(videos_with_subs, 1):
                print(f"\n[{i}/{len(videos_with_subs)}] Extracting from: {filename}")
                
                output_srt = os.path.splitext(file_path)[0] + '.srt'
                cmd = [
                    "ffmpeg", "-i", file_path,
                    "-map", f"0:s:{stream_index}",
                    "-c:s", "srt",
                    "-y", output_srt
                ]
                
                result = subprocess.run(cmd, capture_output=True)
                if result.returncode == 0:
                    extracted += 1
                    print(f"     ✓ Extracted to {os.path.basename(output_srt)}")
                else:
                    print(f"     ✗ Failed to extract")
            
            print(f"\n✓ Extracted subtitles from {extracted} videos")
        
        input("\nPress Enter to continue...")
        
    def batch_delete_by_size(self, min_size_mb):
        """Delete videos smaller than specified size."""
        print(f"\nFinding videos smaller than {min_size_mb} MB...")
        
        small_files = []
        min_bytes = min_size_mb * 1024 * 1024
        
        for root, dirs, files in os.walk(self.base_path):
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
            input("\nPress Enter to continue...")
            return
        
        print(f"\nFound {len(small_files)} small videos:")
        for file_info in small_files:
            print(f"  {file_info['name']} ({file_info['size_mb']:.1f} MB)")
        
        print(f"\n⚠️  WARNING: This will permanently delete {len(small_files)} files!")
        response = input("Are you sure? Type 'DELETE' to confirm: ")
        
        if response == 'DELETE':
            for file_info in small_files:
                try:
                    os.remove(file_info['path'])
                    print(f"Deleted: {file_info['name']}")
                except OSError as e:
                    print(f"Error deleting {file_info['name']}: {e}")
            
            print(f"\n✓ Deleted {len(small_files)} small videos")
        
        input("\nPress Enter to continue...")
    
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
            
            use_cached = input("Use cached analysis? (Y/n): ").strip()
            if use_cached.lower() != 'n':
                self.display_analysis_results(cached)
                return
        
        print(f"\n💡 Analysis options:")
        print("1. Full analysis (scan all files)")
        print("2. Incremental analysis (only scan new/changed files)")
        print("3. View previous analysis reports")
        print("0. Cancel")
        
        choice = input("Select option: ").strip()
        
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
        
        # Initialize analysis results
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
            'storage_usage': {},
            'recommendations': []
        }
        
        # Progress tracking variables
        progress = {
            'file_scan': {'current': 0, 'total': 0, 'complete': False},
            'resolution_analysis': {'current': 0, 'total': 0, 'complete': False},
            'subtitle_check': {'current': 0, 'total': 0, 'complete': False},
            'naming_analysis': {'current': 0, 'total': 0, 'complete': False},
            'codec_analysis': {'current': 0, 'total': 0, 'complete': False}
        }
        
        def update_progress_display():
            """Update progress bars in real-time."""
            while not all(p['complete'] for p in progress.values()):
                print("\033[2J\033[H")  # Clear screen and go to top
                print("="*60)
                print("🔍 Background Analysis in Progress...")
                print("="*60)
                
                for task, data in progress.items():
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
                
                time.sleep(0.5)
        
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
        
        for root, dirs, files in os.walk(self.base_path):
            for file in files:
                if file.lower().endswith(self.video_extensions):
                    file_path = os.path.join(root, file)
                    all_video_files.append(file_path)
                    
                    # Check if file needs analysis
                    if not incremental_mode or self.is_file_changed(file_path):
                        files_to_analyze.append(file_path)
        
        progress['file_scan']['total'] = len(all_video_files)
        analysis_results['total_files'] = len(all_video_files)
        
        if incremental_mode:
            print(f"Found {len(files_to_analyze)} new/changed files out of {len(all_video_files)} total")
        else:
            files_to_analyze = all_video_files
        
        for i, file_path in enumerate(all_video_files):
            progress['file_scan']['current'] = i + 1
            analysis_results['files_scanned'] = i + 1
            time.sleep(0.001)
        
        progress['file_scan']['complete'] = True
        
        # Phase 2: Load cached data and analyze new/changed files
        progress['resolution_analysis']['total'] = len(files_to_analyze)
        progress['codec_analysis']['total'] = len(files_to_analyze)
        
        # Load existing data from database for unchanged files
        if incremental_mode:
            conn = self.get_db_connection()
            cursor = conn.cursor()
            
            # Get cached data for unchanged files
            unchanged_files = [f for f in all_video_files if f not in files_to_analyze]
            for file_path in unchanged_files:
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
                
                # Save to database
                self.save_video_metadata(file_data)
                
            except Exception as e:
                print(f"Error analyzing {file_path}: {e}")
                continue
            
            time.sleep(0.001)
        
        progress['resolution_analysis']['complete'] = True
        progress['codec_analysis']['complete'] = True
        progress['naming_analysis']['complete'] = True
        progress['subtitle_check']['complete'] = True
        
        # Wait for progress display to finish
        time.sleep(1)
        
        # Scan for system files
        for root, dirs, files in os.walk(self.base_path):
            for file in files:
                if file in ['.DS_Store', 'Thumbs.db', 'desktop.ini'] or file.startswith('._'):
                    analysis_results['system_files'].append(os.path.join(root, file))
        
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
        
        # Display results
        self.display_analysis_results({
            'session': {
                'timestamp': time.time(),
                'total_files': len(all_video_files),
                'files_analyzed': len(files_to_analyze),
                'duration_seconds': analysis_duration
            },
            'analysis_results': analysis_results
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
        
        input("\nPress Enter to continue...")
    
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
            cursor.execute('SELECT * FROM video_files WHERE file_size > ?', (10 * 1024**3,))
            for row in cursor.fetchall():
                results['large_files'].append({
                    'path': row['file_path'],
                    'size_gb': row['file_size'] / (1024**3),
                    'resolution': f"{row['width']}x{row['height']}"
                })
                
        finally:
            conn.close()
            
        # Scan for system files (not cached)
        for root, dirs, files in os.walk(self.base_path):
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
                input("\nPress Enter to continue...")
                return
            
            print("Recent analysis sessions:")
            for i, session in enumerate(sessions, 1):
                timestamp = datetime.fromtimestamp(session['timestamp'])
                print(f"{i:2}. {timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
                print(f"    Files: {session['files_analyzed']}/{session['total_files']}")
                print(f"    Duration: {session['duration_seconds']:.1f}s")
                if session['recommendations']:
                    rec_count = len(json.loads(session['recommendations']))
                    print(f"    Recommendations: {rec_count}")
                print()
            
            choice = input("Select session to view (or 0 to cancel): ").strip()
            
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
            result = subprocess.run(['rclone', 'version'], capture_output=True, text=True)
            if result.returncode == 0:
                return True
        except FileNotFoundError:
            return False
        return False
    
    def get_rclone_remotes(self):
        """Get list of configured rclone remotes."""
        try:
            result = subprocess.run(['rclone', 'listremotes'], capture_output=True, text=True)
            if result.returncode == 0:
                remotes = [line.strip().rstrip(':') for line in result.stdout.strip().split('\n') if line.strip()]
                return remotes
        except:
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
                print("  Linux: curl https://rclone.org/install.sh | sudo bash")
                print("  Manual: https://rclone.org/downloads/")
                input("\nPress Enter to continue...")
                return
            
            # Get configured remotes
            remotes = self.get_rclone_remotes()
            
            if not remotes:
                print("❌ No rclone remotes configured")
                print("\nTo configure a remote:")
                print("  Run: rclone config")
                print("  Follow prompts to add cloud storage (Google Drive, S3, etc.)")
                input("\nPress Enter to continue...")
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
            
            choice = input("Enter your choice: ").strip()
            
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
                             for dirpath, dirnames, filenames in os.walk(item_path)
                             for filename in filenames) / (1024**3)
                main_dirs.append({'name': item, 'size_gb': size_gb})
        
        print("Available directories:")
        for i, dir_info in enumerate(main_dirs, 1):
            print(f"{i:2}. {dir_info['name']} ({dir_info['size_gb']:.1f} GB)")
        
        print(f"\n{len(main_dirs)+1}. All directories")
        print("0. Cancel")
        
        dir_choice = input("\nSelect directory to sync: ").strip()
        
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
        
        remote_choice = input("Select remote: ").strip()
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
        
        sync_choice = input("Select sync type: ").strip()
        
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
        
        confirm = input(f"\nProceed with {sync_cmd}? (y/N): ")
        if confirm.lower() != 'y':
            return
        
        # Execute sync
        for dir_name in selected_dirs:
            source_path = os.path.join(self.base_path, dir_name)
            remote_path = f"{selected_remote}:Media/{dir_name}"
            
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
                subprocess.run(cmd)
                print(f"✅ {dir_name} {sync_cmd} completed!")
            except KeyboardInterrupt:
                print(f"\n⚠️  {sync_cmd} interrupted for {dir_name}")
                break
            except Exception as e:
                print(f"❌ Error during {sync_cmd}: {e}")
        
        input("\nPress Enter to continue...")
    
    def full_backup(self, remotes):
        """Backup entire media library to cloud."""
        self.clear_screen()
        print("="*50)
        print("💾 Full Media Library Backup")
        print("="*50)
        
        # Calculate total size
        total_size = 0
        for root, dirs, files in os.walk(self.base_path):
            for file in files:
                try:
                    total_size += os.path.getsize(os.path.join(root, file))
                except:
                    continue
        
        total_size_gb = total_size / (1024**3)
        
        print(f"📁 Source: {self.base_path}")
        print(f"📊 Total size: {total_size_gb:.1f} GB")
        print()
        
        # Select remote
        print("Available remotes:")
        for i, remote in enumerate(remotes, 1):
            print(f"{i}. {remote}")
        
        remote_choice = input("Select backup destination: ").strip()
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
        
        backup_choice = input("Select backup type: ").strip()
        
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
        
        confirm = input(f"\nStart backup? (y/N): ")
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
            subprocess.run(cmd)
            print(f"\n✅ Backup completed successfully!")
        except KeyboardInterrupt:
            print(f"\n⚠️  Backup interrupted by user")
        except Exception as e:
            print(f"\n❌ Backup failed: {e}")
        
        input("\nPress Enter to continue...")
    
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
        
        remote_choice = input("Select source remote: ").strip()
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
                
                dir_choice = input("Select directory to download (or 'all'): ").strip()
                
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
                
                confirm = input(f"\nStart download? (y/N): ")
                if confirm.lower() != 'y':
                    return
                
                # Execute download
                for dir_name in selected_dirs:
                    remote_path = f"{selected_remote}:{dir_name}"
                    local_path = os.path.join(self.base_path, dir_name)
                    
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
                        subprocess.run(cmd)
                        print(f"✅ {dir_name} downloaded!")
                    except KeyboardInterrupt:
                        print(f"\n⚠️  Download interrupted")
                        break
                    except Exception as e:
                        print(f"❌ Download failed: {e}")
                
            else:
                print(f"❌ Could not access {selected_remote}")
        except Exception as e:
            print(f"❌ Error accessing remote: {e}")
        
        input("\nPress Enter to continue...")
    
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
        
        remote_choice = input("Select remote to check: ").strip()
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
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.returncode == 0:
                print("✅ Local and remote are in sync!")
            else:
                print("📊 Sync differences found:")
                if result.stdout:
                    print(result.stdout)
                if result.stderr:
                    print(result.stderr)
                    
        except Exception as e:
            print(f"❌ Error checking sync status: {e}")
        
        input("\nPress Enter to continue...")
    
    def configure_bandwidth(self):
        """Configure bandwidth limits for rclone operations."""
        self.clear_screen()
        print("="*50)
        print("⚡ Configure Bandwidth Limits")
        print("="*50)
        
        print("Current rclone configuration file location:")
        try:
            result = subprocess.run(['rclone', 'config', 'file'], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"📁 {result.stdout.strip()}")
        except:
            print("❌ Could not locate config file")
        
        print("\nBandwidth limit options:")
        print("1. No limit (default)")
        print("2. 10 Mbps (good for background sync)")
        print("3. 50 Mbps (moderate usage)")
        print("4. 100 Mbps (high speed)")
        print("5. Custom limit")
        
        choice = input("Select bandwidth limit: ").strip()
        
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
            custom_limit = input("Enter custom limit (e.g., '25M', '1G'): ").strip()
            print(f"✅ Custom bandwidth limit: {custom_limit}")
            print(f"💡 Add --bwlimit {custom_limit} to rclone commands")
        
        input("\nPress Enter to continue...")
    
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
        
        remote_choice = input("Select remote to verify: ").strip()
        try:
            selected_remote = remotes[int(remote_choice) - 1]
        except (ValueError, IndexError):
            print("Invalid selection.")
            input("Press Enter to continue...")
            return
        
        remote_path = f"{selected_remote}:MediaBackup"
        
        print(f"\n🔍 Verifying integrity between local and {remote_path}...")
        print("This will compare checksums of all files (may take a while)")
        
        confirm = input("Start verification? (y/N): ")
        if confirm.lower() != 'y':
            return
        
        cmd = [
            'rclone', 'check',
            self.base_path, remote_path,
            '--checkfile', f"integrity_check_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        ]
        
        print(f"\n🚀 Starting integrity check...")
        
        try:
            result = subprocess.run(cmd)
            if result.returncode == 0:
                print("✅ All files verified successfully!")
            else:
                print("⚠️  Some files have differences - check the log file")
        except KeyboardInterrupt:
            print("\n⚠️  Verification interrupted")
        except Exception as e:
            print(f"❌ Verification failed: {e}")
        
        input("\nPress Enter to continue...")
    
    def view_rclone_config(self):
        """View rclone configuration details."""
        self.clear_screen()
        print("="*50)
        print("⚙️  rclone Configuration")
        print("="*50)
        
        try:
            # Show config file location
            result = subprocess.run(['rclone', 'config', 'file'], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"📁 Config file: {result.stdout.strip()}")
        except:
            pass
        
        # Show remotes with details
        try:
            result = subprocess.run(['rclone', 'config', 'show'], capture_output=True, text=True)
            if result.returncode == 0:
                print(f"\n📡 Configured remotes:")
                print(result.stdout)
            else:
                print("❌ Could not show configuration")
        except Exception as e:
            print(f"❌ Error reading config: {e}")
        
        print("\n💡 Useful rclone commands:")
        print("   rclone config          - Configure new remote")
        print("   rclone listremotes     - List all remotes")
        print("   rclone about remote:   - Show storage info")
        print("   rclone ls remote:      - List files on remote")
        
        input("\nPress Enter to continue...")

if __name__ == "__main__":
    manager = MediaManager()
    manager.run()