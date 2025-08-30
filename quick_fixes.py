#!/usr/bin/env python3
import os
import sys
from pathlib import Path

def remove_system_files(base_path):
    """Remove .DS_Store, thumbs.db, and other system files."""
    print("Searching for system files...")
    
    system_files = ['.DS_Store', 'Thumbs.db', 'desktop.ini', '._.DS_Store']
    files_removed = 0
    
    for root, dirs, files in os.walk(base_path):
        for file in files:
            if file in system_files or file.startswith('._'):
                file_path = os.path.join(root, file)
                try:
                    os.remove(file_path)
                    files_removed += 1
                    print(f"Removed: {os.path.relpath(file_path, base_path)}")
                except OSError as e:
                    print(f"Error removing {file_path}: {e}")
    
    print(f"\n✓ Removed {files_removed} system files")
    return files_removed

def clean_empty_folders(base_path):
    """Remove empty folders."""
    print("\nSearching for empty folders...")
    
    empty_folders = []
    
    for root, dirs, files in os.walk(base_path, topdown=False):
        if not dirs and not files and root != base_path:
            empty_folders.append(root)
    
    if not empty_folders:
        print("No empty folders found!")
        return 0
    
    print(f"Found {len(empty_folders)} empty folders:")
    for folder in empty_folders:
        print(f"  {os.path.relpath(folder, base_path)}")
    
    removed = 0
    for folder in empty_folders:
        try:
            os.rmdir(folder)
            removed += 1
        except OSError as e:
            print(f"Error removing {folder}: {e}")
    
    print(f"\n✓ Removed {removed} empty folders")
    return removed

def remove_sample_files(base_path):
    """Remove sample and trailer files."""
    print("\nSearching for sample/trailer files...")
    
    video_extensions = ('.mp4', '.mkv', '.avi', '.mov', '.flv', '.m4v', '.wmv')
    sample_patterns = ['sample', 'trailer', 'preview']
    files_to_remove = []
    
    for root, dirs, files in os.walk(base_path):
        for file in files:
            if file.lower().endswith(video_extensions):
                # Check filename
                if any(pattern in file.lower() for pattern in sample_patterns):
                    file_path = os.path.join(root, file)
                    try:
                        size_mb = os.path.getsize(file_path) / (1024**2)
                        
                        # Only flag small files as samples (under 100MB)
                        if size_mb < 100:
                            files_to_remove.append((file_path, size_mb))
                    except OSError:
                        continue
    
    if not files_to_remove:
        print("No sample/trailer files found!")
        return 0
    
    print(f"Found {len(files_to_remove)} sample/trailer files:")
    total_size = sum(size for _, size in files_to_remove)
    
    for path, size in files_to_remove:
        print(f"  {os.path.relpath(path, base_path)} ({size:.1f} MB)")
    
    print(f"\nTotal size: {total_size:.1f} MB")
    
    removed = 0
    for path, _ in files_to_remove:
        try:
            os.remove(path)
            removed += 1
        except OSError as e:
            print(f"Error deleting {path}: {e}")
    
    print(f"\n✓ Deleted {removed} files")
    return removed

def fix_naming_issues(base_path):
    """Fix common naming issues."""
    print("\nChecking for common naming issues...")
    
    video_extensions = ('.mp4', '.mkv', '.avi', '.mov', '.flv', '.m4v', '.wmv')
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
    
    for root, dirs, files in os.walk(base_path):
        for file in files:
            if file.lower().endswith(video_extensions):
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
        return 0
    
    print(f"Found {len(issues_found)} files with naming issues:")
    for old_path, new_path, old_name, new_name in issues_found:
        print(f"  {old_name}")
        print(f"  → {new_name}")
    
    fixed = 0
    for old_path, new_path, _, _ in issues_found:
        try:
            os.rename(old_path, new_path)
            fixed += 1
        except OSError as e:
            print(f"Error renaming {old_path}: {e}")
    
    print(f"\n✓ Fixed {fixed} files")
    return fixed

if __name__ == "__main__":
    base_path = "/Volumes/media/Video"
    
    print("="*60)
    print("🔧 Running Quick Fixes")
    print("="*60)
    
    # Run all quick fixes
    system_files_removed = remove_system_files(base_path)
    empty_folders_removed = clean_empty_folders(base_path)
    sample_files_removed = remove_sample_files(base_path)
    naming_issues_fixed = fix_naming_issues(base_path)
    
    print("\n" + "="*60)
    print("📊 Quick Fixes Summary")
    print("="*60)
    print(f"System files removed: {system_files_removed}")
    print(f"Empty folders removed: {empty_folders_removed}")
    print(f"Sample files removed: {sample_files_removed}")
    print(f"Naming issues fixed: {naming_issues_fixed}")
    print("\n✓ Quick fixes complete!")