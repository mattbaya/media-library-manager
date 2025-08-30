#!/usr/bin/env python3
import os
import sys

def cleanup_directory(directory):
    """Clean up a specific directory."""
    print(f"Cleaning: {os.path.basename(directory)}")
    
    system_files_removed = 0
    converted_files = []
    
    try:
        items = os.listdir(directory)
        
        for item in items:
            item_path = os.path.join(directory, item)
            
            # Remove system files
            if item in ['.DS_Store', 'Thumbs.db', 'desktop.ini'] or item.startswith('._'):
                try:
                    os.remove(item_path)
                    print(f"  Removed system file: {item}")
                    system_files_removed += 1
                except OSError as e:
                    print(f"  Error removing {item}: {e}")
            
            # Find converted files
            elif '-CONVERTED' in item:
                converted_files.append(item_path)
        
        return system_files_removed, converted_files
        
    except PermissionError:
        print(f"  Permission denied for {directory}")
        return 0, []

def main():
    base_path = "/Volumes/media/Video"
    
    print("="*60)
    print("🔧 Targeted Cleanup")
    print("="*60)
    
    # Clean main directories
    main_dirs = ['Movies', 'TV', 'Kids Movies', 'Christmas', 'Music Videos', 'Personal', 'HalloweenFX', 'Misc']
    
    total_system_files = 0
    all_converted_files = []
    
    # Clean root directory first
    print(f"Cleaning root directory...")
    root_items = os.listdir(base_path)
    for item in root_items:
        if item in ['.DS_Store', 'Thumbs.db', 'desktop.ini']:
            try:
                os.remove(os.path.join(base_path, item))
                print(f"  Removed: {item}")
                total_system_files += 1
            except OSError:
                pass
    
    # Process each main directory
    for main_dir in main_dirs:
        dir_path = os.path.join(base_path, main_dir)
        if os.path.exists(dir_path):
            system_removed, converted = cleanup_directory(dir_path)
            total_system_files += system_removed
            all_converted_files.extend(converted)
    
    print("\n" + "="*60)
    print("Cleanup Summary:")
    print(f"System files removed: {total_system_files}")
    print(f"Files with '-CONVERTED' found: {len(all_converted_files)}")
    
    if all_converted_files:
        print("\nFiles with '-CONVERTED' suffix:")
        for file in all_converted_files:
            print(f"  {os.path.relpath(file, base_path)}")
        
        print("\nTo rename these, use the media manager option 11 → 4")
    
    print("\n✓ Targeted cleanup complete!")

if __name__ == "__main__":
    main()