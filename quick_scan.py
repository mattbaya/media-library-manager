#!/usr/bin/env python3
import os

def quick_scan(base_path):
    """Quick scan of immediate directories for common issues."""
    print(f"Quick scanning: {base_path}")
    
    system_files = 0
    sample_files = 0
    converted_files = 0
    
    # Check just the main directories
    main_dirs = ['Movies', 'TV', 'Kids Movies', 'Christmas', 'Music Videos', 'Personal', 'HalloweenFX', 'Misc']
    
    for main_dir in main_dirs:
        dir_path = os.path.join(base_path, main_dir)
        if os.path.exists(dir_path):
            print(f"\nScanning {main_dir}/...")
            
            # Count items in this directory only (not recursive)
            try:
                items = os.listdir(dir_path)
                
                for item in items:
                    if item in ['.DS_Store', 'Thumbs.db', 'desktop.ini']:
                        system_files += 1
                    elif 'sample' in item.lower() or 'trailer' in item.lower():
                        sample_files += 1
                    elif '-CONVERTED' in item:
                        converted_files += 1
                        
                print(f"  Items: {len(items)}")
                        
            except PermissionError:
                print(f"  Permission denied")
    
    # Check root directory
    try:
        root_items = os.listdir(base_path)
        for item in root_items:
            if item in ['.DS_Store', 'Thumbs.db', 'desktop.ini']:
                system_files += 1
    except PermissionError:
        pass
    
    print(f"\n" + "="*50)
    print("Quick Scan Results:")
    print(f"System files found: {system_files}")
    print(f"Sample/trailer files: {sample_files}")
    print(f"Files with '-CONVERTED': {converted_files}")
    
    return system_files, sample_files, converted_files

if __name__ == "__main__":
    import sys
    
    # Default path
    default_path = "/Volumes/media/Video"
    
    # Accept command line argument or use default
    if len(sys.argv) > 1:
        base_path = sys.argv[1]
        
        # Validate the provided path
        if not os.path.exists(base_path):
            print(f"Error: Directory {base_path} does not exist")
            sys.exit(1)
        
        if not os.path.isdir(base_path):
            print(f"Error: {base_path} is not a directory")
            sys.exit(1)
        
        # Basic security check - prevent scanning root or system directories
        dangerous_paths = ['/', '/etc', '/usr', '/bin', '/sbin', '/System', '/Library']
        real_path = os.path.realpath(base_path)
        if any(real_path.startswith(danger) for danger in dangerous_paths):
            print(f"Error: Cannot scan system directory {real_path}")
            sys.exit(1)
            
    else:
        base_path = default_path
    
    print(f"Scanning directory: {base_path}")
    quick_scan(base_path)