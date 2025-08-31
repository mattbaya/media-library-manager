import os
import subprocess

def validate_video_file_path(file_path):
    """Validate file path is safe for FFmpeg operations."""
    
    # Must be a real file, not symlink
    if not os.path.isfile(file_path) or os.path.islink(file_path):
        return False, "File does not exist or is a symbolic link"
    
    # Get absolute path
    abs_path = os.path.abspath(file_path)
    
    # Check for dangerous patterns in filename
    dangerous_patterns = [
        'http:', 'https:', 'ftp:', 'pipe:', 'concat:', 'tcp:', 'udp:',
        '|', '&', ';', '`', '$', '<', '>'
    ]
    
    filename = os.path.basename(abs_path)
    for pattern in dangerous_patterns:
        if pattern in filename:
            return False, f"Unsafe filename pattern: {pattern}"
    
    # Must have valid video extension
    valid_extensions = ('.mp4', '.mkv', '.avi', '.mov', '.flv', '.m4v', '.wmv')
    if not filename.lower().endswith(valid_extensions):
        return False, "Not a valid video file"
    
    return True, "File is safe"

def get_video_resolution(file_path):
    """Use ffprobe to get the video resolution with path validation."""
    
    # Validate file path before FFmpeg operations
    is_safe, message = validate_video_file_path(file_path)
    if not is_safe:
        print(f"Skipping unsafe file {file_path}: {message}")
        return None, None
    
    # Use absolute path to prevent interpretation as option
    abs_path = os.path.abspath(file_path)
    
    cmd = [
        "ffprobe",
        "-v", "error",
        "-select_streams", "v:0",
        "-show_entries", "stream=width,height",
        "-of", "csv=s=x:p=0",
        abs_path
    ]
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if result.returncode == 0:
        try:
            width, height = result.stdout.strip().split('x')
            return int(width), int(height)
        except ValueError:
            print(f"Error reading resolution for {file_path}")
    return None, None

def convert_to_1080p(file_path, output_file):
    """Convert the given video file to 1080p using FFmpeg with path validation."""
    
    # Validate input file path
    is_safe, message = validate_video_file_path(file_path)
    if not is_safe:
        print(f"Cannot convert unsafe file {file_path}: {message}")
        return False
    
    # Validate output file path
    output_dir = os.path.dirname(output_file)
    if not os.path.exists(output_dir):
        print(f"Output directory does not exist: {output_dir}")
        return False
    
    # Use absolute paths to prevent interpretation as options
    abs_input = os.path.abspath(file_path)
    abs_output = os.path.abspath(output_file)
    
    cmd = [
        "ffmpeg",
        "-i", abs_input,
        "-vf", "scale=1920:1080",
        "-c:v", "libx264",
        "-crf", "23",
        "-preset", "medium",
        "-c:a", "aac",
        "-b:a", "128k",
        abs_output
    ]
    print(f"Running FFmpeg command: {' '.join(cmd)}")
    subprocess.run(cmd)

def process_directory(directory):
    """Crawl all folders in a directory and process video files."""
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if file.lower().endswith(('.mp4', '.mkv', '.avi', '.mov', '.flv')):
                print(f"Checking {file_path}...")
                
                # Get resolution
                width, height = get_video_resolution(file_path)
                if width and height:
                    print(f"Resolution of {file_path}: {width}x{height}")
                else:
                    print(f"Could not determine resolution for {file_path}")

                # Get file size in GB
                file_size_gb = os.path.getsize(file_path) / (1024 ** 3)  # Convert bytes to GB
                print(f"File size of {file_path}: {file_size_gb:.2f} GB")

                # Determine if conversion is needed
                needs_conversion = (
                    (width and height and (width > 1920 or height > 1080)) or
                    file_size_gb > 2
                )

                if needs_conversion:
                    output_file = os.path.splitext(file_path)[0] + ".mp4"
                    
                    # Require explicit user consent before destructive operations
                    print(f"\n🚨 CONVERSION REQUIRED:")
                    print(f"   File: {os.path.basename(file_path)}")
                    print(f"   Current: {width}x{height} ({file_size_gb:.2f} GB)")
                    print(f"   Target: 1920x1080 (reduced size)")
                    print(f"   This will create a new file and rename the original.")
                    
                    try:
                        response = input(f"\nConvert this file? (y/N): ").strip().lower()
                        if response != 'y':
                            print("❌ Conversion skipped by user")
                            continue
                    except (EOFError, KeyboardInterrupt):
                        print("\n❌ Conversion cancelled by user")
                        break
                    
                    print(f"✅ User confirmed - Converting {file_path} to 1080p...")
                    convert_to_1080p(file_path, output_file)

                    # Rename original file with user consent already obtained
                    converted_filename = f"{os.path.splitext(file_path)[0]}-CONVERTED{os.path.splitext(file_path)[1]}"
                    os.rename(file_path, converted_filename)
                    print(f"✅ Original file renamed to {os.path.basename(converted_filename)}")
                else:
                    print(f"No conversion needed for {file_path}")

def validate_safe_directory(directory):
    """Validate directory is safe to process media files."""
    
    # Get absolute path and resolve symlinks
    abs_dir = os.path.abspath(os.path.realpath(directory))
    
    # Critical system paths that should NEVER be processed
    critical_forbidden = [
        '/', '/etc', '/usr/bin', '/usr/sbin', '/bin', '/sbin', 
        '/sys', '/proc', '/boot', '/dev', '/var/log', '/var/lib'
    ]
    
    # Check critical paths (exact match or subdirectory)
    for forbidden_path in critical_forbidden:
        if abs_dir == forbidden_path or abs_dir.startswith(forbidden_path + '/'):
            return False, f"Cannot process critical system directory: {abs_dir}"
    
    # Ensure directory exists and is readable
    if not os.path.exists(abs_dir):
        return False, f"Directory {abs_dir} does not exist"
        
    if not os.path.isdir(abs_dir):
        return False, f"{abs_dir} is not a directory"
    
    if not os.access(abs_dir, os.R_OK):
        return False, f"No read permission for {abs_dir}"
    
    # Allow common legitimate media locations
    import fnmatch
    allowed_patterns = [
        '/Users/*/Movies*', '/Users/*/Videos*', '/Users/*/Desktop*', '/Users/*/Documents*',
        '/Volumes/*/Movies*', '/Volumes/*/Videos*', '/Volumes/*/media*', '/Volumes/*/Media*',
        '/home/*/Videos*', '/home/*/Movies*', '/home/*/media*',
        '/tmp/video*', '/tmp/media*', '/tmp/test*', '/tmp/*'
    ]
    
    # Check if path matches allowed patterns
    for pattern in allowed_patterns:
        if fnmatch.fnmatch(abs_dir, pattern):
            return True, f"Allowed media directory: {abs_dir}"
    
    # For other paths, require explicit confirmation
    print(f"\n⚠️  Warning: {abs_dir} is not a recognized media directory")
    print("This could be a security risk if the path contains system files.")
    
    try:
        response = input("Process this directory anyway? (y/N): ").strip().lower()
        if response == 'y':
            return True, f"User confirmed directory: {abs_dir}"
        else:
            return False, "User rejected directory processing"
    except (EOFError, KeyboardInterrupt):
        return False, "User cancelled directory processing"

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) > 1:
        directory = sys.argv[1]
    else:
        directory = os.getcwd()
    
    # Critical security validation
    is_safe, message = validate_safe_directory(directory)
    if not is_safe:
        print(message)
        print("For security reasons, this script only processes media directories.")
        sys.exit(1)
    
    print(f"✅ {message}")
    print(f"Processing directory: {directory}")
    
    # Additional confirmation for destructive operations
    try:
        confirm = input(f"\nThis script will convert videos in {directory}. Continue? (y/N): ").strip().lower()
        if confirm != 'y':
            print("❌ Operation cancelled by user")
            sys.exit(0)
    except (EOFError, KeyboardInterrupt):
        print("\n❌ Operation cancelled")
        sys.exit(0)
    
    process_directory(directory)
