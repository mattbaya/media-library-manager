import os
import subprocess
import sys

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

def validate_safe_directory(directory):
    """Validate directory is safe to process."""
    
    # Get absolute path and resolve symlinks
    abs_dir = os.path.abspath(os.path.realpath(directory))
    
    # Forbidden system directories
    forbidden = [
        '/', '/etc', '/usr', '/bin', '/sbin', '/var', '/sys', '/proc',
        '/System', '/Library', '/Applications', '/Users', '/home', '/root'
    ]
    
    # Check if path starts with any forbidden directory
    for forbidden_path in forbidden:
        if abs_dir.startswith(forbidden_path):
            return False, f"Error: Cannot process system directory {abs_dir}"
    
    # Ensure directory exists and is readable
    if not os.path.exists(abs_dir):
        return False, f"Error: Directory {abs_dir} does not exist"
        
    if not os.path.isdir(abs_dir):
        return False, f"Error: {abs_dir} is not a directory"
    
    if not os.access(abs_dir, os.R_OK):
        return False, f"Error: No read permission for {abs_dir}"
    
    return True, f"Directory {abs_dir} is safe to process"

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
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, capture_output=True)
    if result.returncode == 0:
        try:
            width, height = result.stdout.strip().split('x')
            return int(width), int(height)
        except ValueError:
            print(f"Error reading resolution for {file_path}")
    return None, None

def scan_directory(directory):
    """Scan directory for videos larger than 1080p."""
    videos_to_convert = []
    
    for root, _, files in os.walk(directory):
        for file in files:
            # Skip already converted files
            if "-CONVERTED" in file:
                continue
                
            file_path = os.path.join(root, file)
            if file.lower().endswith(('.mp4', '.mkv', '.avi', '.mov', '.flv')):
                width, height = get_video_resolution(file_path)
                if width and height and (width > 1920 or height > 1080):
                    file_size_gb = os.path.getsize(file_path) / (1024 ** 3)
                    videos_to_convert.append({
                        'path': file_path,
                        'width': width,
                        'height': height,
                        'size_gb': file_size_gb
                    })
    
    return videos_to_convert

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
        "-y",  # Overwrite output files
        abs_output
    ]
    print(f"\nConverting: {os.path.basename(file_path)}")
    print(f"Command: {' '.join(cmd)}")
    result = subprocess.run(cmd, capture_output=True)
    return result.returncode == 0

if __name__ == "__main__":
    directory = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    
    # Critical security validation
    is_safe, message = validate_safe_directory(directory)
    if not is_safe:
        print(message)
        print("For security reasons, this script only processes media directories.")
        sys.exit(1)
    
    print(f"✅ {message}")
    print(f"Scanning directory: {directory}")
    
    # Additional confirmation for destructive operations
    try:
        confirm = input(f"\nThis script will scan and convert videos in {directory}. Continue? (y/N): ").strip().lower()
        if confirm != 'y':
            print("❌ Operation cancelled by user")
            sys.exit(0)
    except (EOFError, KeyboardInterrupt):
        print("\n❌ Operation cancelled")
        sys.exit(0)
    
    videos = scan_directory(directory)
    
    if not videos:
        print("\nNo videos found that need conversion (larger than 1080p).")
        sys.exit(0)
    
    print(f"\nFound {len(videos)} videos larger than 1080p:")
    print("-" * 80)
    
    total_size = 0
    for i, video in enumerate(videos, 1):
        print(f"{i}. {video['path']}")
        print(f"   Resolution: {video['width']}x{video['height']}, Size: {video['size_gb']:.2f} GB")
        total_size += video['size_gb']
    
    print(f"\nTotal size of videos to convert: {total_size:.2f} GB")
    
    response = input("\nDo you want to convert these videos? (y/N): ")
    if response.lower() != 'y':
        print("Conversion cancelled.")
        sys.exit(0)
    
    successful_conversions = 0
    for i, video in enumerate(videos, 1):
        print(f"\n[{i}/{len(videos)}] Processing {video['path']}")
        
        # Generate temporary output filename
        output_file = os.path.splitext(video['path'])[0] + "_temp.mp4"
        
        # Convert the video with error handling
        if convert_to_1080p(video['path'], output_file):
            # Rename original file
            converted_filename = f"{os.path.splitext(video['path'])[0]}-CONVERTED{os.path.splitext(video['path'])[1]}"
            try:
                os.rename(video['path'], converted_filename)
                print(f"Original file renamed to: {os.path.basename(converted_filename)}")
                
                # Rename temp file to original name
                os.rename(output_file, os.path.splitext(video['path'])[0] + ".mp4")
                print(f"✅ Conversion complete!")
                successful_conversions += 1
            except OSError as e:
                print(f"❌ Error renaming files: {e}")
                # Clean up temp file if rename failed
                try:
                    os.remove(output_file)
                except OSError:
                    pass
        else:
            print(f"❌ Conversion failed for {video['path']}")
            # Clean up temp file
            try:
                os.remove(output_file)
            except OSError:
                pass
    
    print(f"\n✓ Conversions complete! Successfully converted {successful_conversions}/{len(videos)} videos.")