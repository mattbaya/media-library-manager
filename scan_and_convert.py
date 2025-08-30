import os
import subprocess
import sys

def get_video_resolution(file_path):
    """Use ffprobe to get the video resolution."""
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
    """Convert the given video file to 1080p using FFmpeg."""
    cmd = [
        "ffmpeg",
        "-i", file_path,
        "-vf", "scale=1920:1080",
        "-c:v", "libx264",
        "-crf", "23",
        "-preset", "medium",
        "-c:a", "aac",
        "-b:a", "128k",
        "-y",  # Overwrite output files
        output_file
    ]
    print(f"\nConverting: {os.path.basename(file_path)}")
    print(f"Command: {' '.join(cmd)}")
    subprocess.run(cmd)

if __name__ == "__main__":
    directory = sys.argv[1] if len(sys.argv) > 1 else os.getcwd()
    
    print(f"Scanning directory: {directory}")
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
    
    for i, video in enumerate(videos, 1):
        print(f"\n[{i}/{len(videos)}] Processing {video['path']}")
        
        # Generate temporary output filename
        output_file = os.path.splitext(video['path'])[0] + "_temp.mp4"
        
        # Convert the video
        convert_to_1080p(video['path'], output_file)
        
        # Rename original file
        converted_filename = f"{os.path.splitext(video['path'])[0]}-CONVERTED{os.path.splitext(video['path'])[1]}"
        os.rename(video['path'], converted_filename)
        print(f"Original file renamed to: {converted_filename}")
        
        # Rename temp file to original name
        os.rename(output_file, os.path.splitext(video['path'])[0] + ".mp4")
        print(f"Conversion complete!")
    
    print(f"\n✓ All conversions complete! Converted {len(videos)} videos.")