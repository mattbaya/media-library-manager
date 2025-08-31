import os
import subprocess

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
        output_file
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

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        directory = sys.argv[1]
    else:
        directory = os.getcwd()
    print(f"Processing directory: {directory}")
    process_directory(directory)
