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
        width, height = result.stdout.strip().split('x')
        return int(width), int(height)
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
    subprocess.run(cmd)

def process_directory(directory):
    """Crawl all folders in a directory and process video files."""
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            if file.lower().endswith(('.mp4', '.mkv', '.avi', '.mov', '.flv')):  # Add more formats if needed
                print(f"Checking resolution of {file_path}...")
                width, height = get_video_resolution(file_path)
                
                if width and height:
                    print(f"Resolution detected: {width}x{height}")
                    if width > 1920 or height > 1080:
                        # Convert video to 1080p
                        output_file = os.path.splitext(file_path)[0] + ".mp4"
                        print(f"Converting {file_path} to 1080p...")
                        convert_to_1080p(file_path, output_file)

                        # Rename original file
                        converted_filename = f"{os.path.splitext(file_path)[0]}-CONVERTED{os.path.splitext(file_path)[1]}"
                        os.rename(file_path, converted_filename)
                        print(f"Original file renamed to {converted_filename}")
                else:
                    print(f"Could not detect resolution for {file_path}")

if __name__ == "__main__":
    directory = input("Enter the directory path to crawl: ")
    process_directory(directory)
