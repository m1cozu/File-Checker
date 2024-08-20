import os
import re
import time
import sys
import threading
import ctypes
import argparse
import logging
from colorama import Fore, Style, init
from tqdm import tqdm
from itertools import cycle
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import mimetypes
import subprocess

# Initialize colorama and logging
init()
logging.basicConfig(filename='threat_scanner.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def log_info(message):
    logging.info(message)
    print(Fore.CYAN + message + Style.RESET_ALL)

def log_error(message):
    logging.error(message)
    print(Fore.RED + message + Style.RESET_ALL)

# Define dangerous patterns with improved accuracy
dangerous_patterns_python = [
    r'eval\(',
    r'exec\(',
    r'os\.system\(',
    r'subprocess\.call\(',
    r'subprocess\.Popen\(',
    r'shutil\.which\(',
    r'pickle\.load\(',
    r'pickle\.dump\(',
    r'marshal\.load\(',
    r'marshal\.dump\('
]

dangerous_patterns_batch = [
    r'del\s+',
    r'format\s+',
    r'shutdown\s+',
    r'rd\s+',
    r'rmdir\s+',
    r'copy\s+',
    r'move\s+'
]

def spinning_cursor(stop_event):
    spinner = cycle(['|', '/', '-', '\\'])
    while not stop_event.is_set():
        sys.stdout.write(f'\r{next(spinner)} ')
        sys.stdout.flush()
        time.sleep(0.1)

def check_python_threats(lines):
    threats = []
    for line in lines:
        for pattern in dangerous_patterns_python:
            if re.search(pattern, line):
                threats.append(f"Potential threat in Python code: {line.strip()}")
    return threats

def check_batch_threats(lines):
    threats = []
    for line in lines:
        for pattern in dangerous_patterns_batch:
            if re.search(pattern, line):
                threats.append(f"Potential threat in Batch script: {line.strip()}")
    return threats

def scan_file(filepath):
    threats = []
    try:
        with open(filepath, 'r', errors='ignore') as file:
            while True:
                chunk = file.read(1024)
                if not chunk:
                    break
                lines = chunk.splitlines()
                if filepath.endswith('.py'):
                    threats.extend(check_python_threats(lines))
                elif filepath.endswith('.bat'):
                    threats.extend(check_batch_threats(lines))
    except FileNotFoundError:
        log_error(f"File not found: {filepath}")
    except IOError as e:
        log_error(f"I/O error reading file {filepath}: {e}")
    except Exception as e:
        log_error(f"Unexpected error reading file {filepath}: {e}")
    return threats

def scan_directory(directory):
    threats = []
    files_with_threats = []
    files = [f for f in os.listdir(directory) if f.endswith('.py') or f.endswith('.bat')]
    
    # Create a stop event for the spinner thread
    stop_event = threading.Event()
    
    # Start spinner in a separate thread
    spinner_thread = threading.Thread(target=spinning_cursor, args=(stop_event,), daemon=True)
    spinner_thread.start()
    
    # Add a progress bar with smoother animation
    with tqdm(total=len(files), desc="Scanning files", unit="file", ncols=100) as pbar:
        for filename in files:
            filepath = os.path.join(directory, filename)
            file_threats = scan_file(filepath)
            if file_threats:
                threats.extend(file_threats)
                files_with_threats.append(filepath)
            pbar.update(1)  # Update progress bar
    
    # Stop spinner animation
    stop_event.set()
    spinner_thread.join()
    sys.stdout.write('\rDone!               \n')
    
    return threats, files_with_threats

def report_threats(threats, report_file='threat_report.txt'):
    with open(report_file, 'w') as file:
        if threats:
            for threat in threats:
                file.write(threat + '\n')
            log_info(f"Threats reported to {report_file}.")
        else:
            file.write("No potential threats found.\n")
            log_info("No potential threats found.")

def delete_threat_files(files_with_threats):
    for filepath in files_with_threats:
        try:
            os.remove(filepath)
            log_info(f"Deleted file: {filepath}")
        except Exception as e:
            log_error(f"Failed to delete file {filepath}: {e}")

class ThreatHandler(FileSystemEventHandler):
    def __init__(self, directory):
        self.directory = directory

    def on_modified(self, event):
        if event.src_path.endswith('.py') or event.src_path.endswith('.bat'):
            log_info(f"File modified: {event.src_path}")
            self.scan_file(event.src_path)

    def scan_file(self, filepath):
        threats = []
        try:
            with open(filepath, 'r', errors='ignore') as file:
                lines = file.readlines()
                if filepath.endswith('.py'):
                    threats.extend(self.check_python_threats(lines))
                elif filepath.endswith('.bat'):
                    threats.extend(self.check_batch_threats(lines))
            if threats:
                log_error(f"Potential threats in file {filepath}:")
                for threat in threats:
                    log_error(threat)
        except Exception as e:
            log_error(f"Error reading file {filepath}: {e}")

    def check_python_threats(self, lines):
        threats = []
        for line in lines:
            for pattern in dangerous_patterns_python:
                if re.search(pattern, line):
                    threats.append(f"Potential threat in Python code: {line.strip()}")
        return threats

    def check_batch_threats(self, lines):
        threats = []
        for line in lines:
            for pattern in dangerous_patterns_batch:
                if re.search(pattern, line):
                    threats.append(f"Potential threat in Batch script: {line.strip()}")
        return threats

def create_monitoring_script(directory):
    script_content = (
        'import os\n'
        'import re\n'
        'import time\n'
        'from watchdog.observers import Observer\n'
        'from watchdog.events import FileSystemEventHandler\n'
        'from colorama import Fore, Style, init\n'
        '\n'
        '# Initialize colorama\n'
        'init()\n'
        '\n'
        '# Define dangerous patterns with improved accuracy\n'
        'dangerous_patterns_python = [\n'
        '    r\'eval\\(\',\n'
        '    r\'exec\\(\',\n'
        '    r\'os\\.system\\(\',\n'
        '    r\'subprocess\\.call\\(\',\n'
        '    r\'subprocess\\.Popen\\(\',\n'
        '    r\'shutil\\.which\\(\',\n'
        '    r\'pickle\\.load\\(\',\n'
        '    r\'pickle\\.dump\\(\',\n'
        '    r\'marshal\\.load\\(\',\n'
        '    r\'marshal\\.dump\\(\',\n'
        ']\n'
        '\n'
        'dangerous_patterns_batch = [\n'
        '    r\'del\\s+\',\n'
        '    r\'format\\s+\',\n'
        '    r\'shutdown\\s+\',\n'
        '    r\'rd\\s+\',\n'
        '    r\'rmdir\\s+\',\n'
        '    r\'copy\\s+\',\n'
        '    r\'move\\s+\'\n'
        ']\n'
        '\n'
        'class ThreatHandler(FileSystemEventHandler):\n'
        '    def __init__(self, directory):\n'
        '        self.directory = directory\n'
        '\n'
        '    def on_modified(self, event):\n'
        '        if event.src_path.endswith(\'.py\') or event.src_path.endswith(\'.bat\'):\n'
        '            print(Fore.CYAN + f"File modified: {event.src_path}" + Style.RESET_ALL)\n'
        '            self.scan_file(event.src_path)\n'
        '\n'
        '    def scan_file(self, filepath):\n'
        '        threats = []\n'
        '        try:\n'
        '            with open(filepath, \'r\', errors=\'ignore\') as file:\n'
        '                lines = file.readlines()\n'
        '                if filepath.endswith(\'.py\'):\n'
        '                    threats.extend(self.check_python_threats(lines))\n'
        '                elif filepath.endswith(\'.bat\'):\n'
        '                    threats.extend(self.check_batch_threats(lines))\n'
        '            if threats:\n'
        '                print(Fore.RED + f"Potential threats in file {filepath}:" + Style.RESET_ALL)\n'
        '                for threat in threats:\n'
        '                    print(Fore.RED + threat + Style.RESET_ALL)\n'
        '        except Exception as e:\n'
        '            print(Fore.RED + f"Error reading file {filepath}: {e}" + Style.RESET_ALL)\n'
        '\n'
        '    def check_python_threats(self, lines):\n'
        '        threats = []\n'
        '        for line in lines:\n'
        '            for pattern in dangerous_patterns_python:\n'
        '                if re.search(pattern, line):\n'
        '                    threats.append(f"Potential threat in Python code: {line.strip()}")\n'
        '        return threats\n'
        '\n'
        '    def check_batch_threats(self, lines):\n'
        '        threats = []\n'
        '        for line in lines:\n'
        '            for pattern in dangerous_patterns_batch:\n'
        '                if re.search(pattern, line):\n'
        '                    threats.append(f"Potential threat in Batch script: {line.strip()}")\n'
        '        return threats\n'
        '\n'
        'def main():\n'
        '    directory = "."\n'
        '    event_handler = ThreatHandler(directory)\n'
        '    observer = Observer()\n'
        '    observer.schedule(event_handler, path=directory, recursive=False)\n'
        '    observer.start()\n'
        '    print(Fore.GREEN + "Real-time threat monitoring started. Press Ctrl+C to stop." + Style.RESET_ALL)\n'
        '    try:\n'
        '        while True:\n'
        '            time.sleep(1)\n'
        '    except KeyboardInterrupt:\n'
        '        observer.stop()\n'
        '    observer.join()\n'
        '\n'
        'if __name__ == "__main__":\n'
        '    main()\n'
    )

    with open(os.path.join(directory, 'active_threats_monitoring.py'), 'w') as file:
        file.write(script_content)
    log_info("Active threat monitoring script created: active_threats_monitoring.py")

def launch_monitoring_script(script_path):
    try:
        subprocess.run(['python', script_path], check=True)
    except subprocess.CalledProcessError as e:
        log_error(f"Failed to run monitoring script: {e}")

def main():
    parser = argparse.ArgumentParser(description="File threat scanner and real-time monitoring tool.")
    parser.add_argument('--directory', type=str, default='.', help="Directory to scan (default is current directory).")
    args = parser.parse_args()

    directory = args.directory
    log_info(f"Scanning for potential threats in directory: {directory}")
    
    # Scan directory and report threats
    threats, files_with_threats = scan_directory(directory)
    report_threats(threats)
    
    if threats:
        log_info("\nThreats detected:")
        for threat in threats:
            log_error(threat)
    
    response = input(Fore.CYAN + "Do you want to delete files with threats (y/n)? " + Style.RESET_ALL).strip().lower()
    if response == 'y':
        if input(Fore.YELLOW + "Are you sure you want to delete these files? This action cannot be undone (y/n): " + Style.RESET_ALL).strip().lower() == 'y':
            log_info("Deleting files with threats...")
            delete_threat_files(files_with_threats)
        else:
            log_info("File deletion canceled.")
    
    create_monitoring_script(directory)
    monitoring_script_path = os.path.join(directory, 'active_threats_monitoring.py')
    launch_monitoring_script(monitoring_script_path)
    
    log_info("Threat monitoring completed!")

if __name__ == "__main__":
    main()
