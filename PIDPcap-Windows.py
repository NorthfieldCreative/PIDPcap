import subprocess
import re
import signal
import time
import os

def check_tshark():
    """Check if tshark is installed and prompt user to install if not."""
    try:
        subprocess.check_output(['tshark', '-v'], stderr=subprocess.STDOUT)
        print("Tshark is installed and ready to use.")
    except FileNotFoundError:
        print("Tshark is not found in PATH. Searching in common installation directories...")
        
        # Check common installation paths
        possible_paths = [
            r"C:\\Program Files\\Wireshark\\tshark.exe",
            r"C:\\Program Files (x86)\\Wireshark\\tshark.exe"
        ]
        for path in possible_paths:
            if os.path.exists(path):
                print(f"Tshark found at {path}. Adding to PATH.")
                os.environ["PATH"] += os.pathsep + os.path.dirname(path)
                try:
                    subprocess.check_output(['tshark', '-v'], stderr=subprocess.STDOUT)
                    print("Tshark installation verified after updating PATH.")
                    return
                except FileNotFoundError:
                    continue
        
        # If not found, prompt the user to install
        print("Tshark is still not found. It is required to run this script.")
        install = input("Would you like to download and install Tshark now? (yes/no): ").strip().lower()
        if install in ['yes', 'y']:
            print("Please download and install Tshark from https://www.wireshark.org/#download")
            input("Press Enter after installation is complete to continue...")
            try:
                subprocess.check_output(['tshark', '-v'], stderr=subprocess.STDOUT)
                print("Tshark installation verified.")
            except FileNotFoundError:
                print("Tshark installation could not be verified. Exiting.")
                exit(1)
        else:
            print("Tshark is required to proceed. Exiting.")
            exit(1)

