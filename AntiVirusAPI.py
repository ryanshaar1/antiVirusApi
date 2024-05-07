import os
import requests
import tkinter as tk
from tkinter import filedialog
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

class FileEventHandler(FileSystemEventHandler):
    def __init__(self, callback):
        super().__init__()
        self.callback = callback
    
    def on_created(self, event):
        if not event.is_directory:
            self.callback(event.src_path)

def check_file_malicious(file_path, api_key):
    url = 'https://www.virustotal.com/vtapi/v2/file/scan'
    params = {'apikey': api_key}
    files = {'file': (file_path, open(file_path, 'rb'))}
    response = requests.post(url, files=files, params=params)
    result = response.json()
    
    if result['response_code'] == 1:
        if 'positives' in result:
            if result['positives'] > 0:
                return True, result['positives'], result['total']
            else:
                return False, 0, result['total']
        else:
            return False, 0, 0  
    else:
        return None, 0, 0


def list_files_and_folders(folder_path):
    file_list = []
    for root, dirs, files in os.walk(folder_path):
        for file in files:
            file_list.append(os.path.join(root, file))
    return file_list

def scan_folder(folder_path, api_key):
    files = list_files_and_folders(folder_path)
    for file in files:
        is_malicious, positives, total = check_file_malicious(file, api_key)
        if is_malicious:
            print(f"Malicious file detected: {file} - Detected by {positives}/{total} scanners.")
        else:
            print(f"File not detected as malicious: {file}")

def choose_folder():
    folder_path = filedialog.askdirectory()
    if folder_path:
        scan_folder(folder_path, api_key)


api_key = ''

root = tk.Tk()
root.title("Antivirus")
root.geometry("400x200")

label = tk.Label(root, text="Select folder to scan:")
label.pack()

scan_button = tk.Button(root, text="Choose Folder", command=choose_folder)
scan_button.pack()

observer = Observer()
observer.schedule(FileEventHandler(lambda x: scan_folder(x, api_key)), path='.', recursive=True)
observer.start()

root.mainloop()
