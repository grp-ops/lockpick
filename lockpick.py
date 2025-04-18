#!/usr/bin/python3

import pyzipper
import argparse
from concurrent.futures import ThreadPoolExecutor
import os
import threading
import time
import sys

ascii_banner = r"""

.____    ________  _________  ____  __.__________.____________  ____  __.
|    |   \_____  \ \_   ___ \|    |/ _|\______   \   \_   ___ \|    |/ _|
|    |    /   |   \/    \  \/|      <   |     ___/   /    \  \/|      <  
|    |___/    |    \     \___|    |  \  |    |   |   \     \___|    |  \ 
|_______ \_______  /\______  /____|__ \ |____|   |___|\______  /____|__ \
        \/       \/        \/        \/                      \/        \/
        
"""

password_attempts = 0
found_password = False
password_lock = threading.Lock()
stop_event = threading.Event()  

def display_banner():
    os.system("cls" if os.name == "nt" else "clear")
    print(ascii_banner)

def extract_file(zname, password):
    global password_attempts, found_password
    if found_password or stop_event.is_set():
        return
    try:
        with pyzipper.AESZipFile(zname) as zip_file:
            zip_file.pwd = password.encode('utf-8')
            zip_file.extractall()
        with password_lock:
            found_password = True
            print(f"\n[+] Found password: {password}\n")
            os._exit(0)
    except (RuntimeError, pyzipper.BadZipFile):
        pass
    finally:
        with password_lock:
            password_attempts += 1

def display_progress(total_passwords):
    global password_attempts
    while not found_password and not stop_event.is_set():
        with password_lock:
            progress = (password_attempts / total_passwords) * 100
        sys.stdout.write(f"\r[INFO] Progress: {password_attempts}/{total_passwords} passwords tried ({progress:.2f}%)")
        sys.stdout.flush()
        time.sleep(2)

def password_generator(dname):
    try:
        with open(dname, 'r', encoding='utf-8', errors='ignore') as pass_file:
            for line in pass_file:
                if stop_event.is_set():
                    break
                yield line.strip()
    except FileNotFoundError:
        print(f"[-] Dictionary file '{dname}' not found.")
        os._exit(1)

def batch_processor(zname, batch):
    for password in batch:
        if stop_event.is_set():
            break
        extract_file(zname, password)

def main(zname, dname, max_threads=4):
    global password_attempts
    display_banner()

    passwords = password_generator(dname)

    total_passwords = sum(1 for _ in open(dname, 'r', encoding='utf-8', errors='ignore'))
    print(f"[+] Loaded {total_passwords} passwords from dictionary file.")

    progress_thread = threading.Thread(target=display_progress, args=(total_passwords,), daemon=True)
    progress_thread.start()

    batch_size = 100
    try:
        with ThreadPoolExecutor(max_threads) as executor:
            batch = []
            for password in passwords:
                batch.append(password)
                if len(batch) >= batch_size:
                    executor.submit(batch_processor, zname, batch)
                    batch = []
            if batch:
                executor.submit(batch_processor, zname, batch)
    except KeyboardInterrupt:
        stop_event.set()  # Signal all threads to stop
        print("\n[!] KeyboardInterrupt. Exiting")
    finally:
        if not found_password:
            print("\n[-] Password not found. Try another dictionary.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(usage="lockpick.py ZIPFILE DICTFILE")
    parser.add_argument("zipfile", type=str, metavar="ZIPFILE", help="Specify the ZIP file to crack.")
    parser.add_argument("dictfile", type=str, metavar="DICTFILE", help="Specify the dictionary file.")
    parser.add_argument("--threads", type=int, default=4, help="Specify the maximum number of threads (default: 4).")
    args = parser.parse_args()

    try:
        main(args.zipfile, args.dictfile, args.threads)
    except KeyboardInterrupt:
        stop_event.set()
        print("\n[!] Program interrupted by user. Exiting...")
