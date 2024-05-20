import requests
import re
import json
import os
import time
from colorama import init, Fore, Style, Back
from urllib.parse import quote
import tiktoken
import shutil
import openai

# Initialize colorama
init(autoreset=True)

# List of known encryption tools/libraries patterns for various languages
known_encryption_tools = [
    # Python
    'import pyarmor', 'from pyarmor',
    'import cryptography', 'from cryptography',
    'import pycryptodome', 'from pycryptodome',
    'import OpenSSL', 'from OpenSSL',
    'import bcrypt', 'from bcrypt',
    'import simple-crypt', 'from simple-crypt',
    'import mcrypt', 'from mcrypt',
    'import scrypt', 'from scrypt',
    'import fernet', 'from fernet',
    'import hashlib', 'from hashlib',
    'import ssl', 'from ssl',
    
    # Java
    'import javax.crypto', 'import java.security', 'import org.bouncycastle',
    
    # JavaScript/Node.js
    'require\\(\'crypto\'\\)', 'require\\(\'bcrypt\'\\)', 'require\\(\'bcryptjs\'\\)',
    'require\\(\'argon2\'\\)', 'require\\(\'pbkdf2\'\\)', 'require\\(\'scrypt\'\\)',
    'require\\(\'crypto-js\'\\)', 'require\\(\'secure-random\'\\)',
    
    # PHP
    'use openssl', 'use phpseclib', 'use defuse',
    'use\\s+Crypt\\S+', 'openssl_encrypt', 'openssl_decrypt',
    
    # C/C++
    '#include <openssl', '#include <crypto', '#include <bcrypt', '#include <sodium',
    
    # Other potential encryption-related keywords (general)
    '\\bAES\\b', '\\bDES\\b', '\\bRSA\\b', '\\bECC\\b', '\\bBlowfish\\b', '\\bTwofish\\b', '\\bCamellia\\b',
    '\\bCAST5\\b', '\\bRC4\\b', '\\bRC5\\b', '\\bRC6\\b', '\\bSerpent\\b', '\\bIDEA\\b', '\\bSHA-256\\b',
    '\\bSHA-1\\b', '\\bSHA-512\\b'
]

# List of text file extensions
text_file_extensions = [
    '.py', '.txt', '.h', '.c', '.cpp', '.js', '.json', '.java', 
    '.cs', '.php', '.html', '.xml', '.sh', '.yml', '.yaml',
    '.bat', '.src', '.cmd'
]

# List of executable file extensions
executable_file_extensions = [
    '.exe', '.dll', '.so', '.bin', '.class', '.jar', '.apk', '.xapk'
]

# Function to transform GitHub URL to raw content URL
def transform_github_url(url):
    if 'github.com' in url:
        url = url.replace('github.com', 'raw.githubusercontent.com')
        url = url.replace('/blob/', '/')
    return url

# Function to check GitHub rate limit
def check_github_rate_limit(headers):
    response = requests.get("https://api.github.com/rate_limit", headers=headers)
    if response.status_code != 200:
        print(f"{Fore.RED}Failed to check GitHub rate limit.")
        return None
    
    rate_limit_info = response.json()
    core = rate_limit_info['resources']['core']
    remaining = core['remaining']
    reset_time = core['reset']
    return remaining, reset_time

# Function to get all files in a GitHub repository directory using GitHub API
def get_files_in_repo(api_url, repo_path="", headers=None):
    url = f"{api_url}/contents/{repo_path}".rstrip('/')
    response = requests.get(url, headers=headers)
    
    if response.status_code == 403:
        remaining, reset_time = check_github_rate_limit(headers)
        if remaining == 0:
            wait_time = reset_time - time.time()
            if wait_time > 0:
                print(f"{Fore.LIGHTBLACK_EX}Rate limit exceeded, waiting for {wait_time} seconds...{Fore.RESET}")
                time.sleep(wait_time)
                return get_files_in_repo(api_url, repo_path, headers)
    
    if response.status_code != 200:
        print(f"{Fore.RED}Failed to access {url}")
        return []

    files = []
    for item in response.json():
        if item['type'] == 'file' and (any(item['name'].endswith(ext) for ext in text_file_extensions + executable_file_extensions)):
            files.append(item['download_url'])
        elif item['type'] == 'dir':
            # Recursively fetch files in subdirectories
            nested_files = get_files_in_repo(api_url, item['path'], headers)
            files.extend(nested_files)
    return files

# Function to check for known encryption tools and encrypted content
def check_file_for_encryption(file_url, openai_api_key=None):
    global passed_files, suspicious_files
    response = requests.get(file_url)
    if response.status_code != 200:
        print(f"{Fore.RED}Failed to access {file_url}")
        return

    file_content = response.text
    lines = file_content.splitlines()
    
    suspicious_found = False

    for line_num, line in enumerate(lines, start=1):
        for tool in known_encryption_tools:
            if re.search(tool, line, re.IGNORECASE):
                col_num = line.find(tool)
                print(f"[{Fore.LIGHTYELLOW_EX}Warning{Fore.RESET}] Known encryption tool/library '{tool}' found in {file_url}")
                print(f"[{Fore.LIGHTYELLOW_EX}Ln {line_num} Col {col_num}{Fore.RESET}] [{Fore.LIGHTBLUE_EX}Trigger{Fore.RESET}]: {line.strip()}")

                # Check with OpenAI if the line is suspicious
                if openai_api_key:
                    context = extract_context(lines, line_num - 1)
                    try:
                        is_suspicious = check_with_openai(context, openai_api_key)
                        if "SUS = True" in is_suspicious:
                            print(f"[{Fore.LIGHTMAGENTA_EX}AI{Fore.RESET}] The AI assigned this file as suspicious")
                            suspicious_found = True
                        else:
                            print(f"[{Fore.LIGHTMAGENTA_EX}AI{Fore.RESET}] The AI assigned this file as safe")
                        if "NOTE = " in is_suspicious and "NOTE = None" not in is_suspicious:
                            note = is_suspicious.split("NOTE = ")[1]
                            print(f"[{Fore.LIGHTMAGENTA_EX}AI{Fore.YELLOW}.NOTE{Fore.RESET}] {note}")
                    except openai.error.RateLimitError:
                        print(f"[{Fore.LIGHTRED_EX}Warning{Fore.RESET}]: No funds in API key. Moving on without using OpenAI API.")
                else:
                    print(f"[{Fore.LIGHTRED_EX}Warning{Fore.RESET}]: No OpenAI API key used, not checking if triggered lines are actually malware/encrypted stuff.")
                suspicious_files += 1
                return

    if re.search(r'\b[A-Fa-f0-9]{32,}\b', file_content):
        match = re.search(r'\b[A-Fa-f0-9]{32,}\b', file_content)
        line_num = file_content[:match.start()].count('\n') + 1
        col_num = match.start() - file_content[:match.start()].rfind('\n')
        print(f"[{Fore.LIGHTRED_EX}Warning{Fore.RESET}] Potential encrypted content found in {file_url}")
        print(f"[{Fore.LIGHTRED_EX}Ln {line_num} Col {col_num}{Fore.RESET}] [{Fore.LIGHTBLUE_EX}Trigger{Fore.RESET}]: {match.group(0)}")

        # Check with OpenAI if the line is suspicious
        if openai_api_key:
            context = extract_context(lines, line_num - 1)
            try:
                is_suspicious = check_with_openai(context, openai_api_key)
                if "SUS = True" in is_suspicious:
                    print(f"[{Fore.LIGHTMAGENTA_EX}AI{Fore.RESET}] The AI assigned this file as suspicious")
                    suspicious_found = True
                else:
                    print(f"[{Fore.LIGHTMAGENTA_EX}AI{Fore.RESET}] The AI assigned this file as safe")
                if "NOTE = " in is_suspicious and "NOTE = None" not in is_suspicious:
                    note = is_suspicious.split("NOTE = ")[1]
                    print(f"[{Fore.LIGHTMAGENTA_EX}AI{Fore.YELLOW}.NOTE{Fore.RESET}] {note}")
            except openai.error.RateLimitError:
                print(f"[{Fore.LIGHTRED_EX}Warning{Fore.RESET}]: No funds in API key. Moving on without using OpenAI API.")
        else:
            print(f"[{Fore.LIGHTRED_EX}Warning{Fore.RESET}]: No OpenAI API key used, not checking if triggered lines are actually malware/encrypted stuff.")
        suspicious_files += 1
        return

    if not suspicious_found:
        passed_files += 1
    print(f"[{Fore.LIGHTGREEN_EX}Passed{Fore.RESET}]: No encryption tools or encrypted content found in {file_url}")

# Function to extract context lines for OpenAI API
def extract_context(lines, line_index):
    start_index = max(line_index - 10, 0)
    end_index = min(line_index + 11, len(lines))
    return "\n".join(lines[start_index:end_index])

# Function to check code with OpenAI API
def check_with_openai(context, api_key):
    openai.api_key = api_key

    enc = tiktoken.encoding_for_model("gpt-3.5-turbo")
    tokenized_context = enc.encode(context)
    if len(tokenized_context) > 800:
        tokenized_context = tokenized_context[:800]

    truncated_context = enc.decode(tokenized_context)

    prompt = f"Is this code malware or suspicious? answer ONLY with \"SUS = True/False\", and if needed(usually if SUS == True) \"NOTE = <note max length 30char>\" NOTE should be \"None\" if unused but still has to be stated, type in the following formatting \" SUS = <bool_value>\\n NOTE = None/\"string_value\" \" Remember to answer only with what stated above: {truncated_context}"

    response = openai.ChatCompletion.create(
        model="gpt-3.5-turbo",
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    result = response.choices[0]['message']['content']
    if "NOTE" not in result:
        result += "\nNOTE = None"
    return result.strip()

# Function to check executable files using VirusTotal
def check_file_with_virustotal(file_url, api_key):
    global passed_files, suspicious_files, not_scanned_executables
    if not api_key:
        print(f"[{Fore.LIGHTCYAN_EX}Info{Fore.RESET}]: {file_url} is executable. To scan executables, use VirusTotal API key.")
        not_scanned_executables += 1
        return

    print(f"[{Fore.LIGHTCYAN_EX}Info{Fore.RESET}]: VirusTotal scan started for {file_url}")
    response = requests.get(file_url)
    if response.status_code != 200:
        print(f"{Fore.RED}Failed to access {file_url}")
        return

    file_content = response.content
    files = {'file': (os.path.basename(file_url), file_content)}
    params = {'apikey': api_key}
    response = requests.post('https://www.virustotal.com/vtapi/v2/file/scan', files=files, params=params)
    if response.status_code != 200:
        print(f"{Fore.RED}Failed to scan {file_url} with VirusTotal.")
        return

    scan_id = response.json()['scan_id']
    params = {'apikey': api_key, 'resource': scan_id}

    # Handle rate limiting
    while True:
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
        if response.status_code == 204:
            print(f"{Fore.LIGHTBLACK_EX}Rate limit exceeded, waiting for 60 seconds...{Fore.RESET}")
            time.sleep(60)
            continue
        if response.status_code != 200:
            print(f"{Fore.RED}Failed to get report for {file_url} from VirusTotal.")
            return

        report = response.json()
        if report['response_code'] == 1:
            positives = report['positives']
            total = report['total']
            if positives > 0:
                print(f"[{Fore.LIGHTRED_EX}VirusTotal{Fore.RESET}] report for {file_url}: {positives}/{total} detections.")
                suspicious_files += 1
            else:
                print(f"[{Fore.LIGHTGREEN_EX}VirusTotal{Fore.RESET}] report for {file_url}: {positives}/{total} detections.")
                passed_files += 1
        else:
            print(f"[{Fore.LIGHTGREEN_EX}Passed{Fore.RESET}]: No VirusTotal report found for {file_url}.")
            passed_files += 1
        break

# Function to print initial banner with rainbow effect
def print_banner():
    term_size = shutil.get_terminal_size((80, 20))
    if term_size.columns >= 100:
        banner = '''                 ,----.      _ __      _,.---._              ,-,--.    _,.----.    ,---.      .-._         
  .-.,.---.   ,-.--` , \  .-`.' ,`.  ,-.' , -  `.          ,-.'-  _\ .' .' -   \ .--.'  \    /==/ \  .-._  
 /==/  `   \ |==|-  _.-` /==/, -   \/==/_,  ,  - \        /==/_ ,_.'/==/  ,  ,-' \==\-/\ \   |==|, \/ /, / 
|==|-, .=., ||==|   `.-.|==| _ .=. |==|   .=.     |       \==\  \   |==|-   |  . /==/-|_\ |  |==|-  \|  |  
|==|   '='  /==/_ ,    /|==| , '=',|==|_ : ;=:  - |        \==\ -\  |==|_   `-' \\\==\,   - \ |==| ,  | -|  
|==|- ,   .'|==|    .-' |==|-  '..'|==| , '='     |        _\==\ ,\ |==|   _  , |/==/ -   ,| |==| -   _ |  
|==|_  . ,'.|==|_  ,`-._|==|,  |    \==\ -    ,_ /        /==/\/ _ |\==\.       /==/-  /\ - \|==|  /\ , |  
/==/  /\ ,  )==/ ,     //==/ - |     '.='. -   .'         \==\ - , / `-.`.___.-'\==\ _.\=\.-'/==/, | |- |  
`--`-`--`--'`--`-----`` `--`---'       `--`--''            `--`---'              `--`        `--`./  `--`  
                                    https://github.com/flaryx32/
      '''
        colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]
        for i, line in enumerate(banner.split('\n')):
            print(colors[i % len(colors)] + line)

# Main function
def main():
    global passed_files, suspicious_files, not_scanned_executables
    print_banner()
    github_url = input(f"[{Fore.LIGHTMAGENTA_EX}Input{Fore.RESET}]: Enter the GitHub repository URL: ").strip()
    
    if github_url.endswith('/tree/main/'):
        print(f"{Fore.RED}Invalid URL. Please provide a valid GitHub repository URL.")
        return

    api_url = github_url.replace('github.com', 'api.github.com/repos').replace('/blob/', '/')
    
    with open('config.json') as config_file:
        config = json.load(config_file)
        github_api_key = config.get('github_api_key')
        virustotal_api_key = config.get('virustotal_api_key')
        openai_api_key = config.get('openai_api_key')

    headers = {}
    if github_api_key:
        headers['Authorization'] = f'Bearer {github_api_key}'
        print(f"[{Fore.LIGHTCYAN_EX}Info{Fore.RESET}]: GitHub API key found, checking rate limit.")
    else:
        print(f"[{Fore.LIGHTRED_EX}Warning{Fore.RESET}]: GitHub API key not found. Consider adding it to reduce rate limits.")

    if not virustotal_api_key:
        print(f"[{Fore.LIGHTRED_EX}Warning{Fore.RESET}]: VirusTotal API key not found. Consider adding it to check executables.")
    else:
        print(f"[{Fore.LIGHTCYAN_EX}Info{Fore.RESET}]: VirusTotal API key found, checking executables.")

    if not openai_api_key:
        print(f"[{Fore.LIGHTRED_EX}Warning{Fore.RESET}]: OpenAI API key not found. Consider adding it to check if triggered lines are actually malware/encrypted stuff.")
    else:
        print(f"[{Fore.LIGHTCYAN_EX}Info{Fore.RESET}]: OpenAI API key found, checking suspicious lines.")
    
    files = get_files_in_repo(api_url, headers=headers)
    if not files:
        print(f"{Fore.RED}No text files found in the repository.")
        return

    passed_files = 0
    suspicious_files = 0
    not_scanned_executables = 0

    for file_url in files:
        if any(file_url.endswith(ext) for ext in text_file_extensions):
            check_file_for_encryption(file_url, openai_api_key)
        elif any(file_url.endswith(ext) for ext in executable_file_extensions):
            check_file_with_virustotal(file_url, virustotal_api_key)

    # Print scan summary
    print(f"[{Fore.LIGHTGREEN_EX}Scan ended{Fore.RESET}]: {passed_files} files passed, {suspicious_files} files suspicious, {not_scanned_executables} executables not scanned.")
    if suspicious_files > 0:
        print(f"[{Fore.RED}The repository is considered malicious.{Fore.RESET}]")
    else:
        print(f"[{Fore.LIGHTGREEN_EX}The repository is considered non-malicious.{Fore.RESET}]")

    print(f"[{Fore.RED}Warning{Fore.RESET}]: Please be aware that this tool does not replace a human. It is recommended to check the files yourself, especially those marked as suspicious.")
    if not virustotal_api_key:
        print(f"[{Fore.RED}Warning{Fore.RESET}]: Consider adding your VirusTotal key to analyze executable files.")
    if not openai_api_key:
        print(f"[{Fore.RED}Warning{Fore.RESET}]: Consider adding your OpenAI key for better analysis and accuracy.")

if __name__ == "__main__":
    main()
