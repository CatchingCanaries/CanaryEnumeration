#!/usr/bin/python3

import zipfile
import os
import re
import sys
import shutil


RED = '\033[91m'
YELLOW = '\033[93m'
GREEN = '\033[92m'
RESET = '\033[0m'


def file_check(file_path):
    try:
        with open(file_path, 'r') as f:
            f.read(1024)
            return True
    except (UnicodeDecodeError, OSError):
        return False


def canary_enum(file_path):
    if not os.path.isfile(file_path):
        print(f'\n{YELLOW}Error: File {file_path} not found.{RESET}')
        return
    
    if not file_path.lower().endswith(('.xlsx', '.docx', '.pptx')):
        print(f'\n{YELLOW}Error: {file_path} is not a supported file format.{RESET}')
        print(f'\n{YELLOW}Supprted formats: .xlsx, .docx, or .pptx file.{RESET}')
        return
    
    temp_zip = 'test.zip'
    with open(file_path, 'rb') as f_in, open(temp_zip, 'wb') as f_out:
        f_out.write(f_in.read())
    
    with zipfile.ZipFile(temp_zip, 'r') as zip_ref:
        zip_ref.extractall('./canary')
    
    # Original URL Pattern RegEX didn't work for some reasons. Replaced with a simple one. 
    url_pattern = r'https?://\S+'
    exclusion_pattern = 'http(s)?://schemas\.(openxmlformats|microsoft)\.(org|com)|http(s)?://(\w{1,4}\.)?(purl|w3|adobe|twitter|youtube|facebook|linkedin|iec\.\w{1,4})|http(s)?://\w{1,100}(\.\w{1,100})?(\.\w{1,100})?(\.\w{1,100})?\.\w{1,4}((/\w{1,100})*)?/schemas/'
    matches = set()
    
    for root, dirs, files in os.walk('./canary'):
        for file in files:
            file_path_full = os.path.join(root, file)
            if file_check(file_path_full):
                try:
                    with open(file_path_full, 'r', errors='ignore') as f:
                        content = f.read()
                        urls = re.findall(url_pattern, content)
                        for url in urls:
                            if not re.search(exclusion_pattern, url):
                                matches.add(url)
                except Exception as e:
                    print(f'Error reading {file_path_full}: {e}')
    
    os.remove(temp_zip)
    shutil.rmtree('./canary')
    
    if not matches:
        print(f'{GREEN}No canaries found!{RESET}')
        print(f'{YELLOW}File:\t{file_path}{RESET}')
    else:
        print(f'\n\n{RED}Potentially Deceptive || External webhook embedded{RESET}')
        for match in set(matches):
            print(f'{YELLOW}File:\t{file_path}{RESET}')
            print(f'{RED}Match:\t{match}{RESET}\n\n')


if __name__ == '__main__':
    if len(sys.argv)!= 2:
        print('Please provide a single file path as an argument.')
        print('Example: python3 MSOffice_Remote_Resource_Canary_Detection.py test.docx\n')
    else:
        canary_enum(sys.argv[1])
