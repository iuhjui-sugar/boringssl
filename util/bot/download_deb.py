import extract
import optparse
import os
import requests
import sys
import tempfile

def download_file(url, filename):
    try:
        temp_dir = tempfile.mkdtemp()
        file_path = os.path.join(temp_dir, filename)
        
        response = requests.get(url)
        response.raise_for_status()

        with open(file_path, 'wb') as file:
            file.write(response.content)

        return file_path
    
    except requests.exceptions.RequestException as e:
        print(f"Error downloading file: {e}")
        return None  

def main(args):
    parser = optparse.OptionParser(usage='Usage: %prog URL SHA256_CHECKSUM DEST')
    _, args = parser.parse_args(args)
    url, sha256_checksum, dest = args

    filename = url.split("/")[-1] 
    downloaded_file = download_file(url, filename)
    extract.extract(downloaded_file, dest)

if __name__ == '__main__':
  sys.exit(main(sys.argv[1:]))