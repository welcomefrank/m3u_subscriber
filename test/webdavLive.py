import urllib

import requests
from xml.etree import ElementTree

url = 'http://192.168.5.1:5244/dav/阿里云盘'
username = 'pi'
password = 'wanjun310'
encoded_url = urllib.parse.quote(url, safe=':/')

# Send a PROPFIND request to retrieve the contents of the directory
response = requests.request('PROPFIND', url, auth=(username, password))

# Parse the XML response and extract the names of the directories and files
root = ElementTree.fromstring(response.content)

with open('/directory_listing.txt', 'w', encoding='utf-8') as f:
    for child in root.findall('{DAV:}response'):
        href = child.find('{DAV:}href').text
        display_name = child.find('{DAV:}propstat/{DAV:}prop/{DAV:}displayname').text
        if not href.endswith('/'):  # Process only files (not directories)
            file_path = '/'.join(href.split('/')[-2:])  # Get the file path from the href
            # Decode any URL-encoded characters in the file name
            file_path = urllib.parse.unquote(file_path)
            # Write the file path to the file
            try:
                f.write('{}\n'.format(file_path))
                #f.write('{}\n'.format(encoded_url+"/"+urllib.parse.quote(file_path, safe=':/')))
            except UnicodeEncodeError:  # Handle non-UTF-8 and non-ASCII characters by replacing them with "?"
                f.write('{}\n'.format(file_path.encode('ascii', 'replace').decode('utf-8', 'replace')))