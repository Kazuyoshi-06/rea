import requests
import urllib3

s = requests.Session()
print(requests.__version__, urllib3.__version__, s.headers["User-Agent"])
