from sympy import diff
import allscripts as con
import difflib
from pymongo import MongoClient
from datetime import datetime
from bs4 import BeautifulSoup as bs
from termcolor import colored


client = MongoClient('mongodb://fdomovic:5tKL4ABlJLLdSYkN@localhost:27017/')
db = client['websecradar']
pages_collection = db.crawled_data_pages_v0
url_collection = db.crawled_data_urls_v0


for url in url_collection.find({"hash":"039da8625964ce0f459c430ea2a5c1e3327cfed590e4de2dba89b88630f7ee85"}).limit(1):
    firstpage = url['page']