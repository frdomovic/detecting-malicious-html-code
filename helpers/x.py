from sympy import diff
import allscripts as con
import difflib
from pymongo import MongoClient
from datetime import datetime
from bs4 import BeautifulSoup as bs
from termcolor import colored
 

html_tags_with_urls = ["<a>","<applet>","<api>","<area>","<base>","<blockquote>","<body>","<del>"
                        ,"<form>","<frame>","<head>","<iframe>","<img>","<input>","<ins>","<link>","<object>","<q>"
                        ,"<script>","<source>","<meta>","<audio>","<button>","<command>","<embed>","<input>","<track>",
                        "<video>","<formaction>"]
#liste atributa pomocu kojih se moze sakriti određeni element webstranica 
bad_css=["z-index","margin","left","right","top","bottom","filter","opacity","height","width"]
bad_css_positioning =["margin","left","right","top","bottom","height","width"]


client = MongoClient('mongodb://fdomovic:5tKL4ABlJLLdSYkN@localhost:27017/')
db = client['websecradar']
pages_collection = db.crawled_data_pages_v0
url_collection = db.crawled_data_urls_v0
#667
firsthash = ""
secondhash = ""

for url in url_collection.find({}):
    arr_len =  len(url['checks'])
    firsthash = url['checks'][arr_len-1]['hash']
    secondhash = url['checks'][arr_len-2]['hash']
    if(firsthash != secondhash):
        firstpage = ""
        secondpage = ""
        for obj in pages_collection.find({"hash":str(firsthash)}).limit(1):
            firstpage = obj['page']

        for obj in pages_collection.find({"hash":str(secondhash)}).limit(1):
            secondpage = obj['page']
        first_parsed_page = con.getParsedPageDB(firstpage)
        second_parsed_page = con.getParsedPageDB(secondpage)

        
        
        attr_difference = "\n".join(difflib.Differ().compare(first_parsed_page.split("\n"),second_parsed_page.split("\n")))
        print(attr_difference)
        break
    
