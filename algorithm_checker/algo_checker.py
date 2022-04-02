from sympy import diff
import allscripts as con
import difflib
from pymongo import MongoClient
from datetime import datetime
from bs4 import BeautifulSoup as bs
from termcolor import colored
 
#lista HTML tagova koji mogu u sebi imati skrivene linkove
html_tags_with_urls = ["<a>","<applet>","<api>","<area>","<base>","<blockquote>","<body>","<del>"
                        ,"<form>","<frame>","<head>","<iframe>","<img>","<input>","<ins>","<link>","<object>","<q>"
                        ,"<script>","<source>","<meta>","<audio>","<button>","<command>","<embed>","<input>","<track>",
                        "<video>","<formaction>"]
#lista CSS atributa koji se mogu koristiti za skrivanje elemenata na stranici (skriveni linkovi)
bad_css=["z-index","margin","left","right","top","bottom","filter","opacity","height","width"]
#lista CSS atributa za pozicioniranje pomoću kojih se može sakriti element iz vidljivog područja stranice
bad_css_positioning =["margin","left","right","top","bottom","height","width"]


client = MongoClient('mongodb://fdomovic:5tKL4ABlJLLdSYkN@localhost:27017/')
db = client['websecradar']
pages_collection = db.crawled_data_pages_v0



firstpage = ""
secondpage = ""

with open("new1.html","r") as f:
    firstpage = "\n".join(f.readlines())
with open("old2.html","r") as f:
    secondpage =  "\n".join(f.readlines())

f1 = con.onlyTagsDB(firstpage)
f2 = con.onlyTagsDB(secondpage)
#imamo samo tagove znaam da su razlicit

attr_difference = "\n".join(difflib.Differ().compare(f2.split("\n"),f1.split("\n")))
diffCharArray = attr_difference.split("\n")
new_added_tags = []
for line in diffCharArray:
    #KRITIČNA PROMJENA ?
    if(len(line) > 1):
        if "+" == line[0]:
            new_added_tags.append(line.replace("+",""))
continue_search = False
for line in new_added_tags:
    #KRITIČNA PROMJENA STRIPANJE
    if line.strip() in html_tags_with_urls:
        continue_search= True
        break

if(continue_search):
    #(new)
    f3 = con.getParsedPageDB(firstpage)
    #(old)
    f4 = con.getParsedPageDB(secondpage)

    attr_difference = "\n".join(difflib.Differ().compare(f4.split("\n"),f3.split("\n")))
    diffCharArray2 = attr_difference.split("\n")
    new_added_attrs = []
    for line in diffCharArray2:
        if(len(line) > 1):
            if "+"  == line[0]:
                if "<" in line or ">" in line:
                    if "<" not in line:
                        temp = line.replace("+","")
                        new_added_attrs.append("<"+temp)
                    elif ">" not in line:
                        temp = line.replace("+","")
                        new_added_attrs.append(">"+temp)
                    else:
                        new_added_attrs.append(line.replace("+",""))
    end = ("".join(new_added_attrs))
    soupEnd = bs(end, 'lxml')
    print(soupEnd.prettify())
    #okej u ovom koraku imam samo nove stvari
    pages_links = set({})
    css_vals_cist = {}

    security_index = 0

    for i in soupEnd.findAll({}):
        if(len(i.attrs) > 0 ):
            for key in i.attrs:
                lista = ["www","www.",".com",".org","https://","http://"]
                
                if any(x in i.attrs[key] for x in lista):
                    pages_links.add(i.attrs[key])

                if(key == "hidden"):
                    security_index +=1
                if(key == "style"):
                    
                    lista_css_atributa = i.attrs[key].split(";")
                    
                    for css_attrs in lista_css_atributa:
                        if(css_attrs != "" and ":" in css_attrs):
                            a = css_attrs.split(":")
                            css_vals_cist[a[0]] = a[1]

    for key in css_vals_cist:
        
        if key.strip() in bad_css:
            if(key.strip() == "z-index"):
                if(int(css_vals_cist[key]) <= 10):
                    security_index +=1
            elif key.strip() in bad_css_positioning:
                val = int(css_vals_cist[key].replace("px","").replace("vh","").replace("vw","").replace("rem","").replace("em","").replace("%",""))
                if( val < -500 or val > 1000 or val == 0):
                    security_index +=1
            elif(key.strip() == "filter"):
                if(css_vals_cist[key] == "alpha(opacity=0)"):
                    security_index +=1
            elif(key.strip() == "opacity"):
                if(float(css_vals_cist[key]) < 1):
                    security_index +=1
    if(len(pages_links) != 0):
        security_index += 2
    if(security_index >= 3):
        #
        #
        #14.
        #ako je sigurnosni index > 3 znaci da postoji mogućnost pronalaska malicioznog koda 
        #radimo usporedbu stranice ponovo te usporedbu zapisujemo u HTML grafičkom obliku da vidimo što 
        #je zapravo dodano. Ručno radimo provjeru da utvrdimo valjanost algoritma
        #
        #
        print(str(1)+"."+colored("[MALICIOUS]","red")+" SECURITY INDEX IS: "+str(security_index))
        difference = difflib.HtmlDiff(wrapcolumn=40).make_file(f4.split("\n"),f3.split("\n"),"old","new",True)
        with open("razlika.html","w") as f:
            f.write(difference)
       
    else:
        print(str(1)+"."+colored("[NO MALICIOUS ELEMENTS]","yellow")+" SECURITY INDEX IS: "+str(security_index)+" || ")
        
                            

#DOBAR ALGO PROVJERENO



