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
index = 1
pages_tested = 10000
pages_with_changes = 0
pages_with_malicious_code = 0
for url in url_collection.find({}).limit(20000):
        try:  
            arr_len =  len(url['checks'])
            firsthash = url['checks'][arr_len-1]['hash']
            try:
                secondhash = url['checks'][arr_len-2]['hash']
                if(firsthash != secondhash):
                   
                    name = (url['url'])
                    datum1 = str(datetime.fromtimestamp( url['checks'][arr_len-1]['timestamp'])).split(" ")[0]
                    datum2 = str(datetime.fromtimestamp( url['checks'][arr_len-2]['timestamp'])).split(" ")[0]

                    nameref =  datum1+url['url']
                    nameref2 = datum2+url['url']
                    name = name.replace("https://","")
                    name = name.replace("http://","")
                    if "/" in name:
                        name = name[0:name.index("/")]

                    name = str('./DIFFERENCES/'+str(index)+'_'+name+'.html')

                    firstpage = ""
                    secondpage = ""
                    for obj in pages_collection.find({"hash":str(firsthash)}).limit(1):
                        firstpage = obj['page']

                    for obj in pages_collection.find({"hash":str(secondhash)}).limit(1):
                        secondpage = obj['page']

                    
                    # #
                    # #U OVOM KORAKU IMAM NAJNOVIJU VERZIJU I PRETHODNU VERZIJU STRANICE I ONE SE SIGURNO RAZLIKUJU U NECEMU
                    # #NAJBOLJE ZA POCETAK OCISTIT TEKST IZ STRANICE 
                    # #NAKON TOGA IMAMO TAG I ATRIBUTE U KOJIMA VEC MOZEMO NAC RAZLIKE, SAD BI TREBALO CILJAT ONDA
                    first_parsed_page = con.onlyTagsDB(firstpage)
                    second_parsed_page = con.onlyTagsDB(secondpage)
                
                    #SAD IMAMO PARSIRANE STRANICE U PRETTIFY BEZ TEKSTA 
                    #
                    if(first_parsed_page != second_parsed_page):
                        #DIFFERENCE je string promjena odnosno usporedba prve i druge verzije stranice
                        #NOVI ELEMENTI SU DODANI OZNACENI SA + IZA NJIH PA ONDA SAMO ZAPISUJEMO I PROVJERVAMO NOVE ELEMENTE
                        #SAD BI JA NAPRAVIL PROMJENU DA PROVJERI JESU LI UNUTRA TAGOVI MOGU IMATI SKRIVENE LINKOVE UNUTRA 
                        #I ONDA AKO TO POSTOJI ISPOCETKA NAPRAVITI USPOREDBU SA ATRIBUTIMA 
                        #
                        #
                        #1.dobivene sve razlike sa + i -
                        difference = "\n".join(difflib.Differ().compare(second_parsed_page.split("\n"),first_parsed_page.split("\n"))).replace(" ","")
                        
                        
                        #2.lista charova po kojoj provjeravamo postojanje + i - u njima
                        diffCharArray = difference.split("\n")
                        
                        new_added_tags = []
                        for line in diffCharArray:
                            if "+" and "-" not in line:
                                new_added_tags.append(line.replace("+",""))
                        
                        continue_search = False
                        for line in new_added_tags:
                            if line in html_tags_with_urls:
                                continue_search= True
                                break

                        if(continue_search):
                            
                            parsed_page_attrs_new = con.getParsedPageDB(firstpage)
                            parsed_page_attrs_old = con.getParsedPageDB(secondpage)

                            #1. attr_difference = "".join(difflib.Differ().compare(parsed_page_attrs_old,parsed_page_attrs_new)).replace(" ","")
                            attr_difference = "\n".join(difflib.Differ().compare(parsed_page_attrs_old.split("\n"),parsed_page_attrs_new.split("\n")))
                            #dobijem to u obliku da gleda samo razlike po linijama AJD OKE ONO JEBOTE ZIVOT VISE 

                            diffCharArray2 = attr_difference.split("\n")
                           
                            #dobijem u obliku arraya ajd to kasnije isprobat za promjenit
            
                            
                            new_added_attrs = []
                            for line in diffCharArray2:
                                
                                if "+" in line and "-" not in line:
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
                            
                            #
                            #
                            #u ovom trenutku imam u lijepo parsirano html obliku samo dodane varijable
                            pages_links = set({})
                            css_vals_cist = {}
                            security_index = 0
                            #
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
                                    if key in bad_css:
                                        if(key == "z-index"):
                                            if(int(css_vals_cist[key]) < 10):
                                                security_index +=1
                                        elif key in bad_css_positioning:
                                            val = int(css_vals_cist[key].replace("px","").replace("wh","").replace("wv","").replace("rem",""))
                                            if( val < -500 or val > 1000 or val == 0):
                                                security_index +=1
                                        elif(key == "filter"):
                                            if(css_vals_cist[key] == "alpha(opacity=0)"):
                                                security_index +=1
                                        elif(key == "opacity"):
                                            if(float(css_vals_cist[key]) < 1):
                                                security_index +=1
                            if(len(pages_links) != 0):
                                    security_index += 1  
                            if(security_index > 3):
                                print(str(index)+"."+colored("[MALICIOUS]","red")+" SECURITY INDEX IS: "+str(security_index)+" || ",url['url'])
                                difference = difflib.HtmlDiff(wrapcolumn=40).make_file(parsed_page_attrs_old.split("\n"),parsed_page_attrs_new.split("\n"),nameref2,nameref,True)
                                with open(name,"w") as f:
                                    f.write(difference)
                                pages_with_malicious_code += 1
                                pages_with_changes +=1
                            else:
                                print(str(index)+"."+colored("[NO MALICIOUS ELEMENTS]","yellow")+" SECURITY INDEX IS: "+str(security_index)+" || ",url['url'])
                                pages_with_changes +=1
                        else:
                            print(str(index)+"."+colored("[NO MALICIOUS ELEMENTS]","magenta")+" THERE ARE CHANGES URL: ",url['url'])
                            pages_with_changes +=1

                else:
                    print(str(index)+"."+colored("[HASH OK]","green")+" PAGES HAVE IDENTICAL HASH")
                index += 1

            except:
                try:
                    print(str(index)+"."+colored("[ERROR]","red")+" URL: ",url['url']," DOES NOT HAVE SAVED ANY _PREVIOUS_ VERSIONS")
                    index += 1
                except:
                    print(colored("[ERROR]","red")+" COULD NOT GET PAGES")
                    index += 1

        except:
            try:
                print(str(index)+"."+colored("[ERROR]","red")+"URL: ",url['url']," DOES NOT HAVE SAVED ANY VERSIONS")
                index += 1
            except:
                print(colored("[ERROR]","red")+" COULD NOT GET PAGES")
                index += 1
print(colored("\n\-\-\-\-\-\-\-\-\-\-\-\-\-\ \n","green"))
print(colored("[DONE]: YES ","yellow"))
print(colored("[STATISTICS]: ","yellow"))
print(colored("[TESTED PAGES]: "+colored(str(pages_tested),"green"),"yellow"))
print(colored("[CHANGED PAGES]: "+colored(str(pages_with_changes),"green"),"yellow"))
print(colored("[MALICIOUS PAGES]: "+colored(str(pages_with_malicious_code),"green"),"yellow"))
print(colored("[TESTED / CHANGED - RATIO]: "+colored(str(float(pages_with_changes/pages_tested)*100),"red"),"yellow" ))
print(colored("[TESTED / MALICIOUS - RATIO]: "+colored(str(float(pages_with_malicious_code/pages_tested)*100),"red"),"yellow" ))
print(colored("[MALICIOUS / CHANGED - RATIO]: "+colored(str(float(pages_with_malicious_code/pages_with_changes)*100),"red"),"yellow" ))




