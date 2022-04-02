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

#
#
#1. spajanje na MongoDB bazu i stvaranja referenci na kolekcije iz kojih čitamo podatke
#
#
client = MongoClient('mongodb://fdomovic:5tKL4ABlJLLdSYkN@localhost:27017/')
db = client['websecradar']
pages_collection = db.crawled_data_pages_v0
url_collection = db.crawled_data_urls_v0
#
#
#2.varijable potrebne za statistiku i indeksiranje ispisa
#
#
firsthash = ""
secondhash = ""
index = 1
pages_tested = 10000
pages_with_changes = 0
pages_with_malicious_code = 0
#limit = određuje broj objekata koje ćemo provjeriti iz mongoDB
for url in url_collection.find({}).limit(20000):
        #
        #
        #url je zapravo objekt iz mongodb baze koji ima svoje atributa 
        #on ima i svoj atribut ['url'] koji nam daje stvarni "www.....com/.." url
        #stavljamo unutar try except bloka jer se može dogoditi error na dohvaćanju hash-eva ako oni nisu
        #spremljeni ili neki drugi razlog 
        #
        #
        try:  
            #dohvaćanje liste spremljenih verzija stranice 
            arr_len =  len(url['checks'])
            #dohvaćanje hash-a najnovije spremljene verzije stranice
            firsthash = url['checks'][arr_len-1]['hash']
            try:
                #dohvaćanje hash-a druge najnovije verzije 
                secondhash = url['checks'][arr_len-2]['hash']
                #ako hashavi nisu jednaki ide daljnja provjera
                if(firsthash != secondhash):
                    #
                    #
                    #3.blok manipulacije stringovima i podacima da dobijem oblik spremanja datoteke
                    # index_ime_stranice
                    # te kod usporedbe da stranice koje uspoređujem ima njihovo ime te datum kad su spremljene
                    #
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
                    #
                    #
                    #
                    #4.dohvaćanje spremljenog HTML teksta iz kolekcije crawled_data_pages_v0
                    #
                    #
                    firstpage = ""
                    secondpage = ""
                    for obj in pages_collection.find({"hash":str(firsthash)}).limit(1):
                        firstpage = obj['page']

                    for obj in pages_collection.find({"hash":str(secondhash)}).limit(1):
                        secondpage = obj['page']
                    #
                    #
                    #5.u ovom koraku pomocu beautyfulsoup radimo parsiranje stranice
                    #s ciljem dobivanja čiste HTML strukture od Tagova
                    #   *osnovna ideja: ako se i razlikuje po tagovima ali ti tagovi nisu 
                    #   *u listi tagova koji mogu sadržavati url-ove (nešto zlocudno)(const tagovi line 10 )
                    #   *onda ih ne treba provjeravati mozemo samo zapisati novu verziju 
                    #
                    #
                    first_parsed_page = con.onlyTagsDB(firstpage)
                    second_parsed_page = con.onlyTagsDB(secondpage)
                    #
                    #
                    #jos fali dodati ako stranice jesu jednake ispis da su jednake
                    #al msm ako jesu jednake onda nist razlikuju se vjv u nekim atributima koji nece biti zlocudni
                    #ovo dolazi iz pretpostavke prethodno provjerenih stranica gdje su u takvim primjerima razlike bile 
                    #u slovima ili se vrijednost atributa promjenila sa 10px na 12px ili takvi oblici promjena
                    #
                    #
                    if(first_parsed_page != second_parsed_page):
                        #
                        #
                        #6. radimo usporedbu dviju parsiranih stranica te ih dobivamo u obliku stringa 
                        #koji na početku linije moze imate + i - (pojednostavljeno , mogu biti i druge stvari ali to ne gledam)
                        #ako ima + znaci da je ta linija dodana u najnovijoj spremljenoj verziji pa ju onda spremamo u odvojenu varijablu
                        #za daljnju provjeru
                        #
                        #
                        difference = "\n".join(difflib.Differ().compare(second_parsed_page.split("\n"),first_parsed_page.split("\n"))).replace(" ","")
                        diffCharArray = difference.split("\n")
                        new_added_tags = []
                        for line in diffCharArray:
                            if "+" and "-" not in line:
                                new_added_tags.append(line.replace("+",""))
                        #
                        #
                        #7.dodane u listu za provjeru nove linije HTML-a 
                        #i sad provjeravamo jel bilo koja od dodanih linija nove verzije jednaka nekom tagu u listi HTML tagova koji mogu imati url.
                        #ako da nastavljamo potragu i stavljamo continue_search na True
                        #inače završavamo jer stranica nema promjenu u kojoj je moguće ubacit nesto malicioznog
                        #
                        #
                        continue_search = False
                        for line in new_added_tags:
                            if line in html_tags_with_urls:
                                continue_search= True
                                break

                        if(continue_search):
                            #
                            #
                            #8.ponovo parsiramo početno dohvaćene stranice i ovaj put iz njih izbacujemo samo inner HTML text
                            #trebaju nam ovaj puta atributi i njihove vrijednosti jer pomoću njih radimo provjeru malicioznosti
                            #
                            #
                            parsed_page_attrs_new = con.getParsedPageDB(firstpage)
                            parsed_page_attrs_old = con.getParsedPageDB(secondpage)
                            #
                            #
                            #9.ponovo dobivamo string razlika gdje linije imaju + ili - preko kojih znamo što provjeravati
                            #*provjeravamo samo ove koje imaju + na početku
                            #
                            #
                            attr_difference = "\n".join(difflib.Differ().compare(parsed_page_attrs_old.split("\n"),parsed_page_attrs_new.split("\n")))
                            diffCharArray2 = attr_difference.split("\n")
                            new_added_attrs = []
                            #
                            #
                            #10. dodavanje samo linija koje su dodane u novoj verziji tj. koje imaju + na početku
                            #dodatne if uvjete sa ispitivanjem "<" i ">" zbog toga jer nekad vrati razliku u obliku 
                            #gdje oznacava da je dodano npr </a ali ne i njegov element zatvaranja ">" pa ga u takvom slucaju dodamo
                            #a linije koje ne sadrze opce "<>" ne gledamo *primjer prikazivalo je za razliku "&b2"
                            #
                            #
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
                            #nakon ovog koraka imamo nove dodane elemente u valjanom HTML obliku
                            #pa pomocu beautyfulsoup mozemo dohvaćati elemente i raditi manipulaciju nad podacima
                            #

                            #
                            #varijabla pages_links pohranjuje unikatne linkove pronađene u novo dodanim elementima
                            #css_vals_cist je dictionary kojemju je key ime atributa a value vrijednost 
                            #npr   "width":"50px" i onda kasnije koristimo to 
                            #                           
                            pages_links = set({})
                            css_vals_cist = {}
                            #
                            #
                            #11.security_index je varijabla koja je NAJBITNIJI DIO ovog testiranja
                            #pomoću njegove vrijednosti zakljućujemo postoji li maliciozni kod ili ne
                            #on povećava svoju vrijednost za sljedeće svojstva
                            # 1. ako je u listi novo dodanih elemenata link (+1)
                            # 2. ako je u bilo kojem tagu atribut "hidden" ili viđe njih (+1)
                            # 3. ako se događaju manipulacije sa CSS-om unutar style atributa 
                            # 3.1 to se odnosi na width,height,filter,opacity,z-index.. 
                            # 3.1.1  ako je width height 0 , left right top bottom veliki broj u minusu ili plusu , 
                            # 3.1.1      opacity bliza nuli , filter za opacity 0, z-index postavljen da element postavi iza stranice
                            # 3.1.2 za svaki od njih dodaje se +1 security indexu
                            #
                            # security index zapravo broji koliko se neuobičajenih atributa i vrrijednosti koristilo
                            # gore nabrojane točke su dovoljne da mozemo zakljucit da je ubačen link i da je on sakriven 
                            # tako da treshold uzimam broj 3 jer barem 3 kombinacije mogu biti podudaranje za nesto maliciozno
                            #
                            #
                            security_index = 0
                            #
                            #
                            #12. u iducem bloku se rade provjere za security_index
                            #
                            #
                            for i in soupEnd.findAll({}):
                                if(len(i.attrs) > 0 ):
                                    for key in i.attrs:
                                        lista = ["www","www.",".com",".org","https://","http://"]
                                        #provjera postoji li link / url u novo dodanim elementima
                                        if any(x in i.attrs[key] for x in lista):
                                            pages_links.add(i.attrs[key])
                
                                        if(key == "hidden"):
                                            security_index +=1
                                        if(key == "style"):
                                            #
                                            #style je zapisan u obliku  style="attr:value;attr:value..."
                                            #poslije svakog atributa i vrijednosti ide ; pa splitamo po ";"
                                            #nakon toga splitamo po : da dobijemo atribut i njegovu vrijednost koju spremamo u dict
                                            #
                                            lista_css_atributa = i.attrs[key].split(";")
                                            
                                            for css_attrs in lista_css_atributa:
                                                if(css_attrs != "" and ":" in css_attrs):
                                                    a = css_attrs.split(":")
                                                    css_vals_cist[a[0]] = a[1]
                            #
                            #
                            #13.CSS provjere neuobičajenih praksi (skrivanje elemenata iz vidokruga stranice)
                            #
                            #
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
                            
                            #
                            #za dodavanje bilo kakvog linka dodajemo +1 zbog toga što
                            #nemamo bazu podataka loših linkova te se novi pojavljuju svakodnevno da bi se to moglo pratit
                            #i uspoređivat. Jedino za onih par za satove  / online casino ali se i to updejta 
                            #
                            if(len(pages_links) != 0):
                                    security_index += 1

                            if(security_index > 3):
                                #
                                #
                                #14.
                                #ako je sigurnosni index > 3 znaci da postoji mogućnost pronalaska malicioznog koda 
                                #radimo usporedbu stranice ponovo te usporedbu zapisujemo u HTML grafičkom obliku da vidimo što 
                                #je zapravo dodano. Ručno radimo provjeru da utvrdimo valjanost algoritma
                                #
                                #
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
#
#
#15.ostatak ne komentiranog je za ispise ako nešto odgovara ili ne odgovara našim podacima...
#
#
print(colored("\n\-\-\-\-\-\-\-\-\-\-\-\-\-\ \n","green"))
print(colored("[DONE]: YES ","yellow"))
print(colored("[STATISTICS]: ","yellow"))
print(colored("[TESTED PAGES]: "+colored(str(pages_tested),"green"),"yellow"))
print(colored("[CHANGED PAGES]: "+colored(str(pages_with_changes),"green"),"yellow"))
print(colored("[MALICIOUS PAGES]: "+colored(str(pages_with_malicious_code),"green"),"yellow"))
print(colored("[TESTED / CHANGED - RATIO]: "+colored(str(float(pages_with_changes/pages_tested)*100),"red"),"yellow" ))
print(colored("[TESTED / MALICIOUS - RATIO]: "+colored(str(float(pages_with_malicious_code/pages_tested)*100),"red"),"yellow" ))
print(colored("[MALICIOUS / CHANGED - RATIO]: "+colored(str(float(pages_with_malicious_code/pages_with_changes)*100),"red"),"yellow" ))




