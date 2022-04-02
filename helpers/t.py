from typing import Set
from bs4 import BeautifulSoup as bs
REMOVE_ATTRIBUTES = ['lang','href','language','onmouseover','onmouseout','script','style','font',
                        'dir','face','size','color','style','width','height','hspace',
                        'border','valign','align','background','bgcolor','text','link','vlink',
                        'alink','cellpadding','cellspacing','id','class','clear','action','name','type','title','value','autocomplete'
                        ,'nowrap','alt','src','nonce','content','property','itemprop','itemscope','data-script-url','maxlength','max','min'
                        ,'height','width','target','http-equiv','placeholder','hidden', 'itemtype','method','for','selected','aria-label',
                        'data-label','rel',',role','data-src','srcset','data-srcset','loading','sizes','a','abbr','address','area','article',
                        'aside','audio','b','base','bdi','bdo','blockquote','body','br','button','canvas','caption','cite','code','col',
                        'colgroup','data','datalist','dd','del','details','dfn','dialog',
                        'div','dl','dt','em','figure','embed','fieldset','figcaption','footer','form','h1','h2','h3','h4','h5','h6','head',
                        'accept','accept-charset','accesskey','action','allow','allowfullscreen','alt','as','async','autocapitalize','autocomplete',
                        'autofocus','autoplay','blocking','charset','checked','cite','class','color','colspan','content','contenteditable','controls',
                        'coords','crossorigin','data','datatime','decodin','default','defer','dir','disabled','dirname','download','draggable','enctype',
                        'enterkeyhint','for','form','formaction','formenctype','formenctypeformmethod','headers','height','hidden','high','href','hreflang',
                        'http-equiv','id','imagessize','insert','inputmode','integrity','is','ismap','itemid','itemprop','itemref','itemscope','itemtype',
                        'kind','label','lang','list','loading','loop','low','max','maxlength','media','method','min','minlength','multiple','muted','name',
                        'nomodule','optimum','pettern','ping','placeholder','playsinlin','poster','preload','redonly','refferpolicy','rel','required',
                        'reversed','rows','rowspan','sandbox','scope','selected','shape','size','sizes','slot','span','spellcheck','src','srcdoc',
                        'srclang','srcset','start','step','style','tabindex','target','title','translate','type','usemap','width','wrap','height',
                        'onauxclick','onafterprint','onbeforematch','onbeforeprint','onbeforeunload','onblur','oncancel','oncanplay',
                        'oncanplaythrough','onchange','onclose','oncontextlost','oncontextmenu','oncontextrestored','oncopy',
                        'oncuechange','oncut','ondblcick','ondrag','ondragend','ondragenter','ondragleave','onerror',
                        'onfocus','onformdata','onhashchange','oninput','video','wbr']
pages_links = set({})
index = 0
css_vals_cist = {}
bad_css=["z-index","margin","left","right","top","bottom","filter","opacity","height","width"]
bad_css_positioning =["margin","left","right","top","bottom","height","width"]
with open("1.html","r") as f:
    a = f.readlines()
    soup = bs("".join(a),"lxml")
    for i in soup.findAll({}):
        if(len(i.attrs) > 0 ):
            for key in i.attrs:
                lista = ["www","www.",".com",".org","/","https://","http://"]
                if any(x in i.attrs[key] for x in lista):
                    pages_links.add(i.attrs[key])
                if(key == "hidden"):
                    index +=1
                if(key == "style"):
                    lista_css_atributa = i.attrs[key].split(";")
                    
                    for css_attrs in lista_css_atributa:
                        if(css_attrs != ""):
                            a = css_attrs.split(":")
                            css_vals_cist[a[0]] = a[1]

for key in css_vals_cist:
        if key in bad_css:
            if(key == "z-index"):
                if(int(css_vals_cist[key]) < 10):
                    index +=1
            elif key in bad_css_positioning:
                val = int(css_vals_cist[key].replace("px","").replace("wh","").replace("wv","").replace("rem",""))
                if( val < -500 or val > 1000 or val == 0):
                    index +=1
            elif(key == "filter"):
                if(css_vals_cist[key] == "alpha(opacity=0)"):
                    index +=1
            elif(key == "opacity"):
                if(float(css_vals_cist[key]) < 1):
                    index +=1

if(len(pages_links) != 0):
        index += 1  
if(index > 3):
    print("MALICIOZNO BRE")

# 1 za postoji u njemu link
# 2 ima hidden u sebi 
# 3 z-index < 10 
# 4 jedan od atributa ne šljaka skriven sa ekrana
# 5 opacity alpha 0
# 6 opacity obican manji od 1


#dovoljno je 3 da se napravi maliciozni kod