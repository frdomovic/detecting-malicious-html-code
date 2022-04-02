from bs4 import BeautifulSoup as bs
from bs4.element import NavigableString

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


#IZBACIVANJE INNERHTML TEXTA
def remove_text(soup):
    contents = []
    
    for element in soup.contents:
        if not isinstance(element, NavigableString):
            contents.append(remove_text(element))
            
    soup.contents = contents
    return soup

#SAMO HTML TAGOVI
def onlyTagsDB(dbpage):
    soup = bs(dbpage, 'lxml')
    for tag in soup.find_all():
        tag.attrs = {} 
    soup = remove_text(soup)
    return soup.prettify()

#PARSIRANJE CIJELE STRANICE
def getParsedPageDB(dbpage):
  
    soup = bs(dbpage, 'lxml')
    soup = remove_text(soup)
    return(soup.prettify())


#HTML TAGOVI + ATRIBUTI BEZ VRIJEDNOSTI
def removeAttrValuesDB(dbpage):
    soup = bs(dbpage, 'lxml')

    for attr_del in REMOVE_ATTRIBUTES:
        for i in soup.findAll():
            if(attr_del in i.attrs):
                i[attr_del]=''

    soup = remove_text(soup)
    return soup.prettify()

#HTML TAGOVI + ATRIBUTI KOJI MOGU IMATI LINKOVE

