import re, os
from bottle import FormsDict, HTTPError
from hashlib import md5

############################################################
# XSS Defenses

class XSSNone():
    name = "No defense"
    @staticmethod
    def init(response):
        response.set_header("X-XSS-Protection", "0");           
    @staticmethod
    def filter(query):
        return query


class XSSRemoveScript():
    name = "Remove &quot;script&quot;"
    @staticmethod
    def init(response):
        response.set_header("X-XSS-Protection", "0");           
    @staticmethod
    def filter(query):
        return re.sub(r"(?i)script", "", query)


class XSSRemoveSeveralTags():
    name = "Remove several tags"
    @staticmethod
    def init(response):
        response.set_header("X-XSS-Protection", "0");           
    @staticmethod
    def filter(query):
        return re.sub(r"(?i)script|<img|<body|<style|<meta|<embed|<object", "", query)


class XSSRemovePunctuation():
    name = "Remove &quot; &apos; and ;"
    @staticmethod
    def init(response):
        response.set_header("X-XSS-Protection", "0");           
    @staticmethod
    def filter(query):
        return re.sub(r"[;'\"]", "", query)


class XSSEncodeAngles():
    name = "Encode &lt; and &gt;"
    @staticmethod
    def init(response):
        response.set_header("X-XSS-Protection", "0");
    @staticmethod
    def filter(query):
        return query.replace("<", "&lt;").replace(">", "&gt;")

############################################################
# CSRF Defenses

class CSRFNone():
    name = "No defense"
    @staticmethod
    def init(request, response):
        response.set_header("Access-Control-Allow-Origin", "*");
    @staticmethod
    def formHTML(token):
        return ""
    @staticmethod
    def validate(request, token):
        pass


class CSRFToken():
    name = "Token validation"
    @staticmethod
    def init(request, response):
        token = request.get_cookie("csrf_token")
        if token is None:
            token = os.urandom(16).hex()
            response.set_cookie("csrf_token", token)
        return token
    @staticmethod
    def formHTML(token):
        return "<input type='hidden' name='csrf_token' value='" + token + "'>"
    @staticmethod
    def validate(request, token):
        if request.forms.get('csrf_token') != token:
            raise HTTPError(403, "CSRF Attack Detected (bad or missing token)")     

###########################################################

xssDefenses = [XSSNone,XSSRemoveScript,XSSRemoveSeveralTags,XSSRemovePunctuation,XSSEncodeAngles]
csrfDefenses = [CSRFNone,CSRFToken]

xssDefense = xssDefenses[0]
csrfDefense = csrfDefenses[0]


def setCookies(response):
    response.set_cookie("xssdefense", str(xssDefenses.index(xssDefense)))
    response.set_cookie("csrfdefense", str(csrfDefenses.index(csrfDefense)))


def setup(request, response):
    def getDefense(request, name):
        if name in request.forms:
            return int(request.forms.get(name))
        elif name in request.query:
            return int(request.query.get(name))
        else:
            return int(request.get_cookie(name,0))
    global xssDefense, csrfDefense
    xss = getDefense(request, "xssdefense")
    if xss not in range(len(xssDefenses)):
        raise HTTPError(output="Invalid XSS Defense (%d)" % xss)
    csrf = getDefense(request, "csrfdefense")
    if csrf not in range(len(csrfDefenses)):
        raise HTTPError(output="Invalid CSRF Defense (%d)" % csrf)
    xssDefense = xssDefenses[xss]
    csrfDefense = csrfDefenses[csrf]
    print(xssDefense, csrfDefense)
    setCookies(response)


def selectors():
    def getSelector(defenseList, selectedDefense=None):
        return "".join("<option value=%d%s>%d - %s</option>" % \
                           (i,(defenseList[i].name==selectedDefense.name and " selected" or ""), i, defenseList[i].name) \
                           for i in range(len(defenseList)))
    return FormsDict(xssoptions=getSelector(xssDefenses,xssDefense),
                     csrfoptions=getSelector(csrfDefenses,csrfDefense))