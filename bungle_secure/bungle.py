import sys, os, re, bottle
os.chdir(os.path.dirname(os.path.abspath(__file__)))

from bottle import get, post, run, debug, request, response, redirect, view, FormsDict, HTTPError, static_file
import defenses
import database


authSecret = open("auth.secret").read().strip()
database.create()


def getUser():
    username = request.get_cookie("authuser", None, secret=authSecret)
    if username is None:
        return None
    return database.fetchUser(username)


@get("/")
@view("index")
def index():
    defenses.setup(request, response)
    csrftoken = defenses.csrfDefense.init(request, response)
    return dict(v=FormsDict(defenses=defenses.selectors(),
                            user=getUser(),
                            csrfcode=defenses.csrfDefense.formHTML(csrftoken)))


@get('/favicon.ico')
def get_favicon():
    return static_file('favicon.ico', root="./media")


@get("/search")
@view("search")
def search():
    defenses.setup(request, response)
    csrftoken = defenses.csrfDefense.init(request, response)
    defenses.xssDefense.init(response)
    query = defenses.xssDefense.filter(request.query.q)
    user = getUser()
    if user and user.username:
        if query != "":
            database.addHistory(user.username, query)
        history = database.getHistory(user.username)
    else:
        history = None
    return dict(v=FormsDict(defenses=defenses.selectors(),
                            user=getUser(),
                            query=query,
                            history=history,
                            csrfcode=defenses.csrfDefense.formHTML(csrftoken)))


@post("/create")
def create():
    defenses.setup(request, response)
    csrftoken = defenses.csrfDefense.init(request, response)
    defenses.csrfDefense.validate(request, csrftoken)
    username = request.forms.get("username")
    password = request.forms.get("password")
    if not username or not password:
        raise HTTPError(400, "Required field is empty")
    if not re.match("[A-Za-z0-9]+$", username):
        raise HTTPError(400, "Invalid username")
    if database.fetchUser(username):
        raise HTTPError(400, "User already exists")
    if len(password) < 4:
        raise HTTPError(400, "Password too short")
    database.createUser(username, password)
    if not database.validateUser(username, password):
        raise HTTPError(403, "Account creation unsuccessful")
    response.set_cookie("authuser", username, authSecret, httponly=True)
    redirect("./")
    

@post("/login")
def login():
    defenses.setup(request, response)
    csrftoken = defenses.csrfDefense.init(request, response)
    defenses.csrfDefense.validate(request, csrftoken)
    username = request.forms.get("username")
    password = request.forms.get("password")
    if not database.validateUser(username, password):
        raise HTTPError(403, "Login unsuccessful")
    response.set_cookie("authuser", username, authSecret, httponly=True)
    redirect("./")


@post("/logout")
def logout():
    defenses.setup(request, response)
    csrftoken = defenses.csrfDefense.init(request, response)
    defenses.csrfDefense.validate(request, csrftoken)
    response.delete_cookie("authuser")
    redirect("./")


@post("/clear")
def clear():
    defenses.setup(request, response)
    csrftoken = defenses.csrfDefense.init(request, response)
    defenses.csrfDefense.validate(request, csrftoken)
    user = getUser()
    if user and user.username:
        database.clearHistory(user.username)
    redirect("./")


@post("/setdefenses")
def setdefenses():
    defenses.setup(request, response)
    if request.forms.get("location"):
        redirect(request.forms.get("location"))
    else:
        redirect("./")


if __name__ == "__main__":
    debug(True)
    run(host='127.0.0.5', reloader=True)
