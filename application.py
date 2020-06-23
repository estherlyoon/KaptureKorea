import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finalproj.db")



@app.route("/")
@login_required
def index():
    """Show homepage"""

    #need to apply this to ALL PAGES
    username = db.execute("SELECT * FROM users WHERE id = :user_id",
                          user_id = session["user_id"])[0]['username']

    return render_template("index.html", username=username)





@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    return apology("Sorry")


@app.route("/check", methods=["GET"])
def check():
    return apology("soory")


@app.route("/about", methods=["GET"])
@login_required
def about():



    username = db.execute("SELECT * FROM users WHERE id = :user_id",
                          user_id = session["user_id"])[0]['username']

    return render_template("about.html", username=username)



@app.route("/tips", methods=["GET", "POST"])
@login_required
def tips():

    #get username
    username = db.execute("SELECT * FROM users WHERE id = :user_id",
        user_id = session["user_id"])[0]['username']

    # if user submits comment (method = POST)
    if request.method == "POST":
        # add comment to tips comment table in db
        comment = db.execute("INSERT INTO tipcomments (username, comment) VALUES (:username, :comment)",
            username=username, comment=request.form.get("comment"))

        return redirect('/tips')

    else:
        # make list of all user comments
        comments = db.execute("SELECT * FROM tipcomments ORDER BY id DESC")
        comments_list = []
        for comment in comments:
            comments_list.append(comment)

        # add method to delete, edit comments
        # add method to reply to comments
        # add multiple pages for comments if there gets to be too many (or "load more" option)

        username = db.execute("SELECT * FROM users WHERE id = :user_id",
                         user_id = session["user_id"])[0]['username']

        return render_template("tips.html", comments_list = comments_list, username=username)



@app.route("/language", methods=["GET", "POST"])
@login_required
def language():

    #get username
    username = db.execute("SELECT * FROM users WHERE id = :user_id",
        user_id = session["user_id"])[0]['username']

    # if user submits comment (method = POST)
    if request.method == "POST":
        # add comment to tips comment table in db
        comment = db.execute("INSERT INTO languagecomments (username, comment) VALUES (:username, :comment)",
            username=username, comment=request.form.get("comment"))

        return redirect('/language')

    else:
        # make list of all user comments
        comments = db.execute("SELECT * FROM languagecomments ORDER BY id DESC")
        comments_list = []
        for comment in comments:
            comments_list.append(comment)

        # add method to delete, edit comments
        # add method to reply to comments

        username = db.execute("SELECT * FROM users WHERE id = :user_id",
                         user_id = session["user_id"])[0]['username']

        return render_template("language.html", comments_list = comments_list, username=username)



@app.route("/food", methods=["GET", "POST"])
@login_required
def food():

    #get username
    username = db.execute("SELECT * FROM users WHERE id = :user_id",
        user_id = session["user_id"])[0]['username']

    # if user submits comment (method = POST)
    if request.method == "POST":
        # add comment to tips comment table in db
        comment = db.execute("INSERT INTO foodcomments (username, comment) VALUES (:username, :comment)",
            username=username, comment=request.form.get("comment"))

        return redirect('/food')

    else:
        # make list of all user comments
        comments = db.execute("SELECT * FROM foodcomments ORDER BY id DESC")
        comments_list = []
        for comment in comments:
            comments_list.append(comment)

        # add method to delete, edit comments
        # add method to reply to comments

        username = db.execute("SELECT * FROM users WHERE id = :user_id",
                         user_id = session["user_id"])[0]['username']

        return render_template("food.html", comments_list = comments_list, username=username)



@app.route("/events", methods=["GET", "POST"])
@login_required
def events():

    #get username
    username = db.execute("SELECT * FROM users WHERE id = :user_id",
        user_id = session["user_id"])[0]['username']

    # if user submits comment (method = POST)
    if request.method == "POST":
        # add comment to tips comment table in db
        comment = db.execute("INSERT INTO eventscomments (username, comment) VALUES (:username, :comment)",
            username=username, comment=request.form.get("comment"))

        return redirect('/events')

    else:
        # make list of all user comments
        comments = db.execute("SELECT * FROM eventscomments ORDER BY id DESC")
        comments_list = []
        for comment in comments:
            comments_list.append(comment)

        # add method to delete, edit comments
        # add method to reply to comments

        username = db.execute("SELECT * FROM users WHERE id = :user_id",
                         user_id = session["user_id"])[0]['username']

        return render_template("events.html", comments_list = comments_list, username=username)



@app.route("/places", methods=["GET", "POST"])
def places():

    username = db.execute("SELECT * FROM users WHERE id = :user_id",
                         user_id = session["user_id"])[0]['username']

    return render_template("places.html", username=username)



@app.route("/itinerary", methods=["GET", "POST"])
def itinerary():

    username = db.execute("SELECT * FROM users WHERE id = :user_id",
                         user_id = session["user_id"])[0]['username']

    return render_template("itinerary.html", username=username)




@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username")

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password")

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password")

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register new user"""

    # request username and password
    if request.method == "POST":

        # Ensure passwords were submitted
        password = request.form.get("password")
        confirmation = request.form.get("confirmation")
        email = request.form.get("email")
        if not password or not confirmation or not email:
            return apology("Must fill out all fields")

        # Ensure passwords match
        if password != confirmation:
            return apology("your passwords don't match")

        # store requested username value
        username = request.form.get("username")

        # check if username is taken
        users = db.execute("SELECT * FROM users WHERE username = :username",
                         username=username)

        # if username taken alert user
        if len(users) != 0:
            return apology("Username already taken")

        # check if email is taken
        email = request.form.get("email")
        emails = db.execute("SELECT * FROM users WHERE email = :email",
                         email=email)

        if len(emails) != 0:
            return apology("Please enter a valid email address")

        #insert new user into users, storing hash of password FIRST
        pwhash = generate_password_hash(password)
        db.execute("INSERT INTO users (username, hash, email) VALUES (:username, :password, :email)",
        username=username, password=pwhash, email=email)

        # you have succesfully registered.
        return redirect('/login')

    else:
        return render_template("register.html")


#@app.route("/**", methods=["GET", "POST"])
#@login_required
#def **():



def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)