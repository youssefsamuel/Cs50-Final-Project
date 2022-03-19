import os
import datetime
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, usd

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

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///colleagues.db")



@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/newpass", methods =["GET", "POST"])
@login_required
def newpass():
    if request.method == "GET":
        return render_template("newpass.html")
    else:
        old = request.form.get("old")
        new = request.form.get("new")
        conf = request.form.get("conf")
        userid = session["user_id"]
        if not old:
            return apology("must provide old pass", 403)
        if not new:
            return apology("must provide new pass", 403)
        if not conf:
            return apology("must confirm pass", 403)

        if new != conf:
            return apology("Passwords do not match", 403)
        rows=db.execute("SELECT hash FROM users WHERE id = ?", userid)
        if not check_password_hash(rows[0]["hash"], old):
            return apology("old password incorrect", 403)

        else:
            hashed_password = generate_password_hash(new, method='pbkdf2:sha512')

        db.execute("UPDATE users SET hash = ?", hashed_password)

        return redirect("/")


@app.route("/edit", methods = ["GET", "POST"])
@login_required
def edit():
    if request.method == "GET":
        userid = session["user_id"]
        rows = db.execute("SELECT * FROM students WHERE student_id = ?", userid)
        return render_template("edit.html", rows=rows)
    else:
       userid = session["user_id"]
       father=request.form.get("father")
       email=request.form.get("email")
       father_number=request.form.get("father_number")
       mother=request.form.get("mother")
       mother_number=request.form.get("mother_number")
       student=request.form.get("student")
       birth=request.form.get("birth")
       adress=request.form.get("adress")
       db.execute("UPDATE students SET (student, father, mother, email, birth, adress, fnum, mnum) = (?, ?, ?, ? ,?,?,?,?) WHERE student_id = ?",student, father, mother, email, birth, adress, father_number, mother_number, userid)
       return redirect("/info")

@app.route("/students")
@login_required
def students():
    rows = db.execute("SELECT student_id, student, father FROM students")
    return render_template("students.html", rows=rows)

@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/enroll", methods = ["GET", "POST"])
def enroll():
    if request.method == "GET":
        studentid = session["user_id"]
        rows = db.execute("SELECT * FROM students WHERE student_id = ?", studentid)
        if not rows:
            return render_template("enroll.html")
        else:
            return apology("You have already enrolled your kid")
    else:
        studentid = session["user_id"]
        father=request.form.get("father")
        email=request.form.get("email")
        father_number=request.form.get("father_number")
        mother=request.form.get("mother")
        mother_number=request.form.get("mother_number")
        student=request.form.get("student")
        birth=request.form.get("birth")
        adress=request.form.get("adress")
        db.execute("INSERT INTO students (student_id, student, father, mother, email, birth, adress, fnum, mnum) VALUES (?,?,?,?,?,?,?,?,?)", studentid, student, father, mother, email, birth, adress, father_number, mother_number)
        return redirect("/info")

@app.route("/info")
def info():
    studentid = session["user_id"]
    rows = db.execute("SELECT * FROM students WHERE student_id = ?", studentid)
    if not rows:
        return apology("You have not enrolled your kid yet!")
    else:
        return render_template("info.html", rows=rows)


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")

    else:
        if not request.form.get("username"):
            return apology("must provide username", 403)

        elif not request.form.get("password"):
            return apology("must provide password", 403)

        elif not request.form.get("confirm"):
            return apology("must provide password", 403)

        password = request.form.get("password")
        password_confirmation = request.form.get("confirm")

        if password != password_confirmation:
            return apology("Passwords do not match", 403)

        rows = db.execute("SELECT * FROM users WHERE username = :username",username=request.form.get("username"))

        if len(rows) != 0:
             return apology("Username already exists", 403)

        username = request.form.get("username")
        hashed_password = generate_password_hash(password, method='pbkdf2:sha512')

        db.execute("INSERT INTO users (username, hash) VALUES (:username, :hashed_password)", username=username, hashed_password=hashed_password)

        return redirect("/")




def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
