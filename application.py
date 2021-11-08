import os
from datetime import datetime

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd, isValid

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
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():

    user = db.execute("SELECT username FROM users WHERE id = ?", session['user_id'])[0]['username']
    currCash = db.execute("SELECT cash FROM users WHERE username = ?", user)[0]['cash']
    Record = db.execute(
        'SELECT symbol, company_name, SUM(qty), total, current_price FROM record WHERE username = ? GROUP BY symbol', user)

    TOTAL = currCash
    for Set in Record:
        newPrice = lookup(Set['symbol'])['price']
        db.execute("UPDATE record SET current_price = ? WHERE symbol = ?", newPrice, Set['symbol'])
        Set['total'] = Set['SUM(qty)']*Set['current_price']
        print(Set['total'])
        TOTAL += Set['total']

    return render_template("index.html", List=Record, cash=currCash, usd=usd, TOTAL=TOTAL)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        now = datetime.now()
        dateTime = now.strftime("%d/%m/%Y %H:%M:%S")
        user = session["user_id"]

        username = db.execute("SELECT username FROM users WHERE id = ?", user)[0]["username"]
        userCash = db.execute("SELECT cash FROM users WHERE id = ?", user)[0]['cash']
        try:
            qty = int(request.form.get("shares"))
        except:
            return apology("Shares must be an integer")
        SYMBOL = request.form.get("symbol")
        symbol = lookup(request.form.get("symbol"))
        if symbol == None:
            return apology("Symbol not found")
        totalP = symbol["price"] * qty
        if qty < 1:
            return apology("You can't buy less than one share")
        elif symbol == None:
            return apology("Symbol not found")
        elif userCash < totalP:
            return apology("Insufficient cash")
        else:
            db.execute("UPDATE users SET cash = ? WHERE id = ?", userCash - totalP, user)
            stocks = db.execute("SELECT symbol FROM record WHERE username = ?", username)
            symbols = [x['symbol'] for x in stocks]
            if SYMBOL not in symbols:
                db.execute("INSERT INTO record (username, symbol, qty, datetime, current_price, total,company_name) VALUES(?,?,?,?,?,?,?)",
                           username, SYMBOL, qty, dateTime, symbol["price"], totalP, symbol["name"])
                db.execute("INSERT INTO history (username, symbol, qty, datetime, pps, operation) VALUES(?,?,?,?,?,?)",
                           username, SYMBOL, qty, dateTime, symbol["price"], "BUY")
            else:
                qtyowned = db.execute("SELECT qty FROM record WHERE symbol = ? AND username = ?", SYMBOL, username)[0]['qty']
                newQty = qtyowned + qty
                db.execute("INSERT INTO history (username, symbol, qty, datetime, pps, operation) VALUES(?,?,?,?,?,?)",
                           username, SYMBOL, qty, dateTime, symbol["price"], "BUY")
                db.execute("UPDATE record SET qty = ? WHERE symbol = ? AND username = ?", newQty, SYMBOL, username)
            flash(u'Bought!', )
            return redirect("/")
    else:
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    username = db.execute("SELECT username FROM users WHERE id = ?", session['user_id'])[0]['username']
    History = db.execute("SELECT symbol, qty, pps, datetime FROM history WHERE username = ?", username)
    return render_template("history.html", History=History, usd=usd)


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
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

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


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        requestedSymbol = lookup(request.form.get('symbol'))  # use the api to lookup for the price name and symbol of the stock
        if requestedSymbol == None:
            return apology("Symbol not found")
        else:

            name = requestedSymbol["name"]
            symbol = requestedSymbol["symbol"]
            price = usd(requestedSymbol["price"])
            return render_template("quoted.html", COname=name, COsymbol=symbol, COprice=price)
    else:
        return render_template("quote.html")
        

@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    session.clear()
    user = request.form.get("username")
    pwd = request.form.get("password")
    pwdc = request.form.get("confirmation")

    if request.method == "POST":
        if user == "":
            return apology("Username can'n be blank")
        elif user in [x['username'] for x in db.execute("SELECT username FROM users")]:
            return apology("Username is used")
        elif not isValid(pwd):
            return apology("not a valid password")
        elif pwdc != pwd:
            return apology("Passwords don't match")
        elif pwd == "":
            return apology("Password can't be blank")
        elif pwdc == "":
            return apology("Password Confirmation is required")
        else:
            # print(db.execute("SELECT username FROM users"))
            HASH = generate_password_hash(method='pbkdf2:sha256', password=pwd)
            db.execute("INSERT INTO users (username, hash) VALUES(?, ?)", user, HASH)

            return render_template("regSuc.html")

    else:

        return render_template("register.html")
        

@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    username = db.execute("SELECT username FROM users WHERE id = ?", session['user_id'])[0]['username']

    Record = db.execute('SELECT symbol, SUM(qty) as Qty FROM record WHERE username = ? GROUP BY symbol', username)

    if request.method == 'POST':
        now = datetime.now()
        dateTime = now.strftime("%d/%m/%Y %H:%M:%S")
        symbol = request.form.get("symbol")
        qty = int(request.form.get("shares"))

        owned = db.execute("SELECT SUM(qty) FROM record WHERE username = ? AND symbol = ? GROUP BY symbol",
                           username, symbol)[0]['SUM(qty)']
        if qty > owned:
            return apology("Too many shares")
        else:
            total = qty * lookup(symbol)['price']
            newCash = db.execute("SELECT cash FROM users WHERE username = ?", username)[0]['cash'] + total
            SQLQTY = -1*qty
            newOwned = owned - qty
            db.execute('UPDATE users SET cash = ? WHERE username = ?', newCash, username)
            db.execute("UPDATE record SET qty = ? WHERE username = ?", newOwned, username)
            db.execute("INSERT INTO history (username, symbol, qty, datetime, pps, operation) VALUES(?,?,?,?,?,?)",
                       username, symbol, SQLQTY, dateTime, lookup(symbol)['price'], "SELL")
            flash('Sold!')
            return redirect('/')
    else:
        print(Record)
        return render_template("sell.html", record=Record)


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
