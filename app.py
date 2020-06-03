import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
# from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

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

os.environ['API_KEY'] = "pk_e34b8d451f6e4b51a157f727315097f7"
# Session(app)
app.secret_key='secret123'

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""

    portfolioRows = db.execute("SELECT symbol, name, SUM(shares), price, SUM(total) FROM purchases  WHERE id = ? GROUP BY symbol", session['user_id'])
    userCash = db.execute("SELECT cash FROM users WHERE id = ?", session['user_id'])[0]['cash']

    message = ''
    if "message" in session:
        message=session['message']
        session['message'] = ''

    return render_template("index.html", rows=portfolioRows, cash=userCash, message=message)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == 'GET':
        return render_template("buy.html")
    else:
        lookupDict = lookup(request.form.get("symbol"))
        shares = 0
        try:
            shares = int(request.form.get("shares"))
        except:
            return apology("Missing shares", 400)
        if not lookupDict:
            return apology("Invalid symbol", 400)

        userCash = db.execute("SELECT cash FROM users WHERE id = ?", session['user_id'])[0]['cash']
        if userCash >= shares * lookupDict['price']:
            userCash -= shares * lookupDict['price']
            db.execute("UPDATE users SET cash = ? WHERE id = ?", (userCash, session['user_id']))
            db.execute("INSERT INTO purchases(id, symbol, name, shares, price, total) VALUES(?, ?, ?, ?, ?, ?) ",
            (session['user_id'], lookupDict['symbol'], lookupDict['name'], shares, lookupDict['price'], shares * lookupDict['price']))

            userSymbolRows = db.execute("SELECT * FROM symbols WHERE id = ?", session['user_id'])
            if userSymbolRows == []:
                db.execute("INSERT INTO symbols(id, symbol, shares) VALUES(?, ?, ?)", (session['user_id'], lookupDict['symbol'], shares))
            else:
                executed = False
                for row in userSymbolRows:
                    if lookupDict['symbol'] == row['symbol']:
                        db.execute("UPDATE symbols SET shares = ? WHERE id = ? AND symbol = ?", (row['shares'] + shares, session['user_id'], lookupDict['symbol']))
                        executed = True
                        break

                if not executed:
                    db.execute("INSERT INTO symbols(id, symbol, shares) VALUES(?, ?, ?)", (session['user_id'], lookupDict['symbol'], shares))

            session['message'] = "Bought!"
            return redirect("/")
        else:
            return apology("Can't afford", 400)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""

    rows = db.execute("SELECT * FROM purchases WHERE id = ?", session['user_id'])
    return render_template("history.html", rows=rows)


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
    if request.method == 'GET':
        return render_template("quote.html")
    else:
        lookupDict = lookup(request.form.get("symbol"))
        if lookupDict:
            return render_template("quoted.html", lookup=lookupDict)
        else:
            return apology("Invalid symbol", 400)


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    if request.method == 'GET':
        return render_template("register.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        confirm = request.form.get("confirmation")

        if not username or db.execute("SELECT * FROM users WHERE username = :username", username=username):
            return apology("Username is not available", 400)
        if not password:
            return apology("Missing Password", 400)
        if password != confirm:
            return apology("Passwords don't match", 400)

        db.execute("INSERT INTO users(username, hash) VALUES(?, ?)", (username, generate_password_hash(password)))
        return redirect('/login')


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    if request.method == 'GET':
        symbols = db.execute("SELECT symbol FROM symbols WHERE id = ?", session['user_id'])
        return render_template("sell.html", symbols=symbols)
    else:
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        if not symbol:
            return apology("Missing symbol", 400)
        if not shares:
            return apology("Missing shares", 400)

        shares = int(shares)
        if shares <= 0:
            return apology("Shares must be positive", 400)

        if db.execute("SELECT shares FROM symbols WHERE id = ? AND symbol = ?",
                      (session['user_id'], symbol))[0]['shares'] - shares < 0:
            return apology("Too many shares", 400)

        lookupDict = lookup(symbol)
        db.execute("INSERT INTO purchases(id, symbol, name, shares, price, total) VALUES(?, ?, ?, ?, ?, ?) ",
            (session['user_id'], lookupDict['symbol'], lookupDict['name'], -shares, lookupDict['price'], -shares * lookupDict['price']))

        oldShares = db.execute("SELECT shares FROM symbols WHERE id = ? AND symbol = ?", (session['user_id'], symbol))[0]['shares']
        if oldShares == shares:
            db.execute("DELETE FROM symbols WHERE id = ? AND symbol = ?", (session['user_id'], symbol))
        else:
            db.execute("UPDATE symbols SET shares = ? WHERE id = ? AND symbol = ?", (oldShares - shares, session['user_id'], symbol))

        userCash = db.execute("SELECT cash FROM users WHERE id = ?", session['user_id'])[0]['cash']
        db.execute("UPDATE users SET cash = ? WHERE id = ?", (userCash + (lookupDict['price'] * shares), session['user_id']))

        session['message'] = "Sold!"

        return redirect('/')


@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    if request.method == 'GET':
        return render_template("change_password.html")
    else:
        password = request.form.get("password")
        confirm = request.form.get("confirm")

        if not password:
            return apology("Missing Password", 400)
        if password != confirm:
            return apology("Passwords don't match", 400)

        db.execute("UPDATE users SET hash = ? WHERE id = ?", (generate_password_hash(password), session['user_id']))

        session["message"] = "Password Changed!"
        return redirect("/")



def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)

if __name__ == "__main__":
    app.run()