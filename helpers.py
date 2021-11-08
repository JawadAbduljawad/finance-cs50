import os
import requests
import urllib.parse

from flask import redirect, render_template, request, session
from functools import wraps


def apology(message, code=400):
    """Render message as an apology to user."""
    def escape(s):
        """
        Escape special characters.

        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
                         ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=code, bottom=escape(message)), code


def login_required(f):
    """
    Decorate routes to require login.

    https://flask.palletsprojects.com/en/1.1.x/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect("/login")
        return f(*args, **kwargs)
    return decorated_function


def lookup(symbol):
    """Look up quote for symbol."""

    # Contact API
    try:
        api_key = os.environ.get("API_KEY")
        url = f"https://cloud.iexapis.com/stable/stock/{urllib.parse.quote_plus(symbol)}/quote?token={api_key}"
        response = requests.get(url)
        response.raise_for_status()
    except requests.RequestException:
        return None

    # Parse response
    try:
        quote = response.json()
        return {
            "name": quote["companyName"],
            "price": float(quote["latestPrice"]),
            "symbol": quote["symbol"]
        }
    except (KeyError, TypeError, ValueError):
        return None


def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"

    
def isValid(password):
    """Valid Password Checker"""
    # for checking if password length
    # is between 8 and 15
    if (len(password) < 8 or len(password) > 15):
        return False
  
    # to check space
    if (" " in password):
        return False
  
    if (True):
        count = 0
  
        # check digits from 0 to 9
        arr = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
  
        for i in password:
            if i in arr:
                count = 1
                break
  
        if count == 0:
            return False
  
    # for special characters
    if True:
        count = 0
  
        arr = ['@', '#', '!', '~', '$', '%', '^', '&', '*', '(', ',', '-', '+', '/', ':', '.', ',', '<', '>', '?', '|']
  
        for i in password:
            if i in arr:
                count = 1
                break
        if count == 0:
            return False
  
    if True:
        count = 0
  
        # checking capital letters
        for i in range(65, 91):
  
            if chr(i) in password:
                count = 1
  
        if (count == 0):
            return False
  
    if (True):
        count = 0
  
        # checking small letters
        for i in range(90, 123):
  
            if chr(i) in password:
                count = 1
  
        if (count == 0):
            return False
  
    return True
    