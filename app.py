"""
 * FILENAME: [Lab 8: Security and Cipher Tools]
 * AUTHOR: [Holly Williams]
 * COURSE: [SDEV 300]
 * PROFESSOR: [Justin Boswell]
 * CREATEDATE: [May 9, 2023]

"""

# imports
import re
import logging
from datetime import datetime
from passlib.hash import pbkdf2_sha256
from flask import Flask
from flask import render_template, session, redirect, url_for, request, flash

# create logger variable
logger = logging.getLogger(__name__)
# set level
logger.setLevel(logging.INFO)
# create custom formatter
formatter = logging.Formatter("%(asctime)s:%(levelname)s: %(message)s")
# add to file handler
file_handler = logging.FileHandler("faileduser.log")
file_handler.setFormatter(formatter)
# log file
logger.addHandler(file_handler)


# create an instance of the Flask object
app = Flask(__name__)
app.secret_key = "super secret key"
# read the HTML template and return it to the webpage
# URL '/' to be handled by main() route handler (or view function)
@app.route("/home/")
def home():
    """
    This function renders an html template
    and returns
    """
    if "visited" not in session:
        return redirect(url_for("login"))
    # Render an HTML template and return template and date
    return render_template("home.html", date=datetime.now())


# function to validate password
# must have at least 12 characters in length, and
# include at least 1 uppercase character,
# 1 lowercase character, 1 number and 1 special character.
def validate_password(password):
    """
    This function validates user password complexity
    """
    # create regex
    validpwd = (
        "^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*#?&])[A-Za-z\\d@$!#%*?&]{12,25}$"
    )
    pattern = re.compile(validpwd)
    # call method search to compare
    match = re.search(pattern, password)
    testval = False
    # validating conditions
    if match:
        testval = True
    return testval


# create route to login page and function to login
@app.route("/", methods=["GET", "POST"])
@app.route("/login/", methods=["GET", "POST"])
def login():
    """
    This function validates user login
    """
    if request.method == "POST":
        login_user = request.form["username"]
        login_pwd = request.form["password"]
        if not login_user:
            flash("Please enter your Username.")
            return render_template("login.html")
        if not login_pwd:
            flash("Please enter your Password.")
            return render_template("login.html")
        # open the file to read
        userregist = open("registdata.txt", "r", encoding="utf8")
        # readlines() reads all the lines
        line_data = userregist.readlines()
        userregist.close()
        # loop through until find username and pwd
        find = True
        while find:
            # loop through file to check if user exist
            for item in line_data:
                # Split on the space, and store the results in a list of two strings
                userdata_info_two = item.split()
                # check username and varify hashed password
                if login_user == userdata_info_two[0] and pbkdf2_sha256.verify(
                        login_pwd, userdata_info_two[1]
                    ):
                    # if yes, redirect to home page
                    session["visited"] = True
                    # notify user in home page
                    flash("Login successful!")
                    # stop the loop
                    find = False
                    return render_template("home.html", date=datetime.now())
            # log failed users to faileduser.log
            logger.info("%s %s failed to log in", login_user, request.remote_addr)
            # display error message, if user doesn't exist
            flash("Login failed, try again")
            return render_template("login.html")
    return render_template("login.html")


# function to check if already user registered
def checknotreg(usernametwo):
    """
    This function validates if user already registered
    """
    # declare vars
    testreg = True
    resultreg = True
    # open and read file
    usercheck = open("registdata.txt", "r", encoding="utf8")
    # read all the lines
    usercheckdata = usercheck.readlines()
    # close the file
    usercheck.close()
    # loop through until find user
    while testreg:
        # Read the lines
        for line in usercheckdata:
            # Split on the space, and store the results in a list of two strings
            userdata_info = line.split()
            # test if user exists
            if usernametwo == userdata_info[0]:
                # if yes, stop the loop
                testreg = False
                resultreg = False
                # return result is false
                return resultreg
        # return result to registrsation function
        return resultreg


# create route and function to register
@app.route("/register", methods=["GET", "POST"])
def register():
    """
    This function registrates user
    check if user exists
    hash the password and stores in the file
    """
    if request.method == "POST":
        # get usernmae and pwd
        username = request.form["username"]
        password = request.form["password"]
        # open and read file
        userdata = open("registdata.txt", "r", encoding="utf8")
        # check if not username, pwd
        if not username:
            flash("Please create your Username.")
            return render_template("register.html")
        if not password:
            flash("Please create your Password.")
            return render_template("register.html")
        # call method to check if user exists
        if not checknotreg(username):
            # I decided to pass error message instead of using flash
            message = "This username is already registered"
            return render_template("register.html", error=message)
        # check password complexity
        if not validate_password(password):
            flash("Password does not match requirements")
            return render_template("register.html")
        userdata.close()
        # open file to append
        userdata = open("registdata.txt", "a", encoding="utf8")
        # Hash the password
        hash_pass = pbkdf2_sha256.hash(password)
        # write to the file
        userdata.write(
            "%s %s\n" % (username, str(hash_pass))
        )  # writes the data into the registdata.txt file
        userdata.close()  # close the file
        return render_template(
            "register.html", error="successfully registered, please login."
        )
    return render_template("register.html")


# function to compare pwds
def compare(newpwd):
    """
    This function compares passwords
    with a list of compromised passwords
    """
    testcompare = True
    resultcompare = True
    # read file
    fcp = open("CommonPassword.txt", "r", encoding="utf8")
    data = fcp.readlines()
    fcp.close()
    # loop through data and compare
    while testcompare:
        for item in data:
            # test user pwd with a list
            if newpwd == item.strip():
                testcompare = False
                resultcompare = False
                # return false if found
                return resultcompare
        # return true if not found
        return resultcompare


# create route for reset page and function to reset
@app.route("/reset/", methods=["GET", "POST"])
def reset():
    """
    This function renders an html template
    and returns
    """
    if request.method == "POST":
        # get usernmae and pwd
        username = request.form["username"]
        new_password = request.form["password"]
        # call function to compare pwd with a list
        if not compare(new_password):
            message = "This password is most commonly used or compromised"
            return render_template("reset.html", error=message)
        # validated pwd for pwd requirements
        if not validate_password(new_password):
            message = "Password doesnot match requirements"
            return render_template("reset.html", error=message)
        # read file
        with open("registdata.txt", "r+", encoding="utf8") as resetfile:
            resetf = resetfile.readlines()
            # for every line in the file
            for line in resetf:
                text = line.split()
                # if a text[0] is == to the required username
                if text[0] == username:
                    # Hash the password
                    hash_pass_new = pbkdf2_sha256.hash(new_password)
                    # replace password
                    repl = line.replace(text[1], hash_pass_new)
                    # call update function
                    update_password(repl)
            # redirect and notify user
            return render_template("reset.html", error="Password changed successfully")
    return render_template("reset.html")


# writes to the file new updated pwd
def update_password(repl):
    """
    This function creates and updates
    user password
    """
    # create new file and add new pwd of the user
    with open("newdata.txt", "a+", encoding="utf8") as newreset:
        newreset.write("%s\n" % (repl))


# create route and function to logout
@app.route("/logout", methods=["GET", "POST"])
def logout():
    """
    This function logouts user
    """
    # set sesion to False
    session["visited"] = False
    # go back to login page
    return login()


# register the url for history page
@app.route("/history/")
def history():
    """
    This function renders an html template
    and returns
    """
    return render_template("history.html", date=datetime.now())


# register the url for description page
@app.route("/description/")
def description():
    """
    This function renders an html template
    and returns
    """
    return render_template("description.html", date=datetime.now())


# register the url for health page
@app.route("/health/")
def health():
    """
    This function renders an html template
    and returns
    """
    return render_template("health.html", date=datetime.now())


# if the script is executed run the app
if __name__ == "__main__":
    app.run(debug=True)
