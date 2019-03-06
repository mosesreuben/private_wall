from flask import Flask, render_template, session, redirect, request, flash
import re
from flask_bcrypt import Bcrypt
from mysqlconnection import connectToMySQL

app = Flask(__name__)
app.secret_key = "youcandothis"
bcrypt = Bcrypt(app)

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$') 

def login_user(user_info, session_object):
    session_object['curr_user_id'] = user_info['id']
    session_object['curr_user_name'] = user_info['name']

@app.route("/")
def show_log_reg():
    print("Going to login/registration.")
    return render_template("landing.html")

@app.route("/wall")
def show_wall():
    if not 'curr_user_id' in session:
        return redirect("/")
    else:
        # get logged in user data
        logged_in_user = {
            'name': session['curr_user_name'],
            'id': session['curr_user_id']
        }
        print(logged_in_user)
        # get users messages
        mysql = connectToMySQL("wall")
        msg_query = "SELECT message, first_name, messages.message_id FROM messages JOIN users ON messages.sender_id=users.user_id WHERE recipient_id=%(id)s;"
        msg_data = {'id': logged_in_user['id']}
        messages = mysql.query_db(msg_query, msg_data)
        print(messages)
        # get all users
        mysql = connectToMySQL("wall")
        users_query = "SELECT first_name, last_name, user_id FROM users"
        users = mysql.query_db(users_query)
        print(users)
        context = {
            'user': logged_in_user,
            'users': users,
            'messages': messages,
        }
        return render_template("wall.html", context=context)

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

@app.route("/login", methods= ['POST'])
def login():
    errors = []
    # grab details
    input_pw = request.form['password']
    input_email = request.form['email']
    input_alias = request.form['alias']
    # check if user exists
    mysql = connectToMySQL("wall")
    query = "SELECT * FROM users WHERE email = %(email)s"
    data = {
        'email': input_email
    }
    result = mysql.query_db(query, data)
    
    if not result:
        errors.append("wrong user")
        for message in range(len(errors)):
            print(message)
            flash(errors[message])
        return redirect("/")

    if result[0]['email']!=input_email:
        errors.append("Email are not corrrect.")
        
    if result[0]['alias']!=input_alias:
        errors.append("a are not corrrect.")
        
    if not bcrypt.check_password_hash(result[0]['password_hash'], input_pw):
        errors.append("password are not corrrect.")

    print(len(errors))
    if len(errors) > 0:
        for message in range(len(errors)):
            print(message)
            flash(errors[message])
        return redirect("/")
    else:
        login_user({'id': result[0]['user_id'], 'name':result[0]['first_name']}, session)
        return redirect("/")
    
@app.route("/register", methods=["POST"])
def register():
    print(request.form)
    error_messages = []
    # check validations
    if len(request.form['first_name']) <2:
        error_messages.append("First name must be more than two characters.")
    if not request.form['first_name'].isalpha():
        error_messages.append("First name must be alphabet, silly human.")
    if len(request.form['last_name']) < 2:
        error_messages.append("Last name must be more than 2 characters.")
    if len(request.form['alias']) < 2:
        error_messages.append("Alias must be more than 2 characters.")
    if request.form['alias'] != request.form['alias']:
        error_messages.append("Your username does NOT match the one we have on file.")
    if not EMAIL_REGEX.match(request.form['email']):
        error_messages.append("Must be VALID email.")
    if request.form['password'] != request.form['confirm_password']:
        error_messages.append("Passwords must match.")
    if len(request.form['password']) < 2:
        error_messages.append("Password must be longer than 2 characters.")
    if len(request.form['dob']) < 2: 
        error_messages.append("Password must be longer than 2 characters.")


    if len(error_messages) == 0:
        # log our user in...
        pw_hash = bcrypt.generate_password_hash(request.form['password'])
        mysql = connectToMySQL("wall")
        query = "INSERT INTO users (first_name,last_name,alias,email,password_hash) VALUES (%(first)s, %(last)s, %(alias)s, %(email)s, %(password)s)"
        data = {
            'first':    request.form['first_name'],
            'last':     request.form['last_name'],
            'alias':     request.form['alias'],
            'email':    request.form['email'],
            'password': pw_hash,
        }
        newid = mysql.query_db(query, data)
        print(newid)
        login_user({'id': newid, 'name': request.form['first_name']}, session)
        return redirect("/wall")
    else:
        # flash a bunch of messages
        for message in error_messages:
            print(message)
            flash(message)
        return redirect("/")

@app.route("/delete/message", methods=['POST'])
def delete_message():
    print("*"*10)
    mysql = connectToMySQL('wall')
    query = "DELETE FROM messages WHERE message_id=%(msg_id)s;"
    data = {'msg_id': request.form['msg_id']}
    results = mysql.query_db(query, data)
    print(results)
    return redirect("/wall")

@app.route("/message", methods=["POST"])
def create_message():
    mysql = connectToMySQL('wall')
    new_message = {
        'sender_id':     request.form['sender_id'],
        'recipient_id':  request.form['recipient_id'], 
        'message':       request.form['message']
    }
    query = "INSERT INTO messages (message, recipient_id, sender_id) VALUES (%(message)s, %(recipient_id)s, %(sender_id)s)"
    result = mysql.query_db(query, new_message)
    print(result)
    return redirect("/wall")

@app.route("/edit")
def edit():
    return render_template("edit.html")

@app.route("/myevents")
def myevents():
    return render_template("myevents.html")

if __name__ == "__main__":
    print("Let's get this belt.")
    app.run(debug=True)