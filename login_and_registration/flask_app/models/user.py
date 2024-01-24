
from flask_app import app
from flask_app.config.mysqlconnection import connectToMySQL
from flask import flash, session,request
from flask_bcrypt import Bcrypt
import re
bcrypt = Bcrypt(app)
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
# The above is used when we do login registration, flask-bcrypt should already be in your env check the pipfile

# Remember 'fat models, skinny controllers' more logic should go in here rather than in your controller. Your controller should be able to just call a function from the model for what it needs, ideally.

class User:
    db = "login_and_registration" #which database are you using for this project
    def __init__(self, data):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password = data['password']
        self.confirm_password = None
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']
        # What changes need to be made above for this project?
        #What needs to be added here for class association?



    # Create Users Models
    @classmethod
    def create_new_user(cls,data):
        if cls.get_user_by_email(data['email']):
            flash('There is already an account with that email')
            return False
        if not cls.validate_user(data): return False
        pw_hash = bcrypt.generate_password_hash(data['password'])
        new_user = {'first_name': data['first_name'],
                'last_name': data['last_name'],
                'email' : data['email'],
                'password': pw_hash}
        query = """
            INSERT INTO users (first_name, last_name, email, password)
            VALUES (%(first_name)s, %(last_name)s, %(email)s, %(password)s);"""
        results = connectToMySQL(cls.db).query_db(query, new_user)
        session['first_name'] = data['first_name']
        session['email'] = data['email']
        session['logged_in'] = True
        session['id'] = results
        return results


    # Read Users Models

    @classmethod
    def get_user_by_id(cls,id):
        data = {'id': id}
        query = """
            SELECT * 
            FROM users  
            WHERE id = %(id)s;"""
        result = connectToMySQL(cls.db).query_db(query,data)
        return(cls(result[0]))
    
    
    @classmethod
    def get_user_by_email(cls,data):
        email= {'email' : data}
        query = """
            SELECT * 
            FROM users  
            WHERE email = %(email)s;"""
        result = connectToMySQL(cls.db).query_db(query,email)
        if len(result) < 1:
            return False
        return cls(result[0])
    
    # Update Users Models



    # Delete Users Models
    
    # Login
    
    @classmethod
    def login_user(cls, data):
        # user_info = {'email': data['email'],
        #         'password': data['password']}
        logged_user = cls.get_user_by_email(data['email'])
        if logged_user:
            if bcrypt.check_password_hash(logged_user.password, data['password']):
                session['id'] = logged_user.id
                session['first_name'] = f'{logged_user.first_name}'
                session['logged_in'] = True
                return True
        flash('Invalid Email or Password')
        return False
    
    # logout
    
    @classmethod
    def log_user_out():
        session.clear()
        return
    
    # Validate user information
    
    @classmethod
    def validate_user(cls, data):
        is_valid = True
        if len(data['first_name']) < 1:
            flash("First name is required.")
            is_valid = False
        if not data['first_name'].isalpha():
            flash("First name can only be letters.")
            is_valid = False
        if len(data['first_name']) < 2:
                flash("First name must be at least 2 charicters long.")
                is_valid = False
        if len(data['last_name']) < 1:
            flash("Last name is required.")
            is_valid = False
        if not data['last_name'].isalpha():
            flash("Last name can only be letters.")
            is_valid = False
        if len(data['last_name']) < 2:
                flash("Last name must be at least 2 charicters long.")
                is_valid = False
        if len(data['email']) < 1:
            flash("Email is required.")
            is_valid = False
        if not EMAIL_REGEX.match(data['email']):
                flash("Invalid email address")
                is_valid = False
        if len(data['password']) < 1:
            flash("a password is required")
            is_valid = False
        if len(data['password']) < 8:
                flash("Password must be at least 8 charicters long")
                is_valid = False
        if not data["password"] == data["confirm_password"]:
            flash("Your password must match confirm password.")
            is_valid=False 
        return is_valid
    