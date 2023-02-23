"""
login_users.py
This module contains all function for user register/login
"""
import re 
from email_validator import validate_email, EmailNotValidError
from .config import RegularExpression
from .database_utils import (
         create_user, 
         if_email_not_registered, 
         if_user_not_registered)


def register_user(username,password,email):
    """
    Function register validate and register new user

    :Parameters:
        - username (string)
        - password (string)
        - email (string)
    :Return:
        - True registration successful 
        - False registration faild
    """
    if validation_user(username) and \
                validation_pass(password) and \
                validation_email(email) and\
                if_email_not_registered(email) and \
                if_user_not_registered(username):
        create_user(username,password,email)
        print("validation ok")
        return True
    else:
        return False


def validation_user(username):
    """
    Validation givet username
    Start has to contains only letters and number
    It should have at least 8 letters

    :Parameters:
        - username (string)
    :Return:
        - True/False
    """
    regex = RegularExpression.REGEX_USER
    return True if regex.match(username) else False


def validation_pass(password):
    """
    Validation givet password
    Start has to contains only letters and number
    It should have at least 8 letters

    :Parameters:
        - password (string)
    :Return:
        - True/False
    """
    regex = RegularExpression.REGEX_PASS
    return True if regex.match(password) else False


def validation_email(email):
    """
    Validation give emial  addres
    
    :Parameters:
        - email (string)
    :Return:
        - True/False
    """
    try:
        validation = validate_email(email, check_deliverability=True)
        email_validation = True
    except EmailNotValidError as e:
        email_validation = False
    return email_validation

    



