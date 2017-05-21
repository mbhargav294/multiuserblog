#!/usr/bin/env python
#
# Copyright 2007 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import os
import webapp2
import jinja2
import hmac
import random
import string
import hashlib
import re
import logging
from google.appengine.ext import db

#Put this secret in another module that we dont publish
SECRET = "PUT_SECRET_KEY_HERE"

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir), autoescape=True)

def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

def check_secure_val(h):
    x = h.split('|')
    if len(x) == 2 and x[1] == hash_str(x[0]):
        return x[0]

def make_salt():
    return ''.join(random.sample(string.ascii_letters, 5))

def make_pw_hash(name, pw):
    salt = make_salt()
    return hashlib.sha256(name+pw+salt).hexdigest() + "|" +salt

def check_pw(name, gotPass, hadPass):
    hadHash = hadPass.split('|')[0]
    salt = hadPass.split('|')[1]
    if(salt):
        gotHash = hashlib.sha256(name+gotPass+salt).hexdigest()
        logging.info(hadHash)
        logging.info(gotHash)
        return hadHash == gotHash

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class Users(db.Model):
    username = db.StringProperty(required = True)
    password = db.StringProperty(required = True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add = True)

class SignupPage(Handler):

    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    PSW_RE = re.compile(r"^.{3,20}$")
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

    def valid_username(self, username):
        return self.USER_RE.match(username)

    def valid_password(self, password):
        return self.PSW_RE.match(password)

    def valid_email(self, email):
        if email:
            return self.EMAIL_RE.match(email)
        return True

    def password_match(self, password, verify):
        return password == verify

    def get(self):
        self.render("signup.html", validUsr=True,
                                   validEmail=True,
                                   validPsw=True,
                                   pswMatch=True,
                                   validUser=False)

    def post(self):
        usrname = self.request.get("username")
        psw = self.request.get("password")
        ver = self.request.get("verify")
        mail = self.request.get("email")

        validUsr = self.valid_username(usrname)
        validPsw = self.valid_password(psw)
        validEmail = self.valid_email(mail)
        pswMatch = self.password_match(psw, ver)


        if (validUsr and validPsw and validEmail and pswMatch):
            existing = Users.get_by_key_name(usrname)
            if not existing:
                data = Users(username=usrname, password=make_pw_hash(usrname,psw), email=mail)
                data.put()
                self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % make_secure_val(str(data.key().id())))
                self.redirect("/")
            else:
                self.render("signup.html", usrname="", mail="",
                validUsr=validUsr,
                validEmail=validEmail,
                validPsw=validPsw,
                pswMatch=pswMatch,
                userExists=True,
                validUser=False)
        else:
            self.render("signup.html", usrname=usrname, mail=mail,
            validUsr=validUsr,
            validEmail=validEmail,
            validPsw=validPsw,
            pswMatch=pswMatch,
            validUser=False)

class WelcomePage(Handler):
    def get(self):
        userid = self.request.cookies.get('user_id', '')
        id = check_secure_val(userid)
        if id:
            user = Users.get_by_id(long(id))
            if user:
                self.render("welcome.html", username=user.username, validUser=True)
            else:
                self.redirect('/signup')
        else:
            self.redirect('/signup')

class LoginPage(Handler):
    def get(self):
        self.render("login.html", validData=True, validUser=False)

    def post(self):
        usrname = self.request.get("username")
        psw = self.request.get("password")
        error = False

        if usrname and psw:
            users = Users.all()
            users.filter("username =", usrname)
            if users:
                for user in users.run(limit=1):
                    #logging.info(str(user.key().id()))
                    if check_pw(user.username,psw,user.password):
                        self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % make_secure_val(str(user.key().id())))
                        self.redirect("/")
                    else:
                        error = True
            else:
                error = True
        else:
            error = True

        if error:
            self.render("login.html", validData=False, validUser=False)

class LogoutPage(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % '')
        self.redirect("/login")

app = webapp2.WSGIApplication([
    ('/logout', LogoutPage),
    ('/login', LoginPage),
    ('/signup', SignupPage),
    ('/', WelcomePage)
], debug=True)
