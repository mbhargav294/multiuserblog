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
import time
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

def is_valid_user(self):
    userid = self.request.cookies.get('user_id', '')
    id=check_secure_val(userid)
    if id:
        return id
    else:
        self.response.headers.add_header('Set-Cookie',
                                        'user_id=%s; Path=/' % '')

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

class Content(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required = True)
    userid = db.StringProperty(required = True)
    username = db.StringProperty(required = True)
    likeslist = db.ListProperty(long)
    commentlist = db.StringListProperty(required = True)
    commentuser = db.StringListProperty(required = True)
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
        userid = self.request.cookies.get('user_id', '')
        id = check_secure_val(userid)
        if id:
            user = Users.get_by_id(long(id))
            if user:
                time.sleep(0.2)
                self.redirect("/")

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
                data = Users(username=usrname,
                            password=make_pw_hash(usrname,psw),
                            email=mail)
                data.put()
                self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % make_secure_val(str(data.key().id())))
                time.sleep(0.2)
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

class LoginPage(Handler):
    def get(self):
        userid = self.request.cookies.get('user_id', '')
        id = check_secure_val(userid)
        if id:
            user = Users.get_by_id(long(id))
            if user:
                time.sleep(0.2)
                self.redirect("/")
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
                        time.sleep(0.2)
                        self.redirect("/")
                    else:
                        error = True
            else:
                error = True
        else:
            error = True

        if error:
            self.render("login.html", validData=False,
                                    validUser=False)

class WelcomePage(Handler):
    def get(self):
        id = is_valid_user(self)
        if not id:
            time.sleep(0.2)
            self.redirect('/login')
        else:
            user = Users.get_by_id(long(id))
            if user:
                contents = Content.all()
                contents.order('-created')
                self.render("welcome.html", user=user,
                                            validUser=True,
                                            contents=contents)
            else:
                time.sleep(0.2)
                self.redirect('/login')


class LogoutPage(Handler):
    def get(self):
        self.response.headers.add_header('Set-Cookie',
                                        'user_id=%s; Path=/' % '')
        time.sleep(0.2)
        self.redirect("/login")

class NewPost(Handler):
    def render_front(self, subject="", content="", error=""):
        id = is_valid_user(self)
        if not id:
            time.sleep(0.2)
            self.redirect('/login')
        else:
            user = Users.get_by_id(long(id))
            if user:
                contents = Content.all()
                self.render("newpost.html", subject=subject,
                                            content=content,
                                            error=error,
                                            user=user,
                                            validUser=True)
            else:
                time.sleep(0.2)
                self.redirect('/login')
    def get(self):
        id = is_valid_user(self)
        if not id:
            time.sleep(0.2)
            self.redirect('/login')
        else:
            self.render_front()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        if subject and content:
            id = is_valid_user(self)
            if not id:
                time.sleep(0.2)
                self.redirect('/login')
            else:
                user=Users.get_by_id(long(id))
                a = Content(subject=subject,
                            content=content,
                            userid=id,
                            username=user.username,
                            likeslist=[],
                            commentlist=[],
                            commentuser=[])
                a.put()
                time.sleep(0.2)
                self.redirect("/" + str(a.key().id()))
        else:
            error="All fields are required"
            self.render_front(subject, content, error)

class SinglePost(Handler):
    def render_front(self, artId=""):
        id = is_valid_user(self)
        if not id:
            time.sleep(0.2)
            self.redirect('/login')
        else:
            user=Users.get_by_id(long(id))
            content = Content.get_by_id(long(artId))
            self.render("article.html", content=content,
                                        user=user,
                                        validUser=True)

    def get(self, product_id):
        id = is_valid_user(self)
        if not id:
            time.sleep(0.2)
            self.redirect('/login')
        else:
            self.render_front(artId=product_id)

    def post(self, product_id):
        id = is_valid_user(self)
        if not id:
            time.sleep(0.2)
            self.redirect('/login')
        else:
            user=Users.get_by_id(long(id))
            comment = self.request.get("comment")
            content = Content.get_by_id(long(product_id))
            if content and comment and len(comment) >= 0 and len(comment) < 200:
                content.commentlist = [comment] + content.commentlist
                content.commentuser = [user.username] + content.commentuser
                content.put()
                time.sleep(0.2)
                self.redirect("/"+product_id)

class LikePost(Handler):

    def get(self, product_id):
        id = is_valid_user(self)
        if not id:
            time.sleep(0.2)
            self.redirect('/login')
        else:
            content = Content.get_by_id(long(product_id))
            referrer = self.request.headers.get('referer')
            if id != content.userid:
                id = long(id)
                if id in content.likeslist:
                    content.likeslist.remove(id)
                else:
                    content.likeslist.append(id)
                content.put()
                time.sleep(0.2)
            self.redirect("%s#%slikes" % (referrer, product_id))


class DeletePost(Handler):
    def get(self, product_id):
        id = is_valid_user(self)
        if not id:
            time.sleep(0.2)
            self.redirect('/login')
        else:
            content = Content.get_by_id(long(product_id))
            if (content.userid != id):
                time.sleep(0.2)
                self.redirect('/'+product_id)
            else:
                content.delete()
                time.sleep(0.2)
                self.redirect('/')

class EditPost(Handler):
    def render_front(self, subject="", content="", artId=""):
        id = is_valid_user(self)
        if not id:
            time.sleep(0.2)
            self.redirect('/login')
        else:
            user=Users.get_by_id(long(id))
            self.render("editpost.html",subject=subject,
                                        content=content,
                                        user=user,
                                        validUser=True)
    def get(self, product_id):
        id = is_valid_user(self)
        if not id:
            time.sleep(0.2)
            self.redirect('/login')
        else:
            content = Content.get_by_id(long(product_id))
            if content.userid == id:
                self.render_front(subject=content.subject,
                                content=content.content)
            else:
                time.sleep(0.2)
                self.redirect('/'+product_id)

    def post(self, product_id):
        id = is_valid_user(self)
        if not id:
            time.sleep(0.2)
            self.redirect('/login')
        else:
            blogpost = Content.get_by_id(long(product_id))

            subject = self.request.get("subject")
            content = self.request.get("content")

            if subject and content:
                blogpost.subject = subject
                blogpost.content = content
                blogpost.put()
                time.sleep(0.2)
                self.redirect("/" + str(blogpost.key().id()))
            else:
                error="All fields are required"
                self.render_front(content, error)

app = webapp2.WSGIApplication([
    ('/logout', LogoutPage),
    ('/login', LoginPage),
    ('/signup', SignupPage),
    ('/', WelcomePage),
    ('/newpost', NewPost),
    (r'/(\d+)', SinglePost),
    (r'/(\d+)/like', LikePost),
    (r'/(\d+)/delete', DeletePost),
    (r'/(\d+)/edit', EditPost)
], debug=True)
