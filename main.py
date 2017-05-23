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

"""
""author: mbhargav294
""last modified: May 23, 2017
""
"""
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

# Put this secret in another module which is not published
SECRET = "PUT_SECRET_KEY_HERE"

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

# hmac is used to secure passwords and securing cookies
# params: s - string
# return: string


def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()

# uses hash_str(string) function and returns a string for cookie
# params: s - string
# return: string


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))

# Verifys if the string/cookie is valid
# by comparing the string with its hash value
# params: h - string
# return: string


def check_secure_val(h):
    x = h.split('|')
    if len(x) == 2 and x[1] == hash_str(x[0]):
        return x[0]

# function to make salt
# params: None
# return: string


def make_salt():
    return ''.join(random.sample(string.ascii_letters, 5))

# Hash the password using username, password and salt
# params: name - string, pw - string
# return: string


def make_pw_hash(name, pw):
    salt = make_salt()
    return hashlib.sha256(name + pw + salt).hexdigest() + "|" + salt

# Validates the login data entered by the user
# params: name - string, gotPass - string, hadPass - string
# return: string


def check_pw(name, gotPass, hadPass):
    hadHash = hadPass.split('|')[0]
    salt = hadPass.split('|')[1]
    if(salt):
        gotHash = hashlib.sha256(name + gotPass + salt).hexdigest()
        logging.info(hadHash)
        logging.info(gotHash)
        return hadHash == gotHash


# Used in every get/post methods to verify if the user is logged in
# params: self - context
# return: string
def is_valid_user(self):
    userid = self.request.cookies.get('user_id', '')
    user_id = check_secure_val(userid)
    if user_id:
        return user_id
    else:
        self.response.headers.add_header('Set-Cookie',
                                         'user_id=%s; Path=/' % '')


# webapp2 handler used to handle the writes and renders
# used in all the classes
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


# data structure for handling user data
class Users(db.Model):
    username = db.StringProperty(required=True)
    password = db.StringProperty(required=True)
    email = db.StringProperty()
    created = db.DateTimeProperty(auto_now_add=True)

# data structure for handling Blog post data


class Content(db.Model):
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    userid = db.StringProperty(required=True)
    username = db.StringProperty(required=True)
    likeslist = db.ListProperty(long)
    comments = db.StringListProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

# data structure for handling comments data


class Comments(db.Model):
    userid = db.StringProperty(required=True)
    username = db.StringProperty(required=True)
    comment = db.StringProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

# Handler for Signup page


class SignupPage(Handler):

    # Regular expression to a valid username
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    # Regular expression to a valid password
    PSW_RE = re.compile(r"^.{3,20}$")
    # Regular expression to a valid email
    EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

    # function to verify validity of username
    def valid_username(self, username):
        return self.USER_RE.match(username)

    # function to verify validity of password
    def valid_password(self, password):
        return self.PSW_RE.match(password)

    # function to verify validity of email
    def valid_email(self, email):
        if email:
            return self.EMAIL_RE.match(email)
        return True

    # function to verify validity of re-entered password
    def password_match(self, password, verify):
        return password == verify

    # get method to handel the signup page when /signup is opened
    def get(self):
        # verifying the cookie
        userid = self.request.cookies.get('user_id', '')
        user_id = check_secure_val(userid)
        if user_id:
            user = Users.get_by_id(long(user_id))
            if user:
                time.sleep(0.2)
                return self.redirect("/")

        return self.render("signup.html", validUsr=True,
                           validEmail=True,
                           validPsw=True,
                           pswMatch=True,
                           validUser=False)

    # post method to handel the signup page when /signup is opened
    def post(self):
        usrname = self.request.get("username")
        psw = self.request.get("password")
        ver = self.request.get("verify")
        mail = self.request.get("email")

        validUsr = self.valid_username(usrname)
        validPsw = self.valid_password(psw)
        validEmail = self.valid_email(mail)
        pswMatch = self.password_match(psw, ver)

        # validating the data entered by the user
        # user will be added to the database once all the data is verified to
        # be valid
        if (validUsr and validPsw and validEmail and pswMatch):
            existing = Users.get_by_key_name(usrname)
            if not existing:
                data = Users(username=usrname,
                             password=make_pw_hash(usrname, psw),
                             email=mail)
                data.put()
                secure_val = make_secure_val(str(data.key().id()))
                cookie = 'user_id=%s;Path=/' % secure_val
                self.response.headers.add_header('Set-Cookie', cookie)
                time.sleep(0.2)
                return self.redirect("/")
            else:
                return self.render("signup.html", usrname="", mail="",
                                   validUsr=validUsr,
                                   validEmail=validEmail,
                                   validPsw=validPsw,
                                   pswMatch=pswMatch,
                                   userExists=True,
                                   validUser=False)
        else:
            return self.render("signup.html", usrname=usrname, mail=mail,
                               validUsr=validUsr,
                               validEmail=validEmail,
                               validPsw=validPsw,
                               pswMatch=pswMatch,
                               validUser=False)


class LoginPage(Handler):
    # get method to handel the signup page when /login is opened
    def get(self):
        # verifying the cookie
        userid = self.request.cookies.get('user_id', '')
        user_id = check_secure_val(userid)
        # if user is already logged in he/she will be directly taken
        # to the homepage
        if user_id:
            user = Users.get_by_id(long(user_id))
            if user:
                time.sleep(0.2)
                return self.redirect("/")
        return self.render("login.html", validData=True, validUser=False)

    # post method to handel the signup page when /login is opened
    def post(self):
        usrname = self.request.get("username")
        psw = self.request.get("password")

        # username and password entered by the user is verified here
        if usrname and psw:
            users = Users.all()
            our_user = None
            for user in users:
                if user.username == usrname:
                    our_user = user
                    break
            verify_psw = check_pw(our_user.username, psw, our_user.password)
            if our_user and verify_psw:
                cookie = make_secure_val(str(our_user.key().id()))
                cookie_str = 'user_id=%s; Path=/' % cookie
                self.response.headers.add_header('Set-Cookie', cookie_str)
                time.sleep(0.2)
                return self.redirect("/")
            else:
                return self.render("login.html", validData=False,
                                   validUser=False)
        else:
            return self.render("login.html", validData=False,
                               validUser=False)

# in this page all the posts are displayed, all posts made by all the users


class WelcomePage(Handler):
    # get method to handel the signup page when / is opened
    def get(self):
        # verifying the cookie
        user_id = is_valid_user(self)
        if not user_id:
            time.sleep(0.2)
            return self.redirect('/login')
        else:
            user = Users.get_by_id(long(user_id))
            if user:
                contents = Content.all()
                contents.order('-created')
                return self.render("welcome.html", user=user,
                                   validUser=True,
                                   contents=contents)
            else:
                time.sleep(0.2)
                return self.redirect('/login')

# this handler handles the user logout event


class LogoutPage(Handler):
    # get method to handel the signup page when /logout is opened
    # the get method will clear the cookie and force the user to login page
    def get(self):
        self.response.headers.add_header('Set-Cookie',
                                         'user_id=%s; Path=/' % '')
        time.sleep(0.2)
        return self.redirect("/login")

# this handeler is used to handel the event of creating a new post by a
# valid user


class NewPost(Handler):
    def render_front(self, subject="", content="", error=""):
        user_id = is_valid_user(self)
        if not user_id:
            time.sleep(0.2)
            return self.redirect('/login')
        else:
            user = Users.get_by_id(long(user_id))
            if user:
                contents = Content.all()
                return self.render("newpost.html", subject=subject,
                                   content=content,
                                   error=error,
                                   user=user,
                                   validUser=True)
            else:
                time.sleep(0.2)
                return self.redirect('/login')

    # get method to handel the signup page when /newpost is opened
    def get(self):
        # verifying the cookie
        user_id = is_valid_user(self)
        if not user_id:
            time.sleep(0.2)
            return self.redirect('/login')
        else:
            return self.render_front()

    # post method to handel the signup page when /signup is opened
    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")

        # checking the validity of entered post content
        if subject and content:
            # verifying the cookie
            user_id = is_valid_user(self)
            if not user_id:
                time.sleep(0.2)
                return self.redirect('/login')
            else:
                user = Users.get_by_id(long(user_id))
                # post the data entered by the user to datastore
                a = Content(subject=subject,
                            content=content,
                            userid=user_id,
                            username=user.username,
                            likeslist=[],
                            comments=[])
                a.put()
                time.sleep(0.2)
                return self.redirect("/" + str(a.key().id()))
        else:
            error = "All fields are required"
            return self.render_front(subject, content, error)

# this page is used to display information regarding each individual post


class SinglePost(Handler):
    def render_front(self, artId=""):
        # verifying the cookie
        user_id = is_valid_user(self)
        if not user_id:
            time.sleep(0.2)
            return self.redirect('/login')
        else:
            user = Users.get_by_id(long(user_id))
            content = Content.get_by_id(long(artId))
            if content is None:
                return self.error(404)
            # this populating comments for this pirticual post
            comments = []
            for commentid in content.comments:
                comments.append(Comments.get_by_id(long(commentid)))
            if user:
                return self.render("article.html", content=content,
                                   user=user,
                                   comments=comments,
                                   validUser=True)
            else:
                return self.redirect('/')

    # get method to handel the signup page when /(postid) is opened
    def get(self, product_id):
        # verifying the cookie
        user_id = is_valid_user(self)
        if not user_id:
            time.sleep(0.2)
            return self.redirect('/login')
        else:
            return self.render_front(artId=product_id)

    # post method to handel the signup page when /(postid) is opened
    def post(self, product_id):
        # verifying the cookie
        user_id = is_valid_user(self)
        if not user_id:
            time.sleep(0.2)
            return self.redirect('/login')
        else:
            user = Users.get_by_id(long(user_id))
            comment = self.request.get("comment")
            content = Content.get_by_id(long(product_id))
            # Handeling the comments form
            # when ever a new comment is added to a pirticular post,
            # the following code handels it
            valid_comment = False
            if comment:
                valid_comment = len(comment) >= 0 and len(comment) < 200
            if content and comment and valid_comment:
                comment = Comments(comment=comment,
                                   userid=str(user.key().id()),
                                   username=user.username)
                comment.put()
                content.comments = [str(comment.key().id())] + content.comments
                content.put()
                time.sleep(0.2)
                return self.redirect("/%s#comments" % product_id)
            else:
                return self.redirect("/%s" % product_id)


class LikePost(Handler):
    # get method to handel the signup page when /(postid)/like is opened
    def get(self, product_id):
        # verifying the cookie
        user_id = is_valid_user(self)
        if not user_id:
            time.sleep(0.2)
            return self.redirect('/login')
        else:
            content = Content.get_by_id(long(product_id))
            if content is None:
                return self.error(404)
            referrer = self.request.headers.get('referer')
            # when user hits the like button following piece of code
            # is executed
            if user_id != content.userid:
                user_id = long(user_id)
                # if user already likes the post, we remove the user
                # from likes likeslist
                # otherwise we add the user to the likeslist
                if user_id in content.likeslist:
                    content.likeslist.remove(user_id)
                else:
                    content.likeslist.append(user_id)
                content.put()
                time.sleep(0.2)
            return self.redirect("%s#%slikes" % (referrer, product_id))


class DeletePost(Handler):
    # get method to handel the signup page when /(postid)/delete is opened
    def get(self, product_id):
        # verifying the cookie
        user_id = is_valid_user(self)
        if not user_id:
            time.sleep(0.2)
            return self.redirect('/login')
        else:
            content = Content.get_by_id(long(product_id))
            if content is None:
                return self.error(404)
            # first we check for user validity and if the user is valid to
            # take this action, we go ahead and delete tha entry from
            # data store otherwise, we take the user back to the post page
            if (content.userid != user_id):
                time.sleep(0.2)
                return self.redirect('/' + product_id)
            else:
                if content and content.comments:
                    for comment_id in content.comments:
                        comment = long(comment_id)
                        c = Comments.get_by_id(comment)
                        c.delete()
                content.delete()
                time.sleep(0.2)
                return self.redirect('/')


class EditPost(Handler):
    def render_front(self, subject="", content="", error="", artId=""):
        # verifying the cookie
        user_id = is_valid_user(self)
        if not user_id:
            time.sleep(0.2)
            return self.redirect('/login')
        else:
            # renders the form to edit the post
            user = Users.get_by_id(long(user_id))
            return self.render("editpost.html", subject=subject,
                               content=content,
                               user=user,
                               error=error,
                               validUser=True)

    # get method to handel the signup page when /(postid)/edit is opened
    def get(self, product_id):
        user_id = is_valid_user(self)
        if not user_id:
            time.sleep(0.2)
            return self.redirect('/login')
        else:
            content = Content.get_by_id(long(product_id))
            if content is None:
                return self.error(404)
            if content and content.userid == user_id:
                return self.render_front(subject=content.subject,
                                         content=content.content)
            else:
                time.sleep(0.2)
                return self.redirect('/' + product_id)

    # post method to handel the signup page when /(postid)/edit is opened
    def post(self, product_id):
        # verifying the cookie
        user_id = is_valid_user(self)
        subject = self.request.get("subject")
        content = self.request.get("content")
        if not user_id:
            time.sleep(0.2)
            return self.redirect('/login')
        else:
            blogpost = Content.get_by_id(long(product_id))
            if blogpost is None:
                return self.error(404)
            if blogpost.userid != user_id:
                time.sleep(0.2)
                return self.redirect('/')
            # if the edited post is submitted by the user, new post data
            # is verified and updated in the datastore
            if subject and content and len(subject) > 0 and len(content) > 0:
                blogpost.subject = subject
                blogpost.content = content
                blogpost.put()
                time.sleep(0.2)
                return self.redirect("/" + str(blogpost.key().id()))
            else:
                error = "All fields are required"
                content = Content.get_by_id(long(product_id))
                if content and content.userid == user_id:
                    return self.render_front(subject=content.subject,
                                             content=content.content,
                                             error=error)
                else:
                    return self.error(404)


class DeleteComment(Handler):
    # get method to handel the signup page when
    # /(postid)/(commentid)/delete is opened
    def get(self, product_id, comment_id):
        # verifying the cookie
        user_id = is_valid_user(self)
        if not user_id:
            time.sleep(0.2)
            return self.redirect('/login')
        else:
            content = Content.get_by_id(long(product_id))
            comment = Comments.get_by_id(long(comment_id))
            if (content is None) or (comment is None):
                return self.error(404)
            if (comment.userid != user_id):
                time.sleep(0.2)
                return self.redirect('/' + product_id)
            else:
                content.comments.remove(str(comment_id))
                comment.delete()
                content.put()
                time.sleep(0.2)
                return self.redirect('/%s#comments' % product_id)


class EditComment(Handler):
    # get method to handel the signup page when
    # /(postid)/(commentid)/edit is opened
    def get(self, product_id, comment_id):
        # verifying the cookie
        user_id = is_valid_user(self)
        if not user_id:
            time.sleep(0.2)
            return self.redirect('/login')
        else:
            user = Users.get_by_id(long(user_id))
            content = Content.get_by_id(long(product_id))
            comment = Comments.get_by_id(long(comment_id))
            if (content is None) or (comment is None):
                return self.error(404)
            if (comment.userid != user_id):
                time.sleep(0.2)
                return self.redirect('/' + product_id)
            else:
                return self.render("editcomment.html", user=user,
                                   validUser=True,
                                   comment=comment.comment,
                                   contentid=content
                                   .key()
                                   .id())

    # post method to handel the signup page when
    # /(postid)/(commentid)/edit is opened
    def post(self, product_id, comment_id):
        # verifying the cookie
        user_id = is_valid_user(self)
        if not user_id:
            time.sleep(0.2)
            return self.redirect('/login')
        else:
            # validity of the comment is verified and if the comment is
            # completely removed, then it is deleted
            edit_comment = self.request.get("comment")
            content = Content.get_by_id(long(product_id))
            comment = Comments.get_by_id(long(comment_id))
            if (content is None) or (comment is None):
                return self.error(404)
            if len(edit_comment) == 0:
                page = "/%s/%s/delete" % (product_id, comment_id)
                return self.redirect(page)
            else:
                if (comment.userid != user_id):
                    time.sleep(0.2)
                    return self.redirect('/' + product_id)
                else:
                    comment.comment = edit_comment
                    comment.put()
                    return self.redirect("/%s#comments" % product_id)


# url handlers handled by webapp2
app = webapp2.WSGIApplication([
    ('/logout', LogoutPage),
    ('/login', LoginPage),
    ('/signup', SignupPage),
    ('/', WelcomePage),
    ('/newpost', NewPost),
    (r'/(\d+)', SinglePost),
    (r'/(\d+)/like', LikePost),
    (r'/(\d+)/delete', DeletePost),
    (r'/(\d+)/edit', EditPost),
    (r'/(\d+)/(\d+)/delete', DeleteComment),
    (r'/(\d+)/(\d+)/edit', EditComment)
], debug=False)
