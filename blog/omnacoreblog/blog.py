import os
import re
import random
import hashlib
import hmac
from string import letters


import webapp2
import jinja2

import logging
import time

from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
blog_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)

secret = 'secretcode'

def render_str(template, **params):
    t = blog_env.get_template(template)
    return t.render(params)


def create_secure_value(value):
    return '%s|%s' % (value, hmac.new(secret, value).hexdigest())


def validate_secure_value(secure_value):
    value = secure_value.split('|')[0]
    if secure_value == create_secure_value(value):
        return value

def render_post(response, post):
    response.out.write('<b>' + post.title + '</b><br>')
    response.out.write(post.content)

# Code related to user functionality
def make_salt(length=5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
        h = hashlib.sha256(name + pw + salt).hexdigest()
        return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group='default'):
    return db.Key.from_path('users', group)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")

def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")

def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

def valid_email(email):
    return not email or EMAIL_RE.match(email)

# code related to the posts and comments
def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_secure_cookie(self, name, value):
        cookie_value = create_secure_value(value)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_value))

    def read_secure_cookie(self, name):
        cookie_value = self.request.cookies.get(name)
        return cookie_value and validate_secure_value(cookie_value)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        u_id = self.read_secure_cookie('user_id')
        self.user = u_id and User.by_id(int(u_id))

#
class MainPage(BlogHandler):
    def get(self):
        self.write('Hello, Udacity!')

# The user model
class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, u_id):
        return User.get_by_id(u_id, parent=users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email=None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent=users_key(),
                    name=name,
                    pw_hash=pw_hash,
                    email=email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u

class Post(db.Model):
    title = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    author_id = db.IntegerProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    last_modified = db.DateTimeProperty(auto_now=True)

    @classmethod
    def by_id(cls, pid):
        return Post.get_by_id(pid, parent=blog_key())

    def render(self, user, permalink):
        self._render_text = self.content.replace('\n', '<br>')
        post_author = User.by_id(self.author_id)
        return render_str('post.html', p = self, author = post_author)

# Render the blog front page
class BlogFront(BlogHandler):
    def get(self):
        posts = Post.all().order('-created')
        self.render('front.html', posts=posts, user=self.user)

# Render the single post view
class PostPage(BlogHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)

# Handle post creation
class NewPost(BlogHandler):
    def get(self):
        if self.user:
            self.render("newpost.html")
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        title = self.request.get('title')
        content = self.request.get('content')

        if title and content:
            p = Post(parent=blog_key(), title=title,
                     content=content, author_id=self.user.key().id())
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))
        else:
            error = "title and content, please!"
            self.render("newpost.html", title=title, content=content,
                        error=error)

# Handle post edits
class EditPost(BlogHandler):
    def get(self):
        if self.user:
            post_id = int(self.request.get('post_id'))
            post = Post.by_id(post_id)

            if not post:
                self.error(404)
                return

            if post.author_id != self.user.key().id():
                self.redirect("/blog")

            self.render("editpost.html", post=post)
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        post_id = int(self.request.get('post_id'))
        post = Post.by_id(post_id)

        if post.author_id != self.user.key().id():
                self.redirect("/blog")

        title = self.request.get('title')
        content = self.request.get('content')

        if title and content:
            post.title = title
            post.content = content

            post.put()
            self.redirect('/blog/%s' % str(post.key().id()))
        else:
            error = "title and content, please!"
            self.render("editpost.html", post=post,
                        error=error)

# Handle post deletion
class DeletePost(BlogHandler):
    def get(self):
        if self.user:
            post_id = int(self.request.get('post_id'))
            post = Post.by_id(post_id)

            if not post:
                self.error(404)
                return

            if post.author_id != self.user.key().id():
                self.redirect("/blog")

            self.render("deletepost.html", post=post)
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        post_id = int(self.request.get('post_id'))
        post = Post.by_id(post_id)

        if post.author_id != self.user.key().id():
                self.redirect("/blog")

        post.delete()
        time.sleep(0.5)
        self.redirect('/blog')

class Comment(db.Model):
    author_id = db.IntegerProperty(required=True)
    post_id = db.IntegerProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, pid):
        return Comment.get_by_id(pid, parent=blog_key())

    def render(self, user):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("comment.html", c=self, user=user,
                          author=User.by_id(int(self.author_id)))

# Handle comment creation
class NewComment(BlogHandler):
    def post(self):
        if not self.user:
            self.redirect('/blog')

        post_id = int(self.request.get('post_id'))
        content = self.request.get('content')

        if post_id and content:
            c = Comment(parent=blog_key(), post_id=post_id, content=content,
                        author_id=self.user.key().id())
            c.put()

        self.redirect('/blog/%s' % str(post_id))

# Handle comment edit
class EditComment(BlogHandler):
    def get(self):
        if self.user:
            comment_id = int(self.request.get('comment_id'))
            comment = Comment.by_id(comment_id)

            if not comment:
                self.error(404)
                return

            if comment.author_id != self.user.key().id():
                self.redirect("/blog")

            self.render("edit-comment.html", comment=comment)
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        comment_id = int(self.request.get('comment_id'))
        comment = Comment.by_id(comment_id)

        if comment.author_id != self.user.key().id():
                self.redirect("/blog")

        content = self.request.get('content')

        if content:
            comment.content = content

            comment.put()
            self.redirect('/blog/%s' % str(comment.post_id))
        else:
            error = "content, please!"
            self.render("edit-comment.html", comment=comment,
                        error=error)

# Handle comment deletion
class DeleteComment(BlogHandler):
    def get(self):
        if self.user:
            comment_id = int(self.request.get('comment_id'))
            comment = Comment.by_id(comment_id)

            if not comment:
                self.error(404)
                return

            if comment.author_id != self.user.key().id():
                self.redirect("/blog")

            self.render("delete-comment.html", comment=comment)
        else:
            self.redirect("/login")

    def post(self):
        if not self.user:
            self.redirect('/blog')

        comment_id = int(self.request.get('comment_id'))
        comment = Comment.by_id(comment_id)

        if comment.author_id != self.user.key().id():
                self.redirect("/blog")

        comment.delete()
        time.sleep(0.5)
        self.redirect('/blog/%s' % str(comment.post_id))


class Signup(BlogHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        if not valid_username(self.username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(self.password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif self.password != self.verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(self.email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
            self.done()

    def done(self, *a, **kw):
        raise NotImplementedError


class Register(Signup):
    def done(self):
        # make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username=msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/blog')

# Handle user account login
class Login(BlogHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/blog')
        else:
            msg = 'Invalueid login'
            self.render('login-form.html', error=msg)

# Handle user account logout
class Logout(BlogHandler):
    def get(self):
        self.logout()
        self.redirect('/blog')

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/blog/?', BlogFront),
                               ('/blog/([0-9]+)', PostPage),
                               ('/blog/newpost', NewPost),
                               ('/blog/editpost', EditPost),
                               ('/blog/newcomment', NewComment),
                               ('/blog/deletepost', DeletePost),
                               ('/blog/editcomment', EditComment),
                               ('/blog/deletecomment', DeleteComment),
                               ('/signup', Register),
                               ('/login', Login),
                               ('/logout', Logout),
                               ],
                              debug=True)
