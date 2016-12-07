import webapp2
import random
import hashlib
import hmac
import string
import re
import os
import jinja2
import logging
from google.appengine.ext import db

SECRET = 'forgot'


template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(
    loader=jinja2.FileSystemLoader(template_dir),
    autoescape=True)

def users_key(group='default'):
    return db.Key.from_path('users', group)

def blog_key(name='default'):
    return db.Key.from_path('blogs', name)

class User(db.Model):
    name = db.StringProperty(required=True)
    pw_hash = db.StringProperty(required=True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent=users_key())

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
    author = db.StringProperty()
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    modified = db.DateTimeProperty(auto_now=True)
    votes = db.IntegerProperty(default=0)
    voted = db.StringProperty()

    def render(self, loggedIn):
        self._render_text = self.content.replace('\n', '<br>')
        return render_env("post.html", p=self, loggedIn=loggedIn)

class Comment(db.Model):
    author = db.StringProperty()
    post_id = db.StringProperty(required=True)
    comment = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now=True)

def make_salt(length=5):
    return ''.join(random.choice(string.letters) for x in xrange(length))

def make_pw_hash(name, pw, salt=None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(SECRET, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r'^[\S]+@[\S]+\.[\S]+$')

def valid_username(username):
    return username and USER_RE.match(username)

def valid_password(password):
    return password and PASS_RE.match(password)

def valid_email(email):
    return not email or EMAIL_RE.match(email)

def render_env(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class BaseHandler(webapp2.RequestHandler):
    """ Base handler for all classes """
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_tmpl(self, template, **params):
        params['user'] = self.user
        return render_env(template, **params)

    def render(self, template, **kw):
        self.write(self.render_tmpl(template, **kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, cookie):
        cookie_val = self.request.cookies.get(cookie)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))

class MainPageHandler(BaseHandler):
    def get(self):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY votes DESC LIMIT 10")
        if self.user:
            self.render('front.html',
                        posts=posts,
                        loggedIn=self.user)
        else:
            self.redirect('/signup')

class NewPostHandler(BaseHandler):
    def get(self):
        if self.user:
            self.render("newpost.html", loggedIn=self.user)
        else:
            self.redirect("/")

    def post(self):
        if not self.user:
            self.redirect("/login")
        else:
            author = self.user.name
            subject = self.request.get('subject')
            content = self.request.get('content')

            if subject and content:
                p = Post(parent=blog_key(),
                         author=author,
                         subject=subject,
                         content=content)

                p.put()
                post_id = str(p.key().id())
                self.key = post_id

                self.redirect('/')
            else:
                error = "Please Fill In All Fields"
                self.render("newpost.html",
                            author=author,
                            subject=subject,
                            content=content,
                            error=error,
                            loggedIn=self.user)

class NewCommentHandler(BaseHandler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)
        if not self.user:
            self.redirect("/login")
        else:
            comments = db.GqlQuery("SELECT * FROM Comment " +
                                   "WHERE post_id = :1 " +
                                   "ORDER BY created DESC",
                                   post_id)

            self.render("newcomment.html",
                        post=post,
                        comments=comments,
                        loggedIn=self.user)

    def post(self, post_id):
        if not self.user:
            self.redirect("/login")
        else:
            posts = db.GqlQuery(
                "SELECT * FROM Post ORDER BY votes DESC LIMIT 10")
            author = self.user.name
            comment = self.request.get('comment')

            if comment:
                c = Comment(author=author,
                            post_id=post_id,
                            comment=comment)
                c.put()

            self.render('front.html', posts=posts, loggedIn=self.user)

class EditPostHandler(BaseHandler):
    def get(self):
        if not self.user:
            self.redirect("/login")
        else:
            post_id = self.request.get('id')
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if self.user.name == post.author:
                self.render('editpost.html', p=post, loggedIn=self.user)
            else:
                msg = "You are not authorized to edit this post."
                self.render('message.html', msg=msg)

    def post(self):
        post_id = self.request.get('id')
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        p = db.get(key)

        if self.user.name != p.author:
            self.redirect("/login")
        else:
            new_content = self.request.get('editpost')
            if new_content:
                p.content = new_content
                p.put()
                self.redirect('/')
            else:
                error = "Content cannot be empty."
                self.render("editpost.html", p=p, error=error)

class DeletePostHandler(BaseHandler):
    def get(self):
        if not self.user:
            self.redirect("/login")
        else:
            post_id = self.request.get('id')
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)

            if self.user.name == post.author:
                db.delete(key)
                self.redirect('/')
            else:
                self.redirect('/')

class EditCommentHandler(BaseHandler):
    def get(self):
        if not self.user:
            self.redirect("/login")
        else:
            comment_id = self.request.get('id')
            key = db.Key.from_path('Comment', int(comment_id))
            comment = db.get(key)

            self.render("editcomment.html",
                        comment=comment,
                        loggedIn=self.user)

    def post(self):
        comment_id = self.request.get('id')
        edit_comment = self.request.get('editcomment')
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        if self.user.name != comment.author:
            self.redirect("/login")
        else:
            if edit_comment:
                comment.comment = edit_comment
                comment.put()
                self.redirect("/")
            else:
                self.redirect("/editcomment?id="+comment_id)

class DeleteCommentHandler(BaseHandler):
    def get(self):
        comment_id = self.request.get('id')
        key = db.Key.from_path('Comment', int(comment_id))
        comment = db.get(key)
        if not self.user:
            self.redirect("/login")
        else:
            if self.user.name != comment.author:
                self.redirect("/login")
            else:
                db.delete(key)
                self.redirect("/")

class UpvoteHandler(BaseHandler):
    def get(self):
        if self.user:
            logging.info(self.user.name + ',')
            post_id = self.request.get('id')
            key = db.Key.from_path('Post', int(post_id), parent=blog_key())
            post = db.get(key)
            if post.voted:
                voters = post.voted.split(',')
                if self.user.name not in voters:
                    post.votes += 1
                    post.voted += (self.user.name + ',')
                    post.put()
                    self.redirect("/")
                else:
                    self.redirect("/")
            else:
                post.votes += 1
                post.voted = (self.user.name + ',')
                post.put()
                self.redirect("/")
        else:
            self.redirect('/login')

class SignUpHandler(BaseHandler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        errors = False
        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.confirm = self.request.get('confirm')
        self.email = self.request.get('email')

        params = dict(username=self.username,
                      email=self.email)

        u = User.by_name(self.username)
        if u:
            params['error_username1'] = 'Username Already Exists'
            errors = True

        if not valid_username(self.username):
            params['error_username2'] = "Invalid Username."
            errors = True

        if not valid_password(self.password):
            params['error_pass'] = "Invalid Password."
            errors = True
        elif self.password != self.confirm:
            params['error_confirm'] = "Passwords Do Not Match."
            errors = True

        if not valid_email(self.email):
            params['error_email'] = "Invalid Email."
            errors = True

        if errors:
            self.render('signup-form.html', **params)

        else:
            u = User.register(self.username, self.password, self.email)
            u.put()
            self.login(u)
            self.redirect('/')

class LoginHandler(BaseHandler):
    def get(self):
        self.render('login-form.html')

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect('/')
        else:
            msg = "Invalid Username/Password"
            self.render('login-form.html', error=msg)

class LogoutHandler(BaseHandler):
    def get(self):
        self.logout()
        self.redirect('/login')

url_map = [
    ('/', MainPageHandler),
    ('/comment/(\d+)', NewCommentHandler),
    ('/newpost', NewPostHandler),
    ('/edit', EditPostHandler),
    ('/delete', DeletePostHandler),
    ('/editcomment', EditCommentHandler),
    ('/deletecomment', DeleteCommentHandler),
    ('/upvote', UpvoteHandler),
    ('/signup', SignUpHandler),
    ('/login', LoginHandler),
    ('/logout', LogoutHandler),
]

app = webapp2.WSGIApplication(url_map, debug=True)
