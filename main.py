import os
import re
import random
import hashlib
import hmac
import logging
import json
import time
from datetime import datetime, timedelta
from string import letters


import webapp2
import jinja2

from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)
secret = 'puta'

def age_set(key, val):
    save_time = datetime.utcnow()
    memcache.set(key, (val, save_time))
    p = WikiPost(parent = WikiPost.parent_key(key), content = val.content, author = val.author)
    p.put()

def age_get(key):
    r = memcache.get(key)
    if r: 
	val, save_time = r
	age = (datetime.utcnow() - save_time).total_seconds()
    else: 
	val = WikiPost.by_path(key).get()
	age = 0
	#if not val:
	 #   val, age = None, 0
    return val, age

def add_post(post):
    post.put()
    time.sleep(.5)
    print post.key().name(), ' is the key name'
    return str(post.key().name())

def blog_key(name = 'default'):
    return db.Key.from_path('blogs', name)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

def make_secure_val(val):
    return '%s|%s' % (val, hmac.new(secret, val).hexdigest())

def check_secure_val(secure_val):
    val = secure_val.split('|')[0]
    if secure_val == make_secure_val(val):
        return val

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)

class BlogHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))
    def render_json(self, d):
        json_txt = json.dumps(d)
        self.response.headers['Content-Type'] = 'application/json; 		charset=UTF-8'
        self.write(json_txt)

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))
    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def time(self, post_time):
	return time.time() - post_time

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))
	if self.request.url.endswith('.json'):
            self.format = 'json'
        else:
            self.format = 'html'

##### user stuff
def make_salt(length = 5):
    return ''.join(random.choice(letters) for x in xrange(length))

def make_pw_hash(name, pw, salt = None):
    if not salt:
        salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return '%s,%s' % (salt, h)

def valid_pw(name, password, h):
    salt = h.split(',')[0]
    return h == make_pw_hash(name, password, salt)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def by_id(cls, uid):
        return User.get_by_id(uid, parent = users_key())

    @classmethod
    def by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def register(cls, name, pw, email = None):
        pw_hash = make_pw_hash(name, pw)
        return User(parent = users_key(),
                    name = name,
                    pw_hash = pw_hash,
                    email = email)

    @classmethod
    def login(cls, name, pw):
        u = cls.by_name(name)
        if u and valid_pw(name, pw, u.pw_hash):
            return u


class Signup(BlogHandler):
    def get(self):
	next_url = self.request.headers.get('referer', '/')
        self.render("signup-form.html", next_url = next_url)

    def post(self):
        have_error = False

	next_url = str(self.request.get("next_url"))
	if not next_url or next_url.startswith('/login'):
	    next_url = '/' 

        self.username = self.request.get('username')
        self.password = self.request.get('password')
        self.verify = self.request.get('verify')
        self.email = self.request.get('email')

        params = dict(username = self.username,
                      email = self.email)

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
	    u = User.register(self.username, self.password)
	    u.put()

            self.login(u)
	    self.redirect(next_url)

class WikiPost(db.Model):
    post_id = db.StringProperty()
    content = db.TextProperty(required = True)
    author = db.ReferenceProperty(User, required = True)
    created = db.DateTimeProperty(auto_now_add = True)
    last_modified = db.DateTimeProperty(auto_now = True)

    @staticmethod
    def parent_key(path):
	return db.Key.from_path('/root' + path, 'pages')

    @classmethod
    def by_path(cls, path):
	q = cls.all()
	q.ancestor(cls.parent_key(path))
	q.order("-created")
	return q

    @classmethod
    def by_id(cls, page_id, path):
	return cls.get_by_id(page_id, cls.parent_key(path))

    def render(self):
        self._render_text = self.content.replace('\n', '<br>')
        return render_str("post.html", p = self)

    def as_dict(self):
        time_fmt = '%c'
        d = {'post_id': self.post_id,
	     'author': self.author,  
	     'content': self.content,
             'created': self.created.strftime(time_fmt),
             'last_modified': self.last_modified.strftime(time_fmt)}
        return d

class HistoryPage(BlogHandler):
    def get(self, post_id):
	if not self.user:
	    self.redirect('/login')
	print post_id, 'get method edit page'
	p, age = age_get(post_id)
        if p:
   	    print 'got p'
	    content = str(p.content)
	    self.render('edit-form.html', content = content, user = self.user, post_id = post_id)
	else: 
	    self.render('edit-form.html', content = "")
                               
class EditPage(BlogHandler):
    def get(self, post_id):
	if not self.user:
	    self.redirect('/login')
	print post_id, 'get method edit page'
	p, age = age_get(post_id)
        if p:
   	    print 'got p'
	    content = str(p.content)
	    self.render('edit-form.html', content = content, user = self.user, edit_view = "view", post_id = post_id)
	else: 
	    self.render('edit-form.html', content = "")
    def post(self, post_id):
	print post_id, 'post method editpage'
        content = self.request.get('content')
	p = WikiPost(content = content, author = self.user)        
	print content, "has this content"
	age_set(post_id, p)
	self.render('edit-form.html', content = content, user = self.user, edit_view = "view", post_id = post_id)
	self.redirect(post_id)

def get_wiki(post_id):
        q = db.GqlQuery(Post)
	q.filter('post_id =', 'post_id')
	return q.run()
	
class WikiPage(BlogHandler):
    def get(self, post_id):
	print post_id, 'get method wiki page'
	p, age = age_get(post_id)
        if p and p.author:
   	    print 'got p'
	    content = str(p.content)
	    author = p.author
	    last_modified = p.last_modified
	    self.render('wiki.html', content = content, user = self.user,
	        last_modified = last_modified, post_id = "_edit" + post_id, 			edit_view = "edit", author = author)
	elif p:
	    print 'got p'
	    content = str(p.content)
	    author = self.user
	    self.render('wiki.html', content = content, user = self.user, post_id = "_edit" + post_id, edit_view = "edit", author = author)
	else:
	    if self.user:
		print 'is user'
		self.redirect('/_edit%s' % post_id)
	    else: 
	        self.render('wiki.html', content = "", user = self.user, post_id = "_edit" + post_id, edit_view = "edit", author = "")
    def post(self, post_id):
	print post_id, 'post method wikipage'
	
        content = self.request.get('content')
	p = WikiPost(content = content)        
	print content, "has this content"
	age_set(post_id, p)
	self.render('wiki.html', content = content, user = self.user, post_id = post_id)

class Login(BlogHandler):
    def get(self):
	next_url = self.request.headers.get('referer', '/')
        self.render('login-form.html', next_url = next_url)

    def post(self):
        username = self.request.get('username')
        password = self.request.get('password')

	next_url = str(self.request.get('next_url'))
	print 'next is', next_url
	if not next_url or next_url.startswith('/login'):
	    next_url = '/'

        u = User.login(username, password)
        if u:
            self.login(u)
            self.redirect(next_url)
        else:
            msg = 'Invalid login'
            self.render('login-form.html', error = msg)

class Logout(BlogHandler):
    def get(self):
	next_url = self.request.headers.get('referer', '/')
        self.logout()
        self.redirect(next_url)

class Register(Signup):
    def done(self):
        #make sure the user doesn't already exist
        u = User.by_name(self.username)
        if u:
            msg = 'That user already exists.'
            self.render('signup-form.html', error_username = msg)
        else:
            u = User.register(self.username, self.password, self.email)
            u.put()

            self.login(u)
            self.redirect('/home')

class Flush(BlogHandler):
    def get(self):
	memcache.flush_all()
	self.redirect('/')


        

PAGE_RE = r'(/(?:[a-zA-Z0-9_-]+/?)*)'
app = webapp2.WSGIApplication([('/signup', Register),
			       ('/login', Login),
			       ('/flush', Flush),
			       ('/logout', Logout),
			       ('/_edit' + PAGE_RE, EditPage),
			       ('/_history' + PAGE_RE, HistoryPage),
			       (PAGE_RE, WikiPage),
                               ],
                              debug=True)
