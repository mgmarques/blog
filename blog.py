###Blog for CS 253###

import os
import re
from string import letters
import webapp2
import jinja2
import logging
from datetime import datetime

from google.appengine.api import memcache
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

def render_str(template, **params):
	t = jinja_env.get_template(template)
	return t.render(params)							   
							   
class Handler(webapp2.RequestHandler):
	def write(self, *a, **kw):
		self.response.out.write(*a, **kw)
		
	def render_str(self, template, **params):
		t = jinja_env.get_template(template)
		return t.render(params)

	def render(self, template, **kw):
		self.response.out.write(self.render_str(template, **kw))

###Blog###

#memcache#
def top_posts(update = False):
	key = 'top'
	posts = memcache.get(key)
	if posts is None or update:
		logging.error("DB QUERY")
		posts = db.GqlQuery("SELECT * FROM BlogPost ORDER BY created DESC LIMIT 10")
		posts = list(posts)
		memcache.set(key, posts)
		memcache.set('time', datetime.now())
	return posts

def perma_post(id):
	post = memcache.get(id)
	if post is None:
		post = BlogPost.get_by_id(int(id))
		memcache.set(id, (post, datetime.now()))
		return post
	return post[0]

#Last Modified#
def top_modified():
	modified = memcache.get('time')
	if modified:
		return datetime.now() - modified
	else:
		return datetime.now() - datetime.now()

def perma_modified(id):
	modified = memcache.get(id)
	if modified:
		return datetime.now() - modified[1]
	else:
		return datetime.now() - datetime.now()	

#Blog Post Entity#
class BlogPost(db.Model):
	subject = db.StringProperty(required = True)
	content = db.TextProperty(required = True)
	created = db.DateTimeProperty(auto_now_add = True)
	last_modified = db.DateTimeProperty(auto_now = True)

	def render(self):
		self._render_text = self.content.replace('\n', '<br>')
		return render_str("post.html", p = self)

#Main Handlers#		
class MainPage(Handler):
	def get(self):
		posts = top_posts()
		modified = top_modified()
		self.render("front.html", posts=posts, modified=modified)

class NewPost(Handler):
	def render_front(self, subject="", content="", error=""):
		self.render("newpost.html", subject=subject, content=content, error=error)

	def get(self):
		self.render_front()
		
	def post(self):
		subject = self.request.get("subject")
		content = self.request.get("content")
		
		if subject and content:
			a = BlogPost(subject=subject, content=content)
			a.put()
			top_posts(True)
			perma_post(str(a.key().id()))
			self.redirect("/blog/%s" % str(a.key().id()))
		else:
			error = "Both a subject and content are required."
			self.render_front(subject, content, error)

class Permanentlink(Handler):
	def get(self, permanentlink):
		post = perma_post(str(permanentlink))
		modified = perma_modified(str(post.key().id()))
		
		if not post:
			self.error(404)
			return
		
		self.render("permanentlink.html", post=post, modified=modified)

class Flush(Handler):
	def get(self):
		#flushes memcache
		memcache.flush_all()
		self.redirect("/blog")
		
###Registration###
	
import hashlib
import random
import hmac

#Password Validation#
def make_salt():
	return ''.join(random.choice(letters) for x in xrange(5))
	
def make_pw_hash(name, pw, salt=None):
	if not salt:
		salt = make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return '%s,%s' % (h, salt)

def valid_pw(name, pw, h):
	salt = h.split(',')[1]
	if h == make_pw_hash(name, pw, salt):
		return True

#Username Cookies#
SECRET = 'imsosecret'
def hash_str(s):
	return hmac.new(SECRET, s).hexdigest()

def make_secure_val(s):
	return "%s|%s" % (s, hash_str(s))
	
def check_secure_val(h):
	val = h.split('|')[0]
	if h == make_secure_val(val):
		return True

#Signup Form Validation#	
USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
def valid_username(username):
    return username and USER_RE.match(username)

PASS_RE = re.compile(r"^.{3,20}$")
def valid_password(password):
    return password and PASS_RE.match(password)

EMAIL_RE  = re.compile(r'^[\S]+@[\S]+\.[\S]+$')
def valid_email(email):
    return not email or EMAIL_RE.match(email)
	
#User Entity#
class Users(db.Model):
	username = db.StringProperty(required = True)
	password = db.StringProperty(required = True)
	email = db.EmailProperty
	created = db.DateTimeProperty(auto_now_add = True)

#Signup#	
class Signup(Handler):
    def get(self):
        self.render("signup-form.html")

    def post(self):
        have_error = False
        username = self.request.get('username')
        password = self.request.get('password')
        verify = self.request.get('verify')
        email = self.request.get('email')

        params = dict(username = username,
                      email = email)

        if not valid_username(username):
            params['error_username'] = "That's not a valid username."
            have_error = True

        if not valid_password(password):
            params['error_password'] = "That wasn't a valid password."
            have_error = True
        elif password != verify:
            params['error_verify'] = "Your passwords didn't match."
            have_error = True

        if not valid_email(email):
            params['error_email'] = "That's not a valid email."
            have_error = True

        if have_error:
            self.render('signup-form.html', **params)
        else:
			check_user = db.GqlQuery("SELECT * FROM Users WHERE username='%s'" % username)
			if check_user.count(1) > 0:
				self.render('signup-form.html', username=username, error_username='That user already exists.')
			else:
				#Make salted pw, add to Users
				salted_pw = make_pw_hash(username, password)
				u = Users(username=username, password=salted_pw, email=email)
				u.put()
				
				#Make user_id cookie
				new_cookie_val = make_secure_val(str(u.key().id()))
				self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % new_cookie_val)
				
				self.redirect("/blog/welcome")

class Welcome(Handler):
    def get(self):
		user_cookie_str = self.request.cookies.get('user_id')
		if not user_cookie_str:
			self.redirect('/blog/signup')
		else:
			cookie_val = check_secure_val(user_cookie_str)
			if cookie_val:
				id = user_cookie_str.split('|')[0]
				user = Users.get_by_id(int(id))
				self.render('welcome.html', username=user.username)
			else:
				self.redirect('/blog/signup')

##Login-Logout##

class Login(Handler):
	def get(self):
		self.render('login.html')
	
	def post(self):
		have_error = False
		username = self.request.get('username')
		password = self.request.get('password')
	
		params = dict(username = username)
	
		check_user = db.GqlQuery("SELECT * FROM Users WHERE username='%s'" % username)
		result = check_user.get()
		if check_user.count(1) == 0:
			params['error_user'] = "User does not exist."
			self.render('login.html', **params)
			return
		
		if not valid_pw(username, password, result.password):
			params['error_login'] = "Invalid login."
			self.render('login.html', **params)
			return
		
		new_cookie_val = make_secure_val(str(result.key().id()))
		self.response.headers.add_header('Set-Cookie', 'user_id=%s; Path=/' % new_cookie_val)
		self.redirect("/blog/welcome")

class Logout(Handler):
	def get(self):
		self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
		self.redirect("/blog/signup")
		

##JSON##
import json
class MainJSON(Handler):
	def get(self):
		self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
		iposts = db.GqlQuery("SELECT * FROM BlogPost ORDER BY created DESC LIMIT 10")
		obj = []
		for post in posts:
			obj.append({
			'subject': post.subject,
			'content': post.content,
			'created': post.created.strftime("%a %b %d %H:%M:%S %Y"),
			'last_modified': post.last_modified.strftime("%a %b %d %H:%M:%S %Y")
			})
		self.response.out.write(json.dumps(obj))

class PermaJSON(Handler):
	def get(self, permanentlink):
		self.response.headers['Content-Type'] = 'application/json; charset=UTF-8'
		post = BlogPost.get_by_id(int(permanentlink))
		obj = {
			'subject': post.subject,
			'content': post.content,
			'created': post.created.strftime("%a %b %d %H:%M:%S %Y"),
			'last_modified': post.last_modified.strftime("%a %b %d %H:%M:%S %Y")
			}
		self.response.out.write(json.dumps(obj))

		
app = webapp2.WSGIApplication([('/blog/?', MainPage),
                               ('/blog/newpost', NewPost),
							   ('/blog/([0-9]+)', Permanentlink),
							   ('/blog/signup', Signup),
							   ('/blog/login', Login),
							   ('/blog/logout', Logout),
							   ('/blog/welcome', Welcome),
							   ('/blog/.json', MainJSON),
							   ('/blog/([0-9]+).json', PermaJSON),
							   ('/blog/flush', Flush)],
                              debug=True)
