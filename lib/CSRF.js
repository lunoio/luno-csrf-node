'use strict';
var crypto = require('crypto');
var scmp = require('scmp');

var CSRF = module.exports = function(luno, config) {
  var self = this;

  self.config = {
    tokenLength: 30,
    useName: true,
    name: 'csrf-',
    nameLength: 12,
    maxTokens: 20,
    expiry: 1000 * 60 * 60 * 24, // 24 hours
    expireAfterUse: true,
    sessionCookieName: 'session',
    sessionCookieConfig: {
      maxAge: 1209600000,
      httpOnly: true
    }
  };

  for (var i in config) self.config[i] = config[i];

  self.luno = luno;
};


/**
 * Generate CSRF credentials for the given forms
 * @date   2016-02-29
 * @param  {Object}   session Luno Session model, e.g. { type: 'session', id: 'sess_X' ...}
 * @param  {Array or String}  forms The forms to generate tokens for, e.g. [ 'signup' ] or 'login'
 * @param  {Function} cb Callback
 */
CSRF.prototype.generate = function(session, forms, cb) {
  var self = this;

  var sessID = (session || {}).id;

  var details = {};

  self._expire(session, details);

  var resp = {};

  forms = Array.isArray(forms) ? forms : [ forms ];
  for (var i = 0; i < forms.length; i++) {
    var f = forms[i];
    var arr = session && session.details.csrf && session.details.csrf[f] || [];
    if (arr.length >= self.config.maxTokens) arr.shift();

    var creds = self.generateCredentials();
    arr.push(creds);
    resp[f] = creds;
    details[f] = arr;
  }

  self.save(session, details, function(err, sess, created) {
    if (err) return cb(err);
    cb(err, resp, sess, created);
  });
};

/**
 * Generate the crypto-secure CSRF token and name
 * @date   2016-02-29
 * @return {Object}   Name and token, with the creation time
 */
CSRF.prototype.generateCredentials = function() {
  var self = this;

  var creds = {};
  if (self.config.useName) {
    creds.name = crypto.randomBytes(self.config.nameLength).toString('base64');
  }
  creds.token = crypto.randomBytes(self.config.tokenLength).toString('base64');
  creds.created = Date.now();

  return creds;
};

/**
 * Remove all expired credentials from the CSRF object
 * @date    2016-02-29
 * @param   {Object}    session Luno Session model
 * @param   {Object}    details Details to save back to the session
 * @private
 */
CSRF.prototype._expire = function(session, details) {
  var self = this;
  if (!session) return;
  var d = session.details.csrf;
  if (!d) return;

  for (var i in d) {
    var l = d[i];
    var j = l.length;
    while (j--) {
      if (l[j].created < Date.now() - self.config.expiry) {
        l.splice(j, 1);
        details[i] = l;
      }
    }
  }
};

/**
 * Save the given details to the session
 * @date   2016-02-29
 * @param  {Object}   session Luno session model
 * @param  {Object}   details CSRF credentials to save
 * @param  {Function} cb      Callback for when the credentials have been saved
 */
CSRF.prototype.save = function(session, details, cb) {
  var self = this;

  var body = {
    details: {
      csrf: details
    }
  };

  if (!session || !session.id) {
    // create new anonymous session
    self.luno.post('/sessions', {}, body, function(err, sess) {
      if (err) return cb(err);
      cb(err, sess, true);
    });
  } else {
    // edit the current session
    self.luno.patch('/sessions/' + session.id, {}, body, function(err) {
      if (err) return cb(err);
      cb(err, session, false);
    });
  }
};

/**
 * Return a middleware function to genererate CSRF credentials for the given forms
 * @date   2016-02-29
 * @param  {Array or String}   forms Forms to generate credentials for
 * @return {Function}          Middleware function
 */
CSRF.prototype.middleware = function(forms) {
  var self = this;

  return function(req, res, next) {
    self.generate(req.session, forms, function(err, csrf, sess, created) {
      if (err) return next(err);

      req.csrf = csrf;
      req.session = sess;
      res.cookie(self.config.sessionCookieName, sess.key, self.config.sessionCookieConfig);
      next();
    });
  };
};

/**
 * Return a middleware function to validate the submitted CSRF credentials for the form
 * @date   2016-02-29
 * @param  {String}   form Form to validate credentials for
 * @return {Function}        Middlware function
 */
CSRF.prototype.validateMiddleware = function(form) {
  var self = this;
  return function(req, res, next) {
    self.validateReq(form, req, function(err, success) {
      if (!success) return next(new Error('Invalid CSRF'));
      next();
    });
  };
};

/**
 * Return a middleware function to validate the submitted CSRF credentials for the form
 * (without waiting for invalidation to save - could be vulnerable to race conditions in some cases)
 * @date   2016-02-29
 * @param  {String}   form Form to validate credentials for
 * @return {Function}        Middlware function
 */
CSRF.prototype.validateMiddlewareQuick = function(form) {
  var self = this;
  return function(req, res, next) {
    if (!self.validateReq(form, req)) return next(new Error('Invalid CSRF'));
    next();
  };
};

/**
 * Validate the submitted CSRF credentials
 * @date   2016-02-29
 * @param  {String}   form Form to validate credentials for
 * @param  {Object}   req  Request object from Express/HTTP
 * @param  {Function} cb   Callback (optional) for when the session has been updated
 * @return {Boolean}        Whether the CSRF credentials are valid
 */
CSRF.prototype.validateReq = function(form, req, cb) {
  var self = this;
  return self.validate(form, req.session, req.body, cb);
};


/**
 * Validate CSRF credentials
 * @date   2016-02-29
 * @param  {String}   form    Form to validate credentials for
 * @param  {Object}   session Luno Session model
 * @param  {Object}   body    Request body
 * @param  {Function} cb      Callback (optional) for when the session has been updated
 * @return {Boolean}          Whether the CSRF credentials are valid
 */
CSRF.prototype.validate = function(form, session, body, cb) {
  var self = this;

  if (!cb) cb = function(){};

  var csrf = session && session.details && session.details.csrf && session.details.csrf[form];
  if (!csrf) {
    cb(null, false);
    return false;
  }

  var details = {};

  // ensure expired tokens aren't here
  self._expire(session, details);
  csrf = details[form] || csrf;

  for (var i = 0; i < csrf.length; i++) {
    var c = csrf[i];

    var name = self.config.name;
    if (self.config.useName && c.name) name += c.name;
    if (!scmp(body[name], c.token)) {
      continue;
    }

    if (!self.config.expireAfterUse) {
      cb(null, true, session);
      return true;
    }

    // remove the matched item
    csrf.splice(i, 1);
    details[form] = csrf;

    self.save(session, details, function(err, sess) {
      if (err) return cb(err);
      cb(err, true, sess);
    });

    return true;
  }

  cb(null, false);
  return false;
};

/**
 * Return the HTML for the CSRF input
 * @date   2016-02-29
 * @param  {Object}   creds CSRF credentials to render
 * @return {String}         HTML string of the input
 */
CSRF.prototype.inputHTML = function(creds) {
  var self = this;
  var name = self.config.name;
  if (self.config.useName && creds.name) name += creds.name;
  return '<input type="hidden" name="' + name + '" value="' + creds.token + '">';
};
