# luno-csrf-node

Implement CSRF protection in your Node.js app using Luno.

## Install

```sh
npm install --save luno-csrf
```

You'll also need to install [Luno](https://github.com/lunoio/luno-node).

## Usage

```js
var Luno = require('luno');
var CSRF = require('luno-csrf');
var luno = new Luno({
  key: 'YOUR-API-KEY', // Your Luno API key
  secret: 'YOUR-SECRET-KEY', // Your Luno secret key
});
var csrf = new CSRF(luno, {
  tokenLength: 30, // token length in bytes
  useName: true, // whether to use a crypto key in the csrf property name, e.g. csrf-XXXX = token
  name: 'csrf-', // the prefix to use before the name key, or the entire key if useName is false
  nameLength: 12, // name key length in bytes
  maxTokens: 20, // maximum number of csrf tokens to store per form
  expiry: 1000 * 60 * 60 * 24, // 24 hours. time before a token becomes invalid
  expireAfterUse: true, // whether a token should become invalid after it's used (recommended)
  sessionCookieName: 'session', // the name of the session cookie which stores the session key
  sessionCookieConfig: { // session cookie config. adding secure: true when using https is recommended
    maxAge: 1209600000,
    httpOnly: true
  }
});
```

### Express

Remember to use cookieParser and bodyParser so cookies and form bodies are parsed.

```js
app.use(luno.session());

// /admin must be authenticated
app.use('/admin', function(req, res, next) {
  if (!req.user) return res.redirect('/login');
  next();
});

app.get('/admin/closeAccount', csrf.middleware('closeAccount'), function(req, res, next) {
  var form = '' +
    '<form method="POST" action="/admin/closeAccount">' +
      csrf.inputHTML(req.csrf.closeAccount) +
      '<input type="submit">' +
    '</form>';

  res.send(form);
});

app.post('/admin/closeAccount', csrf.validateMiddleware('closeAccount'), function(req, res, next) {

  // close the account
  // https://luno.io/docs#DELETE_/users/{id}
  luno.delete('/users/' + req.user.id, {}, function(err) {
    if (err) return next(err);
    res.send('Closed account!');
  });
});
```
