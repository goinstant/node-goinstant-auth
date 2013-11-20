# node-goinstant-auth

GoInstant Authentication for Your Node.js Application

[![Build Status](https://travis-ci.org/goinstant/node-goinstant-auth.png?branch=master)](https://travis-ci.org/goinstant/node-goinstant-auth) [![Coverage Status](https://coveralls.io/repos/goinstant/node-goinstant-auth/badge.png?branch=master)](https://coveralls.io/r/goinstant/node-goinstant-auth?branch=master)

This is an implementation of JWT tokens consistent with what's specified in the
[GoInstant Users and Authentication
Guide](https://developers.goinstant.com/v1/guides/users_and_authentication.html).

This library is not intended as a general-use JWT library; see JWT-php for
that. At the time of this writing, GoInstant supports the [JWT IETF draft
version 8](https://tools.ietf.org/html/draft-ietf-oauth-json-web-token-08).

# Installation

```sh
npm install --save goinstant-auth
```

# Usage

Construct a signer with your goinstant application key. The application key
should be in base64url or base64 string format. To get your key, go to [your
goinstant dashboard](https://goinstant.com/dashboard) and click on your App.

:warning: **Remember, the Secret Key needs to be treated like a password!**
Never share it with your users!

```js
  var Signer = require('goinstant-auth').Signer;
  var signer = new Signer(yourGoInstantAppKey);
```

You can then use this `signer` to create as many tokens as you want. The
`domain` parameter should be replaced with your website's domain. Groups are
optional.

```js
  signer.sign({
    domain: 'example.com', // TODO: replace me
    id: user.id,
    displayName: user.fullName(),
    groups: [
      {
        id: 'room-' + roomId,
        displayName: 'Room ' + roomId
      }
    ]
  }, function(err, token) {
    if (err) {
      // handle it
    }
    // otherwise, use the token
  });
```

# Methods

### `Signer(secretKey)`

Constructs a `Signer` object from a base64url or base64 secret key string.

Throws an Error if the `secretKey` could not be parsed.

### `sign(userData, extraHeaders={}, cb(err, token))`

Creates a JWT as a JWS in Compact Serialization format.  Can be called multiple
times on the same object, saving you from having to load your secret GoInstant
application key every time.

`userData` is an Object with the following required fields, plus any other
custom ones you want to include in the JWT.

- `domain` - the domain of your website
- `id` - the unique, permanent identity of this user on your website
- `displayName` - the name to initially display for this user
- `groups` - an array of groups, each group requiring:
  - `id` - the unique ID of this group, which is handy for defining [GoInstant ACLs](https://developers.goinstant.com/v1/guides/creating_and_managing_acl.html)
  - `displayName` - the name to display for this group

`extraHeaders` is completely optional.  It's used to define any additional
[JWS header fields](http://tools.ietf.org/html/draft-ietf-jose-json-web-signature-11#section-4.1)
that you want to include.

### `signSync(userData, extraHeaders={})`

Synchronous version of `sign()`, returning the token string.  Throws an
exception if the token could not be created.

**Warning** depending on the size of your tokens, this may block the main
javascript thread for too long.

# Technicals

The `sign()` method `userData` maps to the following JWT claims.
The authoritative list of claims used in GoInstant can be found in the [Users and Authentication Guide](https://developers.goinstant.com/v1/guides/users_and_authentication.html#which-reserved-claims-are-required).

- `domain` -> `iss` (standard claim)
- `id` -> `sub` (standard claim)
- `displayName` -> `dn` (GoInstant private claim)
- `groups` -> `g` (GoInstant private claim)
  - `id` -> `id` (GoInstant private claim)
  - `displayName` -> `dn` (GoInstant private claim)
- `'goinstant.net'` -> `aud` (standard claim) _automatically added_

For the `extraHeaders` parameter in `sign()`, the `alg` and `typ` headers will
be overridden by this library.

# Contributing

If you'd like to contribute to or modify node-goinstant-auth, here's a quick
guide to get you started.

## Development Dependencies

- [node.js](http://nodejs.org) >= 0.10
  - 0.11 cannot currently be used due to bug in crypto streams

## Set-Up

Download via GitHub and install npm dependencies:

```sh
git clone git@github.com:goinstant/node-goinstant-auth.git
cd node-goinstant-auth

npm install
```

## Testing

Testing is with the [mocha](https://github.com/visionmedia/mocha) framework.  Tests are located in the `tests/` directory.

```sh
npm test  # uses the locally-installed mocha
```

# Support

Email [GoInstant Support](mailto:support@goinstant.com) or stop by [#goinstant on freenode](irc://irc.freenode.net/#goinstant).

For responsible disclosures, email [GoInstant Security](mailto:security@goinstant.com).

To [file a bug](https://github.com/goinstant/node-goinstant-auth/issues) or
[propose a patch](https://github.com/goinstant/node-goinstant-auth/pulls),
please use github directly.

# Legal

&copy; 2013 GoInstant Inc., a salesforce.com company.  All Rights Reserved.

Licensed under the 3-clause BSD license
