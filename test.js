'use strict';
var assert = require('assert');

describe('goinstant-auth', function() {

  describe('constructor', function() {
    it('needs the secret key to not be null');
    it('needs the secret key to be base64');
    it('doesn\'t need the secret key to be padded');
  });

  function validateJwt(jwt, expectClaims, expectSig) {
    assert('false');
  }

  describe('#sign()', function() {

    it('needs a userData object');
    it('needs a userData to have an id');
    it('needs a userData to have a displayName');
    it('needs a userData to have a domain');
    it('if groups present, must be an array');

    it('happily signs without groups');

    it('needs groups to have an id');
    it('needs groups to have a displayName');

    it('happily signs with groups');
  });
});
