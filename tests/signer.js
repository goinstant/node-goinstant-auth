/*jshint nonew:false */
'use strict';
var assert = require('assert');
var base64url = require('base64url');

var Signer = require('../').Signer;

function assertInstanceOf(obj, ctor, message) {
  if (!(obj instanceof ctor)) {
    assert.fail(obj, ctor.name, message,
                'instanceof', assertInstanceOf);
  }
}

assert.instanceOf = assert.instanceOf || assertInstanceOf;

describe('goinstant-auth Signer', function() {

  describe('constructor', function() {
    it('needs the secret key to not be null', function() {
      assert.throws(function() {
        new Signer(null);
      }, TypeError);
    });
    it('needs the secret key to be base64', function() {
      assert.throws(function() {
        new Signer('!@$^&*');
      }, TypeError);
    });
    it('doesn\'t need the secret key to be padded', function() {
      assert.doesNotThrow(function() {
        new Signer('abc1'); // canonical base64: 'abc1=='
      });
    });
  });

  function validateJwt(jwt, expectClaims, expectSig) {
    var parts = jwt.split('.');

    assert.equal(typeof parts[0], 'string');
    var header = JSON.parse(base64url.decode(parts[0]));
    assert.equal(typeof header, 'object');
    assert.equal(header.typ, 'JWT');
    assert.equal(header.alg, 'HS256');

    assert.equal(typeof parts[1], 'string');
    var claims = JSON.parse(base64url.decode(parts[1]));
    assert.equal(typeof claims, 'object');
    assert.deepEqual(claims, expectClaims);

    assert.equal(parts[2], expectSig);
  }

  describe('#sign()', function() {
    testsForMethod(function(signer, userData, cb) {
      signer.sign(userData, cb);
    });
  });

  describe('#signSync()', function() {
    testsForMethod(function(signer, userData, cb) {
      var jwt;
      try {
        jwt = signer.signSync(userData);
      } catch (e) {
        return cb(e);
      }
      cb(null, jwt);
    });
  });

  function testsForMethod(doSign) {
    var signer;
    before(function() {
      signer = new Signer('HKYdFdnezle2yrI2_Ph3cHz144bISk-cvuAbeAAA999');
    });

    it('needs a userData object', function(done) {
      doSign(signer, null, function(err, jwt) {
        assert.strictEqual(jwt, undefined);
        assert.instanceOf(err, TypeError);
        assert.equal(err.message, 'User Data must be an Object');
        done();
      });
    });

    it('needs a userData to have an id', function(done) {
      var userData = {
        domain: 'example.com',
        displayName: 'bob',
      };
      doSign(signer, userData, function(err, jwt) {
        assert.strictEqual(jwt, undefined);
        assert.instanceOf(err, Error);
        assert.equal(err.message, 'missing required key: id');
        done();
      });
    });

    it('needs a userData to have a displayName', function(done) {
      var userData = {
        id: 'bar',
        domain: 'example.com',
      };
      doSign(signer, userData, function(err, jwt) {
        assert.strictEqual(jwt, undefined);
        assert.instanceOf(err, Error);
        assert.equal(err.message, 'missing required key: displayName');
        done();
      });
    });

    it('needs a userData to have a domain', function(done) {
      var userData = {
        id: 'bar',
        displayName: 'bob',
      };
      doSign(signer, userData, function(err, jwt) {
        assert.strictEqual(jwt, undefined);
        assert.instanceOf(err, Error);
        assert.equal(err.message, 'missing required key: domain');
        done();
      });
    });

    it('if groups present, must be an array', function(done) {
      var userData = {
        id: 'bar',
        domain: 'example.com',
        displayName: 'bob',
        groups: 'nope'
      };
      doSign(signer, userData, function(err,jwt) {
        assert.strictEqual(jwt, undefined);
        assert.instanceOf(err, TypeError);
        assert.equal(err.message, 'Groups must be in an Array');
        done();
      });
    });

    it('happily signs without groups',function(done) {
      var userData = {
        id: 'bar',
        domain: 'example.com',
        displayName: 'bob',
        groups: [],
      };
      var expectClaims = {
        aud: 'goinstant.net',
        sub: 'bar',
        iss: 'example.com',
        dn: 'bob',
        g: []
      };
      var expectSig = '4eb8Wxzu2S9vnoV1Q--8evzZC8FAlqBlUBCeeWZ9xK8';

      doSign(signer, userData, function(err, jwt) {
        if (err) {
          return done(err);
        }
        validateJwt(jwt, expectClaims, expectSig);
        done();
      });
    });

    it('needs groups to have an id', function(done) {
      var userData = {
        id: 'bar',
        domain: 'example.com',
        displayName: 'bob',
        groups: [
          { displayName: 'MyGroup' }
        ],
      };
      doSign(signer, userData, function(err, jwt) {
        assert.strictEqual(jwt, undefined);
        assert.instanceOf(err, Error);
        assert.equal(err.message, 'group 0 missing required key: id');
        done();
      });
    });

    it('needs groups to have a displayName', function(done) {
      var userData = {
        id: 'bar',
        domain: 'example.com',
        displayName: 'bob',
        groups: [
          { id: 99, displayName: 'Gretzky Lovers' },
          { id: 1234 }
        ],
      };
      doSign(signer, userData, function(err, jwt) {
        assert.strictEqual(jwt, undefined);
        assert.instanceOf(err, Error);
        assert.equal(err.message, 'group 1 missing required key: displayName');
        done();
      });
    });

    it('happily signs with groups', function(done) {
      var userData = {
        id: 'bar',
        domain: 'example.com',
        displayName: 'bob',
        groups: [
          { id: 1234, displayName: 'Group 1234' },
          { id: 42, displayName: 'Meaning Group' }
        ]
      };
      var expectClaims = {
        aud: 'goinstant.net',
        sub: 'bar',
        iss: 'example.com',
        dn: 'bob',
        g: [
          { id: 1234, dn: 'Group 1234' },
          { id: 42, dn: 'Meaning Group' }
        ]
      };
      var expectSig = '5isd3i1A4so7MwKm0VHWYHuWRy3WwGFipO0kkelNRLU';

      doSign(signer, userData, function(err, jwt) {
        if (err) {
          return done(err);
        }
        validateJwt(jwt, expectClaims, expectSig);
        done();
      });
    });
  }

});
