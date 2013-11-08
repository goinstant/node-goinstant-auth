'use strict';

var crypto = require('crypto');
var base64url = require('base64url');
var assert = require('assert');

var defer = global.setImmediate ? setImmediate : process.nextTick.bind(process);

var BASE64URL_RX = /^[a-zA-Z0-9_\-]+$/;

var REQUIRED_CLAIMS = {
  domain: 'iss',
  id: 'sub',
  displayName: 'dn',
};

var OPTIONAL_CLAIMS = {
  groups: 'g'
};

var REQUIRED_GROUP_CLAIMS = {
  id: 'id',
  displayName: 'dn'
};

module.exports = Signer;
module.exports.Signer = Signer;

/**
 * Creates a Signer for a particular secret key.
 *
 * @param {string} secretKey base64url or base64 secret key
 * @throws TypeError
 * @throws AssertionError
 */
function Signer(secretKey) {
  if (!secretKey || typeof secretKey !== 'string') {
    throw new TypeError('Secret Key must be a string');
  }

  // allows both base64url and base64 input:
  secretKey = base64url.fromBase64(secretKey);
  if (!secretKey || !BASE64URL_RX.test(secretKey)) {
    throw new TypeError('Secret Key must be a base64url or base64');
  }

  this._binaryKey = base64url.toBuffer(secretKey);
  assert(Buffer.isBuffer(this._binaryKey), 'Secret Key could not be parsed');
}

/**
 * Shallow-clone of an object.
 * @private
 */
function shallowClone(obj) {
  var o = {};
  for (var k in obj) {
    o[k] = obj[k];
  }
  return o;
}

/**
 * Using a table, maps "options" into "claims" for an object.
 * Throws an error if a required claim is missing.
 * @throws Error
 * @param {object} claims
 * @param {object} table mapping from option -> claim
 * @param {string} [msg]
 */
function mapRequiredClaims(claims, table, msg) {
  msg = msg || 'missing required key';
  Object.keys(table).forEach(function(k) {
    var claimName = table[k];
    var val = claims[k];
    if (val === null || val === undefined) {
      throw new Error(msg + ': ' + k);
    }
    delete claims[k];
    claims[claimName] = val;
  });
}

/**
 * Using a table, maps "options" into "claims" for an object.
 * Skips over missing claims.
 * @param {object} claims
 * @param {object} table mapping from option -> claim
 */
function mapOptionalClaims(claims, table) {
  Object.keys(table).forEach(function(k) {
    var claimName = table[k];
    var val = claims[k];
    if (val !== null || val !== undefined) {
      delete claims[k];
      claims[claimName] = val;
    }
  });
}

/**
 * Serializes a set of userData, plus extraHeaders, into a Compact
 * Serialization string, ready for signing.
 *
 * @param {object} userData
 * @param {object} extraHeaders
 */
function serialize(userData, extraHeaders) {
  if (!userData || typeof userData !== 'object') {
    throw new TypeError('User Data must be an Object');
  }
  if (typeof extraHeaders !== 'object') {
    throw new TypeError('Extra Headers must be an Object');
  }

  var headers = shallowClone(extraHeaders);
  headers.typ = 'JWT';
  headers.alg = 'HS256';

  var claims = shallowClone(userData);
  mapRequiredClaims(claims, REQUIRED_CLAIMS);
  mapOptionalClaims(claims, OPTIONAL_CLAIMS);

  if (claims.g) {
    if (!Array.isArray(claims.g)) {
      throw new TypeError('Groups must be in an Array');
    }

    claims.g = claims.g.map(function(group, i) {
      mapRequiredClaims(group, REQUIRED_GROUP_CLAIMS,
                        'group '+i+' missing required key');
      return group;
    });
  }

  claims.aud = 'goinstant.net';

  var head = base64url(JSON.stringify(headers));
  var payload = base64url(JSON.stringify(claims));
  var signingInput = head + '.' + payload;

  return signingInput;
}

/**
 * Creates a JWT token based on the supplied userData.
 *
 * See README.md for complete options.
 *
 * @param {object} userData descriptor for a user
 * @param {object} [extraHeaders={}] optional JWS headers
 * @param {function(Error,string)} cb
 */
Signer.prototype.sign = function(userData, extraHeaders, cb) {
  extraHeaders = extraHeaders || {};
  if (typeof extraHeaders === 'function') {
    cb = extraHeaders;
    extraHeaders = {};
  }
  if (typeof cb !== 'function') {
    throw new TypeError('callback is required');
  }

  var signingInput;
  try {
    signingInput = serialize(userData, extraHeaders);
  } catch (e) {
    return cb(e);
  }

  assert(Buffer.isBuffer(this._binaryKey), '_binaryKey is not a Buffer!');
  var hmac = crypto.createHmac('sha256', this._binaryKey);
  function finish(err,data) {
    hmac.removeAllListeners('data');
    hmac.removeAllListeners('error');
    cb(err,data);
  }
  hmac.on('data', function(sig) {
    var jwt = signingInput + '.' + base64url(sig);
    finish(null, jwt);
  });
  hmac.on('error', function(err) {
    finish(err);
  });

  // bug in some versions of node 0.11 require this to be next-tick
  defer(function() {
    hmac.write(signingInput);
    hmac.end();
  });
};

/**
 * Synchronous version of sign().
 *
 * See README.md for complete options.
 *
 * @param {object} userData descriptor for a user
 * @param {object} [extraHeaders={}] optional JWS headers
 * @throws Error
 * @return {string}
 */
Signer.prototype.signSync = function(userData, extraHeaders) {
  extraHeaders = extraHeaders || {};

  var signingInput = serialize(userData, extraHeaders);
  var hmac = crypto.createHmac('sha256', this._binaryKey);
  hmac.update(signingInput);
  var sig = hmac.digest();
  var jwt = signingInput + '.' + base64url(sig);
  return jwt;
};
