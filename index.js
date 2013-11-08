if (process.version.match(/^v0\.11\./)) {
  console.error('goinstant-auth is not safe to use with node v0.11!');
  console.error('node v0.11.3 appears to have a bug where it returns '+
                'uninitialized memory for HMAC functions!');
  throw new Error('goinstant-auth is not yet safe to use in node v0.11!');
}

module.exports.Signer = require('./lib/signer');
