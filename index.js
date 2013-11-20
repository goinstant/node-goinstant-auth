if (process.version.match(/^(v0\.11\.[0-7])$/)) {
  console.error('goinstant-auth is not safe to use with node '+RegExp.$1);
  console.error('Early versions of node v0.11 appear to have a bug where it '+
                'returns uninitialized memory for HMAC functions!');
  throw new Error('goinstant-auth is not safe to use in node v0.11.[0-7]!');
}

module.exports.Signer = require('./lib/signer');
