const cryptolite = require('cryptonight-hashing')['cryptonight_light'];

// Paste input from nc ctf.pwn.sg 1503.
const data = new Buffer('...', 'hex');

// Function accepts a second parameter for variant (see the C++ file multihashing.cc)
const hashedData = cryptolite(data, 1);

console.log(hashedData.toString('hex'));
