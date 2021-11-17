'use strict';

const webcrypto = require('crypto').webcrypto;

const encoder = require('util').TextEncoder;
const decoder = require('util').TextDecoder;

const path = require('path');
const Commlink = require(__dirname + path.sep + 'cryptic.js');

const CRYPTIC = () => {
  return Commlink(webcrypto, encoder, decoder);
};

module.exports = CRYPTIC;
