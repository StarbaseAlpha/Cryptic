'use strict';

const WebCrypto = require("node-webcrypto-ossl");
const webcrypto = new WebCrypto();

const path = require('path');
const Commlink = require(__dirname + path.sep + 'cryptic.js');

const CRYPTIC = () => {
  return Commlink(webcrypto);
};

module.exports = CRYPTIC;
