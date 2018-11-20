#!/usr/bin/env node
'use strict';

var fs = require('fs');
var eckles = require('../index.js');

var infile = process.argv[2];
var format = process.argv[3];

var key = fs.readFileSync(infile, 'ascii');

try {
  key = JSON.parse(key);
} catch(e) {
  // ignore
}

if ('string' === typeof key) {
  eckles.import({ pem: key }).then(function (jwk) {
    console.log(JSON.stringify(jwk, null, 2));
  }).catch(function (err) {
    console.error(err);
    process.exit(1);
  });
} else {
  eckles.export({ jwk: key, format: format }).then(function (pem) {
    console.log(pem);
  }).catch(function (err) {
    console.error(err);
    process.exit(2);
  });
}
