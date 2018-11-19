#!/usr/bin/env node
'use strict';

var fs = require('fs');
var eckles = require('../index.js');

var infile = process.argv[2];
//var outfile = process.argv[3];

var keypem = fs.readFileSync(infile, 'ascii');

eckles.import({ pem: keypem }).then(function (jwk) {
  console.log(JSON.stringify(jwk, null, 2));
});
