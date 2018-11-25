'use strict';

var PEM = module.exports;
var Enc = require('./encoding.js');

// TODO move object id hinting to x509.js

// 1.2.840.10045.3.1.7
// prime256v1 (ANSI X9.62 named elliptic curve)
var OBJ_ID_EC  = '06 08 2A8648CE3D030107'.replace(/\s+/g, '').toLowerCase();
// 1.3.132.0.34
// secp384r1 (SECG (Certicom) named elliptic curve)
var OBJ_ID_EC_384 = '06 05 2B81040022'.replace(/\s+/g, '').toLowerCase();

PEM.parseBlock = function pemToDer(pem) {
  var typ;
  var pub;
  var crv;
  var der = Buffer.from(pem.split(/\n/).filter(function (line, i) {
    if (0 === i) {
      if (/ PUBLIC /.test(line)) {
        pub = true;
      } else if (/ PRIVATE /.test(line)) {
        pub = false;
      }
      if (/ EC/.test(line)) {
        typ = 'EC';
      }
    }
    return !/---/.test(line);
  }).join(''), 'base64');

  if (!typ || 'EC' === typ) {
    var hex = Enc.bufToHex(der);
    if (-1 !== hex.indexOf(OBJ_ID_EC)) {
      typ = 'EC';
      crv = 'P-256';
    } else if (-1 !== hex.indexOf(OBJ_ID_EC_384)) {
      typ = 'EC';
      crv = 'P-384';
    } else {
      // TODO support P-384 as well (but probably nothing else)
      console.warn("unsupported ec curve");
    }
  }

  return { kty: typ, pub: pub, der: der, crv: crv };
};

PEM.packBlock = function (opts) {
  // TODO allow for headers?
  return '-----BEGIN ' + opts.type + '-----\n'
    + Enc.bufToBase64(opts.bytes).match(/.{1,64}/g).join('\n') + '\n'
    + '-----END ' + opts.type + '-----'
  ;
};
