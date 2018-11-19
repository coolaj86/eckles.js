'use strict';

var Hex = {};

// 1.2.840.10045.3.1.7
// prime256v1 (ANSI X9.62 named elliptic curve)
var OBJ_ID_EC  = '06 08 2A8648CE3D030107'.replace(/\s+/g, '').toLowerCase();
// 1.3.132.0.34
// secp384r1 (SECG (Certicom) named elliptic curve)
var OBJ_ID_EC_384 = '06 05 2B81040022'.replace(/\s+/g, '').toLowerCase();


// The one good thing that came from the b***kchain hysteria: good EC documentation
// https://davidederosa.com/basic-blockchain-programming/elliptic-curve-keys/

var PEM = {};
PEM._toUrlSafeBase64 = function (u8) {
  //console.log('Len:', u8.byteLength);
  return Buffer.from(u8).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

function toHex(ab) {
  var hex = [];
  var u8 = new Uint8Array(ab);
  var size = u8.byteLength;
  var i;
  var h;
  for (i = 0; i < size; i += 1) {
    h = u8[i].toString(16);
    if (2 === h.length) {
      hex.push(h);
    } else {
      hex.push('0' + h);
    }
  }
  return hex.join('').replace(/\s+/g, '').toLowerCase();
}
Hex.fromAB = toHex;

function parsePem(pem) {
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
    var hex = toHex(der);
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

  return { typ: typ, pub: pub, der: der, crv: crv };
}

function parseEcOnlyPrivkey(u8, jwk) {
  var index = 7;
  var len = 32;
  var olen = OBJ_ID_EC.length/2;

  if ("P-384" === jwk.crv) {
    olen = OBJ_ID_EC_384.length/2;
    index = 8;
    len = 48;
  }
  if (len !== u8[index - 1]) {
    throw new Error("Unexpected bitlength " + len);
  }

  // private part is d
  var d = u8.slice(index, index + len);
  // compression bit index
  var ci = index + len + 2 + olen + 2 + 3;
  var c = u8[ci];
  var x, y;

  if (0x04 === c) {
    y = u8.slice(ci + 1 + len, ci + 1 + len + len);
  } else if (0x02 !== c) {
    throw new Error("not a supported EC private key");
  }
  x = u8.slice(ci + 1, ci + 1 + len);

  return {
    kty: jwk.kty
  , crv: jwk.crv
  , d: PEM._toUrlSafeBase64(d)
  //, dh: d
  , x: PEM._toUrlSafeBase64(x)
  //, xh: x
  , y: PEM._toUrlSafeBase64(y)
  //, yh: y
  };
}
function parseEcPkcs8Privkey(u8, jwk) {
  var index = 24 + (OBJ_ID_EC.length/2);
  var len = 32;
  if ("P-384" === jwk.crv) {
    index = 24 + (OBJ_ID_EC_384.length/2) + 2;
    len = 48;
  }

  //console.log(index, u8.slice(index));
  if (0x04 !== u8[index]) {
    //console.log(jwk);
    throw new Error("privkey not found");
  }
  var d = u8.slice(index+2, index+2+len);
  var ci = index+2+len+5;
  var xi = ci+1;
  var x = u8.slice(xi, xi + len);
  var yi = xi+len;
  var y;
  if (0x04 === u8[ci]) {
    y = u8.slice(yi, yi + len);
  } else if (0x02 !== u8[ci]) {
    throw new Error("invalid compression bit (expected 0x04 or 0x02)");
  }

  return {
    kty: jwk.kty
  , crv: jwk.crv
  , d: PEM._toUrlSafeBase64(d)
  //, dh: d
  , x: PEM._toUrlSafeBase64(x)
  //, xh: x
  , y: PEM._toUrlSafeBase64(y)
  //, yh: y
  };
}
function parseEcPub(u8, jwk) {
  var ci = 16 + OBJ_ID_EC.length/2;
  var len = 32;

  if ("P-384" === jwk.crv) {
    ci = 16 + OBJ_ID_EC_384.length/2;
    len = 48;
  }

  var c = u8[ci];
  var xi = ci + 1;
  var x = u8.slice(xi, xi + len);
  var yi = xi + len;
  var y;
  if (0x04 === c) {
    y = u8.slice(yi, yi + len);
  } else if (0x02 !== c) {
    throw new Error("not a supported EC private key");
  }

  return {
    kty: jwk.kty
  , crv: jwk.crv
  , x: PEM._toUrlSafeBase64(x)
  //, xh: x
  , y: PEM._toUrlSafeBase64(y)
  //, yh: y
  };
}

/*global Promise*/
function parseEcPrivkey(opts) {
  return Promise.resolve().then(function () {
    if (!opts || !opts.pem) {
      throw new Error("must pass { pem: pem }");
    }
    var pem = opts.pem;
    var u8 = parsePem(pem).der;
    var hex = toHex(u8);
    var jwk = { kty: 'EC', crv: null, x: null, y: null };

    //console.log();
    if (-1 !== hex.indexOf(OBJ_ID_EC)) {
      jwk.crv = "P-256";

      // PKCS8
      if (0x02 === u8[3] && 0x30 === u8[6] && 0x06 === u8[8]) {
        //console.log("PKCS8", u8[3].toString(16), u8[6].toString(16), u8[8].toString(16));
        return parseEcPkcs8Privkey(u8, jwk);
      // EC-only
      } else if (0x02 === u8[2] && 0x04 === u8[5] && 0xA0 === u8[39]) {
        //console.log("EC---", u8[2].toString(16), u8[5].toString(16), u8[39].toString(16));
        return parseEcOnlyPrivkey(u8, jwk);
      // SPKI/PKIK (Public)
      } else if (0x30 === u8[2] && 0x06 === u8[4] && 0x06 === u8[13]) {
        //console.log("SPKI-", u8[2].toString(16), u8[4].toString(16), u8[13].toString(16));
        return parseEcPub(u8, jwk);
      // Error
      } else {
        //console.log("PKCS8", u8[3].toString(16), u8[6].toString(16), u8[8].toString(16));
        //console.log("EC---", u8[2].toString(16), u8[5].toString(16), u8[39].toString(16));
        //console.log("SPKI-", u8[2].toString(16), u8[4].toString(16), u8[13].toString(16));
        throw new Error("unrecognized key format");
      }
    } else if (-1 !== hex.indexOf(OBJ_ID_EC_384)) {
      jwk.crv = "P-384";

      // PKCS8
      if (0x02 === u8[3] && 0x30 === u8[6] && 0x06 === u8[8]) {
        //console.log("PKCS8", u8[3].toString(16), u8[6].toString(16), u8[8].toString(16));
        return parseEcPkcs8Privkey(u8, jwk);
      // EC-only
      } else if (0x02 === u8[3] && 0x04 === u8[6] && 0xA0 === u8[56]) {
        //console.log("EC---", u8[3].toString(16), u8[6].toString(16), u8[56].toString(16));
        return parseEcOnlyPrivkey(u8, jwk);
      // SPKI/PKIK (Public)
      } else if (0x30 === u8[2] && 0x06 === u8[4] && 0x06 === u8[13]) {
        //console.log("SPKI-", u8[2].toString(16), u8[4].toString(16), u8[13].toString(16));
        return parseEcPub(u8, jwk);
      // Error
      } else {
        //console.log("PKCS8", u8[3].toString(16), u8[6].toString(16), u8[8].toString(16));
        //console.log("EC---", u8[3].toString(16), u8[6].toString(16), u8[56].toString(16));
        //console.log("SPKI-", u8[2].toString(16), u8[4].toString(16), u8[13].toString(16));
        throw new Error("unrecognized key format");
      }
    } else {
      throw new Error("Supported key types are P-256 and P-384");
    }
  });
}

module.exports.import = parseEcPrivkey;
