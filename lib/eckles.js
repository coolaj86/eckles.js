'use strict';

var ASN1;
var EC = module.exports;
var Hex = {};
var PEM = {};

// 1.2.840.10045.3.1.7
// prime256v1 (ANSI X9.62 named elliptic curve)
var OBJ_ID_EC  = '06 08 2A8648CE3D030107'.replace(/\s+/g, '').toLowerCase();
// 1.3.132.0.34
// secp384r1 (SECG (Certicom) named elliptic curve)
var OBJ_ID_EC_384 = '06 05 2B81040022'.replace(/\s+/g, '').toLowerCase();

// 1.2.840.10045.2.1
// ecPublicKey (ANSI X9.62 public key type)
var OBJ_ID_EC_PUB = '06 07 2A8648CE3D0201'.replace(/\s+/g, '').toLowerCase();


// The one good thing that came from the b***kchain hysteria: good EC documentation
// https://davidederosa.com/basic-blockchain-programming/elliptic-curve-keys/

PEM._toUrlSafeBase64 = function (u8) {
  //console.log('Len:', u8.byteLength);
  return Buffer.from(u8).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

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

  return { kty: typ, pub: pub, der: der, crv: crv };
};

PEM.packBlock = function (opts) {
  // TODO allow for headers?
  return '-----BEGIN ' + opts.type + '-----\n'
    + toBase64(opts.bytes).match(/.{1,64}/g).join('\n') + '\n'
    + '-----END ' + opts.type + '-----'
  ;
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

Hex.fromInt = function numToHex(d) {
  d = d.toString(16);
  if (d.length % 2) {
    return '0' + d;
  }
  return d;
};
Hex.toUint8 = function (hex) {
  var buf = Buffer.from(hex, 'hex');
  var ab = buf.buffer;
  return new Uint8Array(ab.slice(buf.offset, buf.offset + buf.byteLength));
};

function toBase64(u8) {
  return Buffer.from(u8).toString('base64');
}

function urlBase64ToBase64(ub64) {
  var r = ub64 % 4;
  if (2 === r) {
    ub64 += '==';
  } else if (3 === r) {
    ub64 += '=';
  }
  return ub64.replace(/-/g, '+').replace(/_/g, '/');
}
function base64ToUint8(b64) {
  var buf = Buffer.from(b64, 'base64');
  return new Uint8Array(buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength));
}

EC.parseSec1 = function parseEcOnlyPrivkey(u8, jwk) {
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
  //, dh: toHex(d)
  , x: PEM._toUrlSafeBase64(x)
  //, xh: toHex(x)
  , y: PEM._toUrlSafeBase64(y)
  //, yh: toHex(y)
  };
};

EC.parsePkcs8 = function parseEcPkcs8(u8, jwk) {
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
  //, dh: toHex(d)
  , x: PEM._toUrlSafeBase64(x)
  //, xh: toHex(x)
  , y: PEM._toUrlSafeBase64(y)
  //, yh: toHex(y)
  };
};

EC.parseSpki = function parsePem(u8, jwk) {
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
  //, xh: toHex(x)
  , y: PEM._toUrlSafeBase64(y)
  //, yh: toHex(y)
  };
};
EC.parsePkix = EC.parseSpki;

/*global Promise*/
EC.parse = function parseEc(opts) {
  return Promise.resolve().then(function () {
    if (!opts || !opts.pem) {
      throw new Error("must pass { pem: pem }");
    }
    var pem = opts.pem;
    var u8 = PEM.parseBlock(pem).der;
    var hex = toHex(u8);
    var jwk = { kty: 'EC', crv: null, x: null, y: null };

    //console.log();
    if (-1 !== hex.indexOf(OBJ_ID_EC)) {
      jwk.crv = "P-256";

      // PKCS8
      if (0x02 === u8[3] && 0x30 === u8[6] && 0x06 === u8[8]) {
        //console.log("PKCS8", u8[3].toString(16), u8[6].toString(16), u8[8].toString(16));
        jwk = EC.parsePkcs8(u8, jwk);
      // EC-only
      } else if (0x02 === u8[2] && 0x04 === u8[5] && 0xA0 === u8[39]) {
        //console.log("EC---", u8[2].toString(16), u8[5].toString(16), u8[39].toString(16));
        jwk = EC.parseSec1(u8, jwk);
      // SPKI/PKIK (Public)
      } else if (0x30 === u8[2] && 0x06 === u8[4] && 0x06 === u8[13]) {
        //console.log("SPKI-", u8[2].toString(16), u8[4].toString(16), u8[13].toString(16));
        jwk = EC.parseSpki(u8, jwk);
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
        jwk = EC.parsePkcs8(u8, jwk);
      // EC-only
      } else if (0x02 === u8[3] && 0x04 === u8[6] && 0xA0 === u8[56]) {
        //console.log("EC---", u8[3].toString(16), u8[6].toString(16), u8[56].toString(16));
        jwk = EC.parseSec1(u8, jwk);
      // SPKI/PKIK (Public)
      } else if (0x30 === u8[2] && 0x06 === u8[4] && 0x06 === u8[13]) {
        //console.log("SPKI-", u8[2].toString(16), u8[4].toString(16), u8[13].toString(16));
        jwk = EC.parseSpki(u8, jwk);
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
    if (opts.public) {
      if (true !== opts.public) {
        throw new Error("options.public must be either `true` or `false` not ("
          + typeof opts.public + ") '" + opts.public + "'");
      }
      delete jwk.d;
    }
    return jwk;
  });
};
EC.toJwk = EC.import = EC.parse;

EC.pack = function (opts) {
  return Promise.resolve().then(function () {
    if (!opts || !opts.jwk || 'object' !== typeof opts.jwk) {
      throw new Error("must pass { jwk: jwk }");
    }
    var jwk = JSON.parse(JSON.stringify(opts.jwk));
    var format = opts.format;
    if (opts.public || -1 !== [ 'spki', 'pkix', 'ssh', 'rfc4716' ].indexOf(format)) {
      jwk.d = null;
    }
    if ('EC' !== jwk.kty) {
      throw new Error("options.jwk.kty must be 'EC' for EC keys");
    }
    if (!jwk.d) {
      if (!format || -1 !== [ 'spki', 'pkix' ].indexOf(format)) {
        format = 'spki';
      } else if (-1 !== [ 'ssh', 'rfc4716' ].indexOf(format)) {
        format = 'ssh';
      } else {
        throw new Error("options.format must be 'spki' or 'ssh' for public EC keys, not ("
          + typeof format + ") " + format);
      }
    } else {
      if (!format || 'sec1' === format) {
        format = 'sec1';
      } else if ('pkcs8' !== format) {
        throw new Error("options.format must be 'sec1' or 'pkcs8' for private EC keys");
      }
    }
    if (-1 === [ 'P-256', 'P-384' ].indexOf(jwk.crv)) {
      throw new Error("options.jwk.crv must be either P-256 or P-384 for EC keys");
    }
    if (!jwk.y) {
      throw new Error("options.jwk.y must be a urlsafe base64-encoded either P-256 or P-384");
    }

    if ('sec1' === format) {
      return PEM.packBlock({ type: "EC PRIVATE KEY", bytes: EC.packSec1(jwk) });
    } else if ('pkcs8' === format) {
      return PEM.packBlock({ type: "EC PRIVATE KEY", bytes: EC.packPkcs8(jwk) });
    } else if (-1 !== [ 'spki', 'pkix' ].indexOf(format)) {
      return PEM.packBlock({ type: "PUBLIC KEY", bytes: EC.packSpki(jwk) });
    } else if (-1 !== [ 'ssh', 'rfc4716' ].indexOf(format)) {
      return EC.packSsh(jwk);
    } else {
      throw new Error("Sanity Error: reached unreachable code block with format: " + format);
    }
  });
};

EC.packSec1 = function (jwk) {
  var d = toHex(base64ToUint8(urlBase64ToBase64(jwk.d)));
  var x = toHex(base64ToUint8(urlBase64ToBase64(jwk.x)));
  var y = toHex(base64ToUint8(urlBase64ToBase64(jwk.y)));
  var objId = ('P-256' === jwk.crv) ? OBJ_ID_EC : OBJ_ID_EC_384;
  return Hex.toUint8(
    ASN1('30'
    , ASN1.UInt('01')
    , ASN1('04', d)
    , ASN1('A0', objId)
    , ASN1('A1', ASN1.BitStr('04' + x + y)))
  );
};
EC.packPkcs8 = function (jwk) {
  var d = toHex(base64ToUint8(urlBase64ToBase64(jwk.d)));
  var x = toHex(base64ToUint8(urlBase64ToBase64(jwk.x)));
  var y = toHex(base64ToUint8(urlBase64ToBase64(jwk.y)));
  var objId = ('P-256' === jwk.crv) ? OBJ_ID_EC : OBJ_ID_EC_384;
  return Hex.toUint8(
    ASN1('30'
    , ASN1.UInt('00')
    , ASN1('30'
      , OBJ_ID_EC_PUB
      , objId
      )
    , ASN1('04'
      , ASN1('30'
        , ASN1.UInt('01')
        , ASN1('04', d)
        , ASN1('A1', ASN1.BitStr('04' + x + y)))))
  );
};
EC.packSpki = function (jwk) {
  var x = toHex(base64ToUint8(urlBase64ToBase64(jwk.x)));
  var y = toHex(base64ToUint8(urlBase64ToBase64(jwk.y)));
  var objId = ('P-256' === jwk.crv) ? OBJ_ID_EC : OBJ_ID_EC_384;
  return Hex.toUint8(
    ASN1('30'
    , ASN1('30'
      , OBJ_ID_EC_PUB
      , objId
      )
    , ASN1.BitStr('04' + x + y))
  );
};
EC.packPkix = EC.packSpki;
EC.packSsh = function (jwk) {
  // Custom SSH format
  var typ = 'ecdsa-sha2-nistp256';
	var a = '32 35 36';
  var b = '41';
  var comment = jwk.crv + '@localhost';
  if ('P-256' !== jwk.crv) {
    typ = 'ecdsa-sha2-nistp384';
    a = '33 38 34';
    b = '61';
  }
  var x = toHex(base64ToUint8(urlBase64ToBase64(jwk.x)));
  var y = toHex(base64ToUint8(urlBase64ToBase64(jwk.y)));
  var ssh = Hex.toUint8(
    ('00 00 00 13 65 63 64 73 61 2d 73 68 61 32 2d 6e 69 73 74 70'
    + a + '00 00 00 08 6e 69 73 74 70' + a + '00 00 00' + b
    + '04' + x + y).replace(/\s+/g, '').toLowerCase()
  );

  return typ + ' ' + toBase64(ssh) + ' ' + comment;
};

//
// A dumbed-down, minimal ASN.1 packer
//

// Almost every ASN.1 type that's important for CSR
// can be represented generically with only a few rules.
ASN1 = function ASN1(/*type, hexstrings...*/) {
  var args = Array.prototype.slice.call(arguments);
  var typ = args.shift();
  var str = args.join('').replace(/\s+/g, '').toLowerCase();
  var len = (str.length/2);
  var lenlen = 0;
  var hex = typ;

  // We can't have an odd number of hex chars
  if (len !== Math.round(len)) {
    throw new Error("invalid hex");
  }

  // The first byte of any ASN.1 sequence is the type (Sequence, Integer, etc)
  // The second byte is either the size of the value, or the size of its size

  // 1. If the second byte is < 0x80 (128) it is considered the size
  // 2. If it is > 0x80 then it describes the number of bytes of the size
  //    ex: 0x82 means the next 2 bytes describe the size of the value
  // 3. The special case of exactly 0x80 is "indefinite" length (to end-of-file)

  if (len > 127) {
    lenlen += 1;
    while (len > 255) {
      lenlen += 1;
      len = len >> 8;
    }
  }

  if (lenlen) { hex += Hex.fromInt(0x80 + lenlen); }
  return hex + Hex.fromInt(str.length/2) + str;
};

// The Integer type has some special rules
ASN1.UInt = function UINT() {
  var str = Array.prototype.slice.call(arguments).join('');
  var first = parseInt(str.slice(0, 2), 16);

  // If the first byte is 0x80 or greater, the number is considered negative
  // Therefore we add a '00' prefix if the 0x80 bit is set
  if (0x80 & first) { str = '00' + str; }

  return ASN1('02', str);
};

// The Bit String type also has a special rule
ASN1.BitStr = function BITSTR() {
  var str = Array.prototype.slice.call(arguments).join('');
  // '00' is a mask of how many bits of the next byte to ignore
  return ASN1('03', '00' + str);
};

EC.toPem = EC.export = EC.pack;
