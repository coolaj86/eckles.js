'use strict';

var Enc = module.exports;

Enc.base64ToBuf = function base64ToBuf(str) {
  // node handles both base64 and urlBase64 equally
  return Buffer.from(str, 'base64');
};

Enc.base64ToHex = function base64ToHex(b64) {
  return Enc.bufToHex(Enc.base64ToBuf(b64));
};

Enc.bufToBase64 = function toHex(u8) {
  // Ensure a node buffer, even if TypedArray
  return Buffer.from(u8).toString('base64');
};

Enc.bufToHex = function bufToHex(u8) {
  // Ensure a node buffer, even if TypedArray
  return Buffer.from(u8).toString('hex');
};

Enc.bufToUrlBase64 = function bufToUrlBase64(u8) {
  return Enc.bufToBase64(u8)
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
};

Enc.hexToUint8 = function (hex) {
  // TODO: I don't remember why I chose Uint8Array over Buffer...
  var buf = Buffer.from(hex, 'hex');
  var ab = buf.buffer.slice(buf.offset, buf.offset + buf.byteLength);
  return new Uint8Array(ab);
};

Enc.numToHex = function numToHex(d) {
  d = d.toString(16);
  if (d.length % 2) {
    return '0' + d;
  }
  return d;
};
