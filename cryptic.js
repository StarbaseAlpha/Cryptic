'use strict';

function Cryptic(webCrypto, encoder, decoder) {

  let crypto = webCrypto;
  if (typeof window !== 'undefined') {
    crypto = window.crypto || webCrypto;
  }

  let TextEncoder = encoder;
  let TextDecoder = decoder;
  if (typeof window !== 'undefined') {
    TextEncoder = window.TextEncoder;
    TextDecoder = window.TextDecoder;
  }

  const toHex = (byteArray) => {
    return Array.from(new Uint8Array(byteArray)).map(val => {
      return ('0' + val.toString(16)).slice(-2);
    }).join('');
  };

  const fromHex = (str) => {
    let result = new Uint8Array(str.match(/.{0,2}/g).map(val => {
      return parseInt(val, 16);
    }));
    return result.slice(0, result.length - 1);
  };

  const encode = (byteArray) => {
    return btoa(Array.from(new Uint8Array(byteArray)).map(val => {
      return String.fromCharCode(val);
    }).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
  };

  const decode = (str) => {
    return new Uint8Array(atob(str.replace(/\_/g, '/').replace(/\-/g, '+')).split('').map(val => {
      return val.charCodeAt(0);
    }));
  };

  const fromText = (string) => {
    return new TextEncoder().encode(string);
  };

  const toText = (byteArray) => {
    return new TextDecoder().decode(byteArray);
  };

  const combine = (bitsA = [], bitsB = []) => {
    let A = bitsA;
    let B = bitsB;
    if (typeof bitsA === 'string') {
      A = decode(bitsA);
    }
    if (typeof bitsB === 'string') {
      B = decode(bitsB);
    }
    let a = new Uint8Array(A);
    let b = new Uint8Array(B);
    let c = new Uint8Array(a.length + b.length);
    c.set(a);
    c.set(b, a.length);
    return c;
  };

  const random = (size) => {
    return crypto.getRandomValues(new Uint8Array(size));
  };

  const createECDH = async (curve = "P-256") => {
    let DH = await crypto.subtle.generateKey({
      "name": "ECDH",
      "namedCurve": curve
    }, true, ['deriveBits']);
    let pub = await crypto.subtle.exportKey('spki', DH.publicKey);
    let key = await crypto.subtle.exportKey('pkcs8', DH.privateKey);
    return {
      "pub": encode(pub),
      "key": encode(key)
    };
  };

  const createECDSA = async (curve = "P-256") => {
    let user = await crypto.subtle.generateKey({
      "name": "ECDSA",
      "namedCurve": curve
    }, true, ['sign', 'verify']);
    let pub = await crypto.subtle.exportKey('spki', user.publicKey);
    let key = await crypto.subtle.exportKey('pkcs8', user.privateKey);
    return {
      "pub": encode(pub),
      "key": encode(key)
    };
  };

  const ecdsaSign = async (key, msg, curve = "P-256", hashAlg = "SHA-256") => {
    let message = msg.toString();
    let signKey = await crypto.subtle.importKey('pkcs8', decode(key), {
      "name": "ECDSA",
      "namedCurve": curve
    }, false, ['sign']);
    let sig = await crypto.subtle.sign({
      "name": "ECDSA",
      "hash": hashAlg
    }, signKey, fromText(message));
    return encode(sig);
  };

  const ecdsaVerify = async (pub, sig, msg, curve = "P-256", hashAlg = "SHA-256") => {
    let message = msg.toString();
    let verifyKey = await crypto.subtle.importKey('spki', decode(pub), {
      "name": "ECDSA",
      "namedCurve": curve
    }, false, ['verify']);
    let verified = await crypto.subtle.verify({
      "name": "ECDSA",
      "hash": hashAlg
    }, verifyKey, decode(sig), fromText(message));
    return verified;
  };

  const hmacSign = async (bits, msg, hashAlg="SHA-256") => {
    let message = msg.toString();
    let hmacKey = await crypto.subtle.importKey('raw', bits, {
      "name": "HMAC",
      "hash": hashAlg,
    }, false, ['sign']);
    let sig = await crypto.subtle.sign({
      "name": "HMAC",
      "hash": hashAlg
    }, hmacKey, fromText(message));
    return encode(sig);
  };

  const hmacVerify = async (bits, sig, msg, hashAlg="SHA-256") => {
    let message = msg.toString();
    let verifyKey = await crypto.subtle.importKey('raw', bits, {
      "name": "HMAC",
      "hash": hashAlg,
    }, false, ['verify']);
    let verified = await crypto.subtle.verify({
      "name": "HMAC",
      "hash": hashAlg
    }, verifyKey, decode(sig), fromText(message));
    return verified;
  };

  const digest = async (bits, hashAlg = "SHA-256") => {
    let result = await crypto.subtle.digest({
      "name": hashAlg
    }, bits);
    return toHex(result);
  };

  const pbkdf2 = async (bits, salt, iterations = 1, size = 256, hashAlg = "SHA-256") => {

    let key = await crypto.subtle.importKey('raw', bits, {
      "name": "PBKDF2"
    }, false, ['deriveBits']);

    let result = await crypto.subtle.deriveBits({
      "name": "PBKDF2",
      "salt": salt,
      "iterations": iterations,
      "hash": hashAlg
    }, key, size);

    return encode(result);

  };

  const kdf = async (bits, salt, info, size, hashAlg="SHA-256") => {
    let key = await hmacSign(bits, toText(info));
    let hash = await pbkdf2(decode(key), salt, 1, size, hashAlg);
    return hash;
  };

  const ecdh = async (key, pub, curve = "P-256", size = 256) => {

    let pubKey = await crypto.subtle.importKey('spki', decode(pub), {
      "name": "ECDH",
      "namedCurve": curve
    }, true, []);

    let privateKey = await crypto.subtle.importKey('pkcs8', decode(key), {
      "name": "ECDH",
      "namedCurve": curve
    }, true, ['deriveBits']);

    let shared = await crypto.subtle.deriveBits({
      "name": "ECDH",
      "public": pubKey
    }, privateKey, size);

    let bits = encode(shared);

    return bits;

  };

  const encrypt = async (plaintext, bits, AD = null) => {
    let key = await crypto.subtle.importKey('raw', bits, {
      "name": "AES-GCM"
    }, false, ['encrypt']);
    let iv = random(12);
    let msg = fromText(plaintext);
    let cipher = await crypto.subtle.encrypt({
      "name": "AES-GCM",
      "iv": iv,
      "additionalData": AD || fromText('')
    }, key, msg);
    return encode(iv) + '.' + encode(cipher);
  };

  const decrypt = async (ciphertext = "", bits, AD = null) => {
    let key = await crypto.subtle.importKey('raw', bits, {
      "name": "AES-GCM"
    }, false, ['decrypt']);
    let iv = decode(ciphertext.split('.')[0]);
    let cipher = decode(ciphertext.split('.')[1]);
    let decrypted = await crypto.subtle.decrypt({
      "name": "AES-GCM",
      "iv": iv,
      "additionalData": AD || fromText('')
    }, key, cipher).catch(err => {
      throw({"message":"Failed to decrypt message.", "error":err});
    });
    return toText(decrypted);
  };

  const passwordEncrypt = async (message, password = "", iterations = 100000) => {
    let salt = random(32);
    let keyBits = await pbkdf2(fromText(password), salt, iterations, 256);
    let encrypted = await encrypt(message, decode(keyBits));
    return encode(fromText(iterations.toString())) + '.' + encode(salt) + '.' + encrypted;
  };

  const passwordDecrypt = async (ciphertext = "", password = "") => {
    let iterations = toText(decode(ciphertext.split('.')[0]));
    let salt = ciphertext.split('.')[1];
    let keyBits = await pbkdf2(fromText(password), decode(salt), iterations, 256);
    let encrypted = ciphertext.split('.').slice(2).join('.');
    let decrypted = await decrypt(encrypted, decode(keyBits));
    return decrypted;
  };

  return {combine, createECDH, createECDSA, decode, encode, decrypt, digest, ecdh, ecdsaSign, ecdsaVerify, encode, encrypt, fromHex, fromText, hmacSign, hmacVerify, kdf, passwordDecrypt, passwordEncrypt, pbkdf2, random, "sign":ecdsaSign, toHex, toText, "verify":ecdsaVerify};

}

if (typeof module !== 'undefined' && module && module.exports) {
  module.exports = Cryptic;
}
