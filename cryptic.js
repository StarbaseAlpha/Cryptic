'use strict';

function Cryptic(webCrypto, encoder, decoder) {

  let cryptic = {};

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

  const toHex = cryptic.toHex = (byteArray) => {
    return Array.from(new Uint8Array(byteArray)).map(val => {
      return ('0' + val.toString(16)).slice(-2);
    }).join('');
  };

  const fromHex = cryptic.fromHex = (str) => {
    let result = new Uint8Array(str.match(/.{0,2}/g).map(val => {
      return parseInt(val, 16);
    }));
    return result.slice(0, result.length - 1);
  };

  const encode = cryptic.encode = (byteArray) => {
    return btoa(Array.from(new Uint8Array(byteArray)).map(val => {
      return String.fromCharCode(val);
    }).join('')).replace(/\+/g, '-').replace(/\//g, '_').replace(/\=/g, '');
  };

  const decode = cryptic.decode = (str) => {
    return new Uint8Array(atob(str.replace(/\_/g, '/').replace(/\-/g, '+')).split('').map(val => {
      return val.charCodeAt(0);
    }));
  };

  const fromText = cryptic.fromText = (string) => {
    return new TextEncoder().encode(string);
  };

  const toText = cryptic.toText = (byteArray) => {
    return new TextDecoder().decode(byteArray);
  };

  const combine = cryptic.combine = (bitsA = [], bitsB = []) => {
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

  const random = cryptic.random = (size) => {
    return crypto.getRandomValues(new Uint8Array(size));
  };

  const createECDH = cryptic.createECDH = async (curve = "P-256") => {
    let DH = await crypto.subtle.generateKey({
      "name": "ECDH",
      "namedCurve": curve
    }, true, ['deriveBits']);
    let pub = await crypto.subtle.exportKey('spki', DH.publicKey);
    let key = encode(await crypto.subtle.exportKey('pkcs8', DH.privateKey));
    return {
      "pub": encode(pub),
      "key": key
    };
  };

  const createECDSA = cryptic.createECDSA = async (curve = "P-256") => {
    let user = await crypto.subtle.generateKey({
      "name": "ECDSA",
      "namedCurve": curve
    }, true, ['sign', 'verify']);
    let pub = await crypto.subtle.exportKey('spki', user.publicKey);
    let key = encode(await crypto.subtle.exportKey('pkcs8', user.privateKey));
    return {
      "pub": encode(pub),
      "key": key
    };
  };

  const ecdsaSign = cryptic.ecdsaSign = cryptic.sign = async (key, msg, curve = "P-256", hashAlg = "SHA-256") => {
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

  const ecdsaVerify = cryptic.ecdsaVerify = cryptic.verify = async (pub, sig, msg, curve = "P-256", hashAlg = "SHA-256") => {
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

  const hmacSign = cryptic.hmacSign = async (bits, msg, hashAlg="SHA-256") => {
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

  const hmacVerify = cryptic.hmacVerify = async (bits, sig, msg, hashAlg="SHA-256") => {
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

  const digest = cryptic.digest = async (bits, hashAlg = "SHA-256") => {
    let digest = await crypto.subtle.digest({
      "name": hashAlg
    }, bits);
    return toHex(digest);
  };

  const pbkdf2 = cryptic.pbkdf2 = async (bits, salt, iterations = 1, size = 256, hashAlg = "SHA-256") => {

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

  const hkdf = cryptic.hkdf = async (bits, salt, info, size, hashAlg="SHA-256") => {
    let ikm = bits;
    let len = size;
    let hashSize = 256;
    if (hashAlg.toLocaleUpperCase() === 'SHA-512') {
      hashSize = 512;
    }
    if (len > 255 * hashSize) {
      throw("Error: Size exceeds maximum output length for selected hash.");
    }
    if (len < 8) {
      throw("Error: Size cannot be smaller 8 bits.");
    }
    if (len / 8 !== parseInt(len / 8)) {
      throw("Error: Size must be a multiple of 8 bits.");
    }

    let PRK = await hmacSign(salt, toText(ikm), hashAlg);
    let result = new Uint8Array([]);
    let T = new Uint8Array([]);
    let rounds = Math.ceil(size / hashSize);
    for (let i = 0; i < rounds; i++) {
      let num = toText(new Uint8Array([i + 1]));
      let t = toText(T) + toText(info);
      let msg = t + num;
      T = decode(await hmacSign(decode(PRK), msg, hashAlg));
      result = combine(result, T);
    }
    return await encode(result.slice(0, len / 8));
  };

  const kdf = cryptic.kdf = async (bits, salt, info, size, hashAlh="SHA-256") => {
    let key = await cryptic.hmacSign(bits, cryptic.toText(info));
    let hash = await cryptic.pbkdf2(cryptic.decode(key), salt, 1, size);
    return hash;
  };

  const ecdh = cryptic.ecdh = async (key, pub, curve = "P-256", size = 256) => {

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

  const encrypt = cryptic.encrypt = async (plaintext, bits, AD = null) => {
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

  const decrypt = cryptic.decrypt = async (ciphertext = "", bits, AD = null) => {
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

  const passwordEncrypt = cryptic.passwordEncrypt = async (message, password = "", iterations = 100000) => {
    let salt = random(32);
    let keyBits = await pbkdf2(fromText(password), salt, iterations, 256);
    let encrypted = await encrypt(message, decode(keyBits));
    return encode(fromText(iterations.toString())) + '.' + encode(salt) + '.' + encrypted;
  };

  const passwordDecrypt = cryptic.passwordDecrypt = async (ciphertext = "", password = "") => {
    let iterations = toText(decode(ciphertext.split('.')[0]));
    let salt = ciphertext.split('.')[1];
    let keyBits = await pbkdf2(fromText(password), decode(salt), iterations, 256);
    let encrypted = ciphertext.split('.').slice(2).join('.');
    let decrypted = await decrypt(encrypted, decode(keyBits));
    return decrypted;
  };

  return cryptic;

}

if (typeof module !== 'undefined' && module && module.exports) {
  module.exports = Cryptic;
}
