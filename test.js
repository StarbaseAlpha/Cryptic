'use strict';

const path = require('path');
const Cryptic = require(__dirname + path.sep + 'index.js');
const cryptic = Cryptic();

async function Test(params={}) {

    let alice = {};
    alice.idk = await cryptic.createECDSA();
    alice.spk = await cryptic.createECDH();
    alice.sig = await cryptic.sign(alice.idk.key, alice.spk.pub);
    alice.card = {
      "idk":alice.idk.pub,
      "spk":alice.spk.pub,
      "sig":alice.sig
    };

    let bob = {};
    bob.idk = await cryptic.createECDSA();
    bob.spk = await cryptic.createECDH();
    bob.sig = await cryptic.sign(bob.idk.key, bob.spk.pub);
    bob.card = {
      "idk":bob.idk.pub,
      "spk":bob.spk.pub,
      "sig":bob.sig
    };

    alice.card.verified = await cryptic.verify(alice.card.idk, alice.card.sig, alice.card.spk);
    bob.card.verified = await cryptic.verify(bob.card.idk, bob.card.sig, bob.card.spk);

    alice.sharedKey = await cryptic.ecdh(alice.spk.key, bob.card.spk);
    bob.sharedKey = await cryptic.ecdh(bob.spk.key, alice.card.spk);

    alice.hashKey = await cryptic.kdf(cryptic.decode(alice.sharedKey), new Uint8Array([0]), cryptic.fromText("Hash"), 256, "SHA-256");
    bob.hashKey = await cryptic.kdf(cryptic.decode(bob.sharedKey), new Uint8Array([0]), cryptic.fromText("Hash"), 256, "SHA-256");

    alice.encrypted = await cryptic.encrypt("Hello Bob!", cryptic.decode(alice.sharedKey));
    bob.decrypted = await cryptic.decrypt(alice.encrypted, cryptic.decode(bob.sharedKey));

    return {alice, bob};

}

Test({}).then(console.log).catch(console.log);
