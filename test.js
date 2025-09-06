const libsignal = require('./dist/index').default;
const { pubKey, privKey } = libsignal.curve.generateKeyPair()
console.log('Public Key:', pubKey);
console.log('Private Key:', privKey);
