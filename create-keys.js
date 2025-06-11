import crypto from 'crypto';
import fs from 'fs';

const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 4096,
  publicKeyEncoding: {
    type: 'spki',
    format: 'pem',
  },
  privateKeyEncoding: {
    type: 'pkcs8',
    format: 'pem' // No encryption
  },
});

console.log("Generated Public Key:", publicKey);
console.log("Generated Private Key:", privateKey);

// Save keys to files
fs.writeFileSync('public.pem', publicKey);
fs.writeFileSync('private.pem', privateKey);

console.log('Unencrypted keys generated and saved.');
