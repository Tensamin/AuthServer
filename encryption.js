async function encrypt_base64_using_aes(base64String, password) {
  let decodedData = Uint8Array.from(atob(base64String), (c) =>
    c.charCodeAt(0),
  );

  let passwordEncoder = new TextEncoder();
  let passwordHash = await crypto.subtle.digest(
    "SHA-256",
    passwordEncoder.encode(password),
  );

  let derivedKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(passwordHash),
    { name: "AES-CBC", length: 256 },
    false,
    ["encrypt"],
  );

  let iv = crypto.getRandomValues(new Uint8Array(16));

  let encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: "AES-CBC",
      iv: iv,
    },
    derivedKey,
    decodedData,
  );

  let combined = new Uint8Array(iv.length + encryptedBuffer.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(encryptedBuffer), iv.length);
  let base64Encrypted = btoa(String.fromCharCode(...combined));

  return base64Encrypted;
}

async function decrypt_base64_using_aes(base64EncryptedString, password) {
  let combinedDecoded = Uint8Array.from(
    atob(base64EncryptedString),
    (c) => c.charCodeAt(0),
  );

  let iv = combinedDecoded.slice(0, 16);
  let ciphertext = combinedDecoded.slice(16);

  let passwordEncoder = new TextEncoder();
  let passwordHash = await crypto.subtle.digest(
    "SHA-256",
    passwordEncoder.encode(password),
  );

  let derivedKey = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(passwordHash),
    { name: "AES-CBC", length: 256 },
    false,
    ["decrypt"],
  );

  let decryptedBuffer = await crypto.subtle.decrypt(
    {
      name: "AES-CBC",
      iv: iv,
    },
    derivedKey,
    ciphertext,
  );

  let decryptedData = new Uint8Array(decryptedBuffer);
  let originalBase64String = btoa(String.fromCharCode(...decryptedData));

  return originalBase64String;
}

async function encrypt_json_using_pubkey(jsonData, pemPublicKey) {
  // Process public key
  let pemHeader = "-----BEGIN PUBLIC KEY-----";
  let pemFooter = "-----END PUBLIC KEY-----";
  let pemContents = pemPublicKey.replace(pemHeader, "").replace(pemFooter, "").replace(/\s+/g, "");
  let binaryDer = Uint8Array.from(atob(pemContents), c => c.charCodeAt(0));

  // Import RSA public key
  let rsaKey = await crypto.subtle.importKey(
    "spki",
    binaryDer,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["encrypt"]
  );

  // Generate AES key
  let aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt"]
  );

  // Export raw AES key and encrypt with RSA
  let rawAesKey = await crypto.subtle.exportKey("raw", aesKey);
  let encryptedAesKey = await crypto.subtle.encrypt(
    { name: "RSA-OAEP" },
    rsaKey,
    rawAesKey
  );

  // Encrypt JSON data with AES
  let iv = crypto.getRandomValues(new Uint8Array(12));
  let jsonBytes = new TextEncoder().encode(JSON.stringify(jsonData));
  let encryptedData = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    jsonBytes
  );

  // Prepare output (combines RSA-encrypted AES key + IV + AES-encrypted data)
  let payload = new Uint8Array(
    encryptedAesKey.byteLength +
    iv.byteLength +
    encryptedData.byteLength
  );

  payload.set(new Uint8Array(encryptedAesKey), 0);
  payload.set(iv, encryptedAesKey.byteLength);
  payload.set(new Uint8Array(encryptedData), encryptedAesKey.byteLength + iv.byteLength);

  return btoa(String.fromCharCode(...payload));
}

async function decrypt_json_using_privkey(encryptedData, pemPrivateKey) {
  // Process private key
  let pemHeader = "-----BEGIN PRIVATE KEY-----";
  let pemFooter = "-----END PRIVATE KEY-----";
  let pemContents = pemPrivateKey.replace(pemHeader, "").replace(pemFooter, "").replace(/\s+/g, "");
  let binaryKey = atob(pemContents);
  let keyBuffer = new Uint8Array([...binaryKey].map(char => char.charCodeAt(0))).buffer;

  // Import RSA private key
  let cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    keyBuffer,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["decrypt"]
  );

  // Get RSA key modulus length (in bytes)
  let modulusLengthBytes = cryptoKey.algorithm.modulusLength / 8;

  // Decode base64 payload
  let rawPayload = atob(encryptedData);
  let payload = new Uint8Array(rawPayload.length);
  for (let i = 0; i < rawPayload.length; i++) {
    payload[i] = rawPayload.charCodeAt(i);
  }

  // Extract components from payload
  if (payload.length < modulusLengthBytes + 12) {
    throw new Error("Invalid payload: too short");
  }

  let encryptedAesKey = payload.subarray(0, modulusLengthBytes);
  let iv = payload.subarray(modulusLengthBytes, modulusLengthBytes + 12);
  let ciphertext = payload.subarray(modulusLengthBytes + 12);

  // Decrypt AES key with RSA private key
  let rawAesKey = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    cryptoKey,
    encryptedAesKey
  );

  // Import decrypted AES key
  let aesKey = await crypto.subtle.importKey(
    "raw",
    rawAesKey,
    { name: "AES-GCM" },
    true,
    ["decrypt"]
  );

  // Decrypt data with AES
  let decryptedData = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv: iv
    },
    aesKey,
    ciphertext
  );

  // Return parsed JSON
  return JSON.parse(new TextDecoder().decode(decryptedData));
}

async function sha256(message) {
  let encoder = new TextEncoder();
  let data = encoder.encode(message);
  let hashBuffer = await crypto.subtle.digest("SHA-256", data);

  return Array.from(new Uint8Array(hashBuffer))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function encryptedFetch(url, method, data) {
    let pubkey;

    await fetch(endpoint.public_key)
    .then(response => response.text())
    .then(data => {
        pubkey = data;
    });

    let finalData = await encrypt_json_using_pubkey(data, pubkey)

    let response = await fetch(url, {
        method: method,
        headers: {
          'Content-Type': 'text/plain'
        },
        body: finalData,
    });

    return response;
}

async function createPasskey(userId) {
  let creds = await navigator.credentials.create({
    publicKey: {
      challenge: btoa("alar"),
      rp: { name: "Tensamin" },
      user: {
        id: btoa(userId),
        name: userId,
        displayName: ""
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }],
    }
  });

  return creds.id;
}

if (typeof module !== 'undefined' && module.exports) {
  console.log('Loading Encryption Modules for NodeJS');
  module.exports = {
    sha256: sha256,
    encrypt_base64_using_aes: encrypt_base64_using_aes,
    createPasskey: createPasskey,
    decrypt_base64_using_aes: decrypt_base64_using_aes,
    encrypt_json_using_pubkey: encrypt_json_using_pubkey,
    decrypt_json_using_privkey: decrypt_json_using_privkey,
    encryptedFetch: encryptedFetch,
  };
} else {
  console.log('Loading Encryption Modules for Browser');
  window.encryption_module = {
    encrypt_base64_using_aes,
    decrypt_base64_using_aes,
    encrypt_json_using_pubkey,
    decrypt_json_using_privkey,
    sha256,
    encryptedFetch,
    createPasskey,
  }
}