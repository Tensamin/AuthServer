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

async function encrypt_base64_using_pubkey(base64String, pemPublicKey) {
  // Process public key
  let pemHeader = "-----BEGIN PUBLIC KEY-----";
  let pemFooter = "-----END PUBLIC KEY-----";
  let pemContents = pemPublicKey
    .replace(pemHeader, "")
    .replace(pemFooter, "")
    .replace(/\s+/g, "");
  let binaryDer = Uint8Array.from(atob(pemContents), (c) =>
    c.charCodeAt(0)
  );

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

  // Encrypt Base64 data with AES
  let iv = crypto.getRandomValues(new Uint8Array(12));
  // --- KEY CHANGE IS HERE ---
  // Decode the Base64 input data into a byte array
  let dataBytes = Uint8Array.from(atob(base64String), (c) => c.charCodeAt(0));
  // ---

  let encryptedData = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    aesKey,
    dataBytes // Use the decoded byte array
  );

  // Prepare output (combines RSA-encrypted AES key + IV + AES-encrypted data)
  let payload = new Uint8Array(
    encryptedAesKey.byteLength + iv.byteLength + encryptedData.byteLength
  );

  payload.set(new Uint8Array(encryptedAesKey), 0);
  payload.set(iv, encryptedAesKey.byteLength);
  payload.set(
    new Uint8Array(encryptedData),
    encryptedAesKey.byteLength + iv.byteLength
  );

  return btoa(String.fromCharCode(...payload));
}

async function decrypt_base64_using_privkey(base64EncryptedString, pemPrivateKey) {
  // Process private key
  let pemHeader = "-----BEGIN PRIVATE KEY-----";
  let pemFooter = "-----END PRIVATE KEY-----";
  let pemContents = pemPrivateKey
    .replace(pemHeader, "")
    .replace(pemFooter, "")
    .replace(/\s+/g, "");
  let keyBuffer = Uint8Array.from(atob(pemContents), (c) =>
    c.charCodeAt(0)
  ).buffer;

  // Import RSA private key
  let cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    keyBuffer,
    { name: "RSA-OAEP", hash: "SHA-256" },
    true,
    ["decrypt"]
  );

  // Get RSA key modulus length (in bytes) to determine the AES key size
  let modulusLengthBytes = cryptoKey.algorithm.modulusLength / 8;

  // Decode base64 payload into a byte array
  let payload = Uint8Array.from(atob(base64EncryptedString), (c) =>
    c.charCodeAt(0)
  );

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
      iv: iv,
    },
    aesKey,
    ciphertext
  );

  // --- KEY CHANGE IS HERE ---
  // Convert the decrypted ArrayBuffer to a UTF-8 string
  const textDecoder = new TextDecoder("utf-8");
  return textDecoder.decode(decryptedData);
  // ---
}

async function sign_data_using_privkey(dataToSign, privateKey) {
  async function importPkcs8PrivateKey(base64PrivateKey) {
    let pkcs8 = base64PrivateKey
      .replace(/-----BEGIN PRIVATE KEY-----/g, "")
      .replace(/-----END PRIVATE KEY-----/g, "")
      .replace(/\s/g, "");

    let binaryDer = atob(pkcs8);

    let pkcs8Der = new Uint8Array(binaryDer.length);
    for (let i = 0; i < binaryDer.length; i++) {
      pkcs8Der[i] = binaryDer.charCodeAt(i);
    }

    let privateKey = await crypto.subtle.importKey(
      "pkcs8",
      pkcs8Der,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: { name: "SHA-256" },
      },
      true,
      ["sign"]
    );

    return privateKey;
  }

  privateKey = await importPkcs8PrivateKey(privateKey)

  let encoder = new TextEncoder();
  let data = encoder.encode(dataToSign);

  let signature = await window.crypto.subtle.sign(
    {
      name: "RSASSA-PKCS1-V1_5",
      hash: "SHA-256",
    },
    privateKey,
    data
  );

  return btoa(String.fromCharCode(...new Uint8Array(signature)));
}

async function verify_signed_data_using_pubkey(originalData, base64Signature, publicKey) {
  let encoder = new TextEncoder();
  let data = encoder.encode(originalData);
  let signature = new Uint8Array(
    atob(base64Signature).split("").map((char) => char.charCodeAt(0))
  );

  try {
    let isValid = await window.crypto.subtle.verify(
      {
        name: "RSASSA-PKCS1-V1_5",
        hash: "SHA-256",
      },
      publicKey,
      signature,
      data
    );
    return isValid;
  } catch (error) {
    console.error("Error during signature verification:", error);
    return false;
  }
}

async function sha256(message) {
  let encoder = new TextEncoder();
  let data = encoder.encode(message);
  let hashBuffer = await crypto.subtle.digest("SHA-256", data);

  return Array.from(new Uint8Array(hashBuffer))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function createPasskey(userId) {
  let creds = await navigator.credentials.create({
    publicKey: {
      challenge: btoa("alar"),
      rp: { name: "Tensamin" },
      user: {
        id: userId,
        name: userId,
        displayName: "Tensamin",
      },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }], // ES256
      authenticatorSelection: {
        authenticatorAttachment: "platform",
        requireResidentKey: true,
        userVerification: "required",
      },
      timeout: 60000,
      attestation: "none",
    },
  });

  localStorage.setItem(
    "passkey_id",
    creds.id,
  );

  return creds.id;
}

async function getDerivedKey(passkey_id) {
  try {
    let creds = await navigator.credentials.get({
      publicKey: {
        challenge: btoa("alar"),
        allowCredentials: [
          {
            type: "public-key",
            id: passkey_id,
          },
        ],
        userVerification: "required",
      },
    });

    let signature = creds.response.signature;

    let derivedKey = await sha256(signature);
    return derivedKey;
  } catch (err) {
    throw new Error(`Could not get signature: ${err.message}`);
  }
}

if (typeof module !== 'undefined' && module.exports) {
  console.log('Loading Encryption Modules for NodeJS');
  module.exports = {
    sha256: sha256,
    encrypt_base64_using_aes: encrypt_base64_using_aes,
    createPasskey: createPasskey,
    decrypt_base64_using_aes: decrypt_base64_using_aes,
    encrypt_base64_using_pubkey: encrypt_base64_using_pubkey,
    decrypt_base64_using_privkey: decrypt_base64_using_privkey,
    sign_data_using_privkey: sign_data_using_privkey,
    verify_signed_data_using_pubkey: verify_signed_data_using_pubkey,
    getDerivedKey: getDerivedKey,
  };
} else {
  console.log('Loading Encryption Modules for Browser');
  window.encryption_module = {
    encrypt_base64_using_aes,
    decrypt_base64_using_aes,
    encrypt_base64_using_pubkey,
    decrypt_base64_using_privkey,
    sha256,
    createPasskey,
    sign_data_using_privkey,
    verify_signed_data_using_pubkey,
    getDerivedKey,
  }
}