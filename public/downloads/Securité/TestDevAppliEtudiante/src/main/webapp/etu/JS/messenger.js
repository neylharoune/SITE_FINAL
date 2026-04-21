// src/libCrypto.ts
async function stringToPublicKeyForEncryption(pkeyBase64) {
  try {
    const keyArrayBuffer = base64StringToArrayBuffer(pkeyBase64);
    const key = await window.crypto.subtle.importKey(
      "spki",
      keyArrayBuffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      true,
      ["encrypt"]
    );
    return key;
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("String for the public key (for encryption) is ill-formed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("String for the public key (for encryption) is ill-formed!");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function stringToPublicKeyForSignature(pkeyBase64) {
  try {
    const keyArrayBuffer = base64StringToArrayBuffer(pkeyBase64);
    const key = await window.crypto.subtle.importKey(
      "spki",
      keyArrayBuffer,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256"
      },
      true,
      ["verify"]
    );
    return key;
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("String for the public key (for signature verification) is ill-formed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("String for the public key (for signature verification) is ill-formed!");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function stringToPrivateKeyForEncryption(skeyBase64) {
  try {
    const keyArrayBuffer = base64StringToArrayBuffer(skeyBase64);
    const key = await window.crypto.subtle.importKey(
      "pkcs8",
      keyArrayBuffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      true,
      ["decrypt"]
    );
    return key;
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("String for the private key (for decryption) is ill-formed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("String for the private key (for decryption) is ill-formed!");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function stringToPrivateKeyForSignature(skeyBase64) {
  try {
    const keyArrayBuffer = base64StringToArrayBuffer(skeyBase64);
    const key = await window.crypto.subtle.importKey(
      "pkcs8",
      keyArrayBuffer,
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256"
      },
      true,
      ["sign"]
    );
    return key;
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("String for the private key (for signature) is ill-formed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("String for the private key (for signature) is ill-formed!");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function publicKeyToString(key) {
  const exportedKey = await window.crypto.subtle.exportKey("spki", key);
  return arrayBufferToBase64String(exportedKey);
}
async function privateKeyToString(key) {
  const exportedKey = await window.crypto.subtle.exportKey("pkcs8", key);
  return arrayBufferToBase64String(exportedKey);
}
async function generateasymmetricKeysForEncryption() {
  const keypair = await window.crypto.subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["encrypt", "decrypt"]
  );
  return [keypair.publicKey, keypair.privateKey];
}
async function generateasymmetricKeysForSignature() {
  const keypair = await window.crypto.subtle.generateKey(
    {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: "SHA-256"
    },
    true,
    ["sign", "verify"]
  );
  return [keypair.publicKey, keypair.privateKey];
}
function generateNonce() {
  const nonceArray = new Uint32Array(1);
  self.crypto.getRandomValues(nonceArray);
  return nonceArray[0].toString();
}
async function encryptWithPublicKey(publicKey, message) {
  try {
    const messageToArrayBuffer = textToArrayBuffer(message);
    const cypheredMessageAB = await window.crypto.subtle.encrypt(
      { name: "RSA-OAEP" },
      publicKey,
      messageToArrayBuffer
    );
    return arrayBufferToBase64String(cypheredMessageAB);
  } catch (e) {
    if (e instanceof DOMException) {
      console.log(e);
      console.log("Encryption failed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("Public key or message to encrypt is ill-formed");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function signWithPrivateKey(privateKey, message) {
  try {
    const messageToArrayBuffer = textToArrayBuffer(message);
    const signedMessageAB = await window.crypto.subtle.sign(
      "RSASSA-PKCS1-v1_5",
      privateKey,
      messageToArrayBuffer
    );
    return arrayBufferToBase64String(signedMessageAB);
  } catch (e) {
    if (e instanceof DOMException) {
      console.log(e);
      console.log("Signature failed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("Private key or message to sign is ill-formed");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function decryptWithPrivateKey(privateKey, message) {
  try {
    const decrytpedMessageAB = await window.crypto.subtle.decrypt(
      { name: "RSA-OAEP" },
      privateKey,
      base64StringToArrayBuffer(message)
    );
    return arrayBufferToText(decrytpedMessageAB);
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("Invalid key, message or algorithm for decryption");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("Private key or message to decrypt is ill-formed");
    } else console.log("Decryption failed");
    throw e;
  }
}
async function verifySignatureWithPublicKey(publicKey, messageInClear, signedMessage) {
  try {
    const signedToArrayBuffer = base64StringToArrayBuffer(signedMessage);
    const messageInClearToArrayBuffer = textToArrayBuffer(messageInClear);
    const verified = await window.crypto.subtle.verify(
      "RSASSA-PKCS1-v1_5",
      publicKey,
      signedToArrayBuffer,
      messageInClearToArrayBuffer
    );
    return verified;
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("Invalid key, message or algorithm for signature verification");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("Public key or signed message to verify is ill-formed");
    } else console.log("Decryption failed");
    throw e;
  }
}
async function generateSymetricKey() {
  const key = await window.crypto.subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256
    },
    true,
    ["encrypt", "decrypt"]
  );
  return key;
}
async function symmetricKeyToString(key) {
  const exportedKey = await window.crypto.subtle.exportKey("raw", key);
  return arrayBufferToBase64String(exportedKey);
}
async function stringToSymmetricKey(skeyBase64) {
  try {
    const keyArrayBuffer = base64StringToArrayBuffer(skeyBase64);
    const key = await window.crypto.subtle.importKey(
      "raw",
      keyArrayBuffer,
      "AES-GCM",
      true,
      ["encrypt", "decrypt"]
    );
    return key;
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("String for the symmetric key is ill-formed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("String for the symmetric key is ill-formed!");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function encryptWithSymmetricKey(key, message) {
  try {
    const messageToArrayBuffer = textToArrayBuffer(message);
    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    const ivText = arrayBufferToBase64String(iv);
    const cypheredMessageAB = await window.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      key,
      messageToArrayBuffer
    );
    return [arrayBufferToBase64String(cypheredMessageAB), ivText];
  } catch (e) {
    if (e instanceof DOMException) {
      console.log(e);
      console.log("Encryption failed!");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("Symmetric key or message to encrypt is ill-formed");
    } else {
      console.log(e);
    }
    throw e;
  }
}
async function decryptWithSymmetricKey(key, message, initVector) {
  const decodedInitVector = base64StringToArrayBuffer(initVector);
  try {
    const decrytpedMessageAB = await window.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: decodedInitVector },
      key,
      base64StringToArrayBuffer(message)
    );
    return arrayBufferToText(decrytpedMessageAB);
  } catch (e) {
    if (e instanceof DOMException) {
      console.log("Invalid key, message or algorithm for decryption");
    } else if (e instanceof KeyStringCorrupted) {
      console.log("Symmetric key or message to decrypt is ill-formed");
    } else console.log("Decryption failed");
    throw e;
  }
}
async function hash(text) {
  const text2arrayBuf = textToArrayBuffer(text);
  const hashedArray = await window.crypto.subtle.digest("SHA-256", text2arrayBuf);
  return arrayBufferToBase64String(hashedArray);
}
var KeyStringCorrupted = class extends Error {
};
function arrayBufferToBase64String(arrayBuffer) {
  var byteArray = new Uint8Array(arrayBuffer);
  var byteString = "";
  for (var i = 0; i < byteArray.byteLength; i++) {
    byteString += String.fromCharCode(byteArray[i]);
  }
  return btoa(byteString);
}
function base64StringToArrayBuffer(b64str) {
  try {
    var byteStr = atob(b64str);
    var bytes = new Uint8Array(byteStr.length);
    for (var i = 0; i < byteStr.length; i++) {
      bytes[i] = byteStr.charCodeAt(i);
    }
    return bytes.buffer;
  } catch (e) {
    console.log(`String starting by '${b64str.substring(0, 10)}' cannot be converted to a valid key or message`);
    throw new KeyStringCorrupted();
  }
}
function textToArrayBuffer(str) {
  var buf = encodeURIComponent(str);
  var bufView = new Uint8Array(buf.length);
  for (var i = 0; i < buf.length; i++) {
    bufView[i] = buf.charCodeAt(i);
  }
  return bufView;
}
function arrayBufferToText(arrayBuffer) {
  var byteArray = new Uint8Array(arrayBuffer);
  var str = "";
  for (var i = 0; i < byteArray.byteLength; i++) {
    str += String.fromCharCode(byteArray[i]);
  }
  return decodeURIComponent(str);
}

// src/messenger.ts
if (!window.isSecureContext) alert("Not secure context!");
var CasUserName = class {
  constructor(username) {
    this.username = username;
  }
};
var KeyRequest = class {
  constructor(ownerOfTheKey, publicKey, encryption) {
    this.ownerOfTheKey = ownerOfTheKey;
    this.publicKey = publicKey;
    this.encryption = encryption;
  }
};
var KeyResult = class {
  constructor(success, key, errorMessage) {
    this.success = success;
    this.key = key;
    this.errorMessage = errorMessage;
  }
};
var ExtMessage = class {
  constructor(sender, receiver2, content) {
    this.sender = sender;
    this.receiver = receiver2;
    this.content = content;
  }
};
var SendResult = class {
  constructor(success, errorMessage) {
    this.success = success;
    this.errorMessage = errorMessage;
  }
};
var HistoryRequest = class {
  constructor(agentName, index) {
    this.agentName = agentName;
    this.index = index;
  }
};
var HistoryAnswer = class {
  constructor(success, failureMessage, index, allMessages) {
    this.success = success;
    this.failureMessage = failureMessage;
    this.index = index;
    this.allMessages = allMessages;
  }
};
var globalUserName = "";
async function fetchCasName() {
  const urlParams = new URLSearchParams(window.location.search);
  const namerequest = await fetch("/getuser?" + urlParams, {
    method: "GET",
    headers: {
      "Content-type": "application/json; charset=UTF-8"
    }
  });
  if (!namerequest.ok) {
    throw new Error(`Error! status: ${namerequest.status}`);
  }
  const nameResult = await namerequest.json();
  console.log("Fetched CAS name= " + nameResult.username);
  return nameResult.username;
}
async function setCasName() {
  globalUserName = await fetchCasName();
  userButtonLabel.textContent = globalUserName;
}
setCasName();
function getOwnerName() {
  const path = window.location.pathname;
  const name = path.split("/", 2)[1];
  return name;
}
var ownerName = getOwnerName();
async function fetchKey(user, publicKey, encryption) {
  const keyRequestMessage = new KeyRequest(user, publicKey, encryption);
  const urlParams = new URLSearchParams(window.location.search);
  const keyrequest = await fetch("/getKey?" + urlParams, {
    method: "POST",
    body: JSON.stringify(keyRequestMessage),
    headers: {
      "Content-type": "application/json; charset=UTF-8"
    }
  });
  if (!keyrequest.ok) {
    throw new Error(`Error! status: ${keyrequest.status}`);
  }
  const keyResult = await keyrequest.json();
  if (!keyResult.success) alert(keyResult.errorMessage);
  else {
    if (publicKey && encryption) return await stringToPublicKeyForEncryption(keyResult.key);
    else if (!publicKey && encryption) return await stringToPrivateKeyForEncryption(keyResult.key);
    else if (publicKey && !encryption) return await stringToPublicKeyForSignature(keyResult.key);
    else if (!publicKey && !encryption) return await stringToPrivateKeyForSignature(keyResult.key);
  }
}
async function sendMessage(agentName, receiverName, messageContent) {
  try {
    let messageToSend = new ExtMessage(agentName, receiverName, messageContent);
    const urlParams = new URLSearchParams(window.location.search);
    const request = await fetch("/sendingMessage/" + ownerName + "?" + urlParams, {
      method: "POST",
      body: JSON.stringify(messageToSend),
      headers: {
        "Content-type": "application/json; charset=UTF-8"
      }
    });
    if (!request.ok) {
      throw new Error(`Error! status: ${request.status}`);
    }
    console.log(`Sent message from ${agentName} to ${receiverName}: ${messageContent}`);
    return await request.json();
  } catch (error) {
    if (error instanceof Error) {
      console.log("error message: ", error.message);
      return new SendResult(false, error.message);
    } else {
      console.log("unexpected error: ", error);
      return new SendResult(false, "An unexpected error occurred");
    }
  }
}
var userButtonLabel = document.getElementById("user-name");
var sendButton = document.getElementById("send-button");
var receiver = document.getElementById("receiver");
var messageG = document.getElementById("message");
var received_messages = document.getElementById("exchanged-messages");
function addingReceivedMessage(message) {
  const p = document.createElement("p");
  p.textContent = message;
  received_messages.append(p);
}
async function hybridEncrypt(rsaPublicKey, message) {
  const aesKey = await generateSymetricKey();
  const [cyphered, iv] = await encryptWithSymmetricKey(aesKey, message);
  const aesKeyStr = await symmetricKeyToString(aesKey);
  const encryptedAesKey = await encryptWithPublicKey(rsaPublicKey, aesKeyStr);
  return JSON.stringify({ rsakey: encryptedAesKey, cyphered, iv });
}
async function hybridDecrypt(rsaPrivateKey, encryptedPayload) {
  const { rsakey, cyphered, iv } = JSON.parse(encryptedPayload);
  const aesKeyStr = await decryptWithPrivateKey(rsaPrivateKey, rsakey);
  const aesKey = await stringToSymmetricKey(aesKeyStr);
  return await decryptWithSymmetricKey(aesKey, cyphered, iv);
}
var localStorageAesKey = null;
async function getLocalAesKey() {
  if (localStorageAesKey) return localStorageAesKey;
  const privKeyRSA = await fetchKey(globalUserName, false, true);
  const privKeyStr = await privateKeyToString(privKeyRSA);
  const hashOfKey = await hash(privKeyStr);
  const rawBytes = atob(hashOfKey).slice(0, 32);
  const rawArray = new Uint8Array(rawBytes.length);
  for (let i = 0; i < rawBytes.length; i++) rawArray[i] = rawBytes.charCodeAt(i);
  localStorageAesKey = await window.crypto.subtle.importKey(
    "raw",
    rawArray,
    "AES-GCM",
    false,
    ["encrypt", "decrypt"]
  );
  return localStorageAesKey;
}
function localStorageKeyName() {
  return `history_${globalUserName}`;
}
async function readLocalHistory() {
  try {
    const raw = localStorage.getItem(localStorageKeyName());
    if (!raw) return [];
    const { cyphered, iv } = JSON.parse(raw);
    const aesKey = await getLocalAesKey();
    const decrypted = await decryptWithSymmetricKey(aesKey, cyphered, iv);
    return JSON.parse(decrypted);
  } catch (e) {
    console.log("Erreur lecture historique : ", e);
    return [];
  }
}
async function saveToLocalHistory(entry) {
  try {
    const existing = await readLocalHistory();
    existing.push(entry);
    const aesKey = await getLocalAesKey();
    const [cyphered, iv] = await encryptWithSymmetricKey(aesKey, JSON.stringify(existing));
    localStorage.setItem(localStorageKeyName(), JSON.stringify({ cyphered, iv }));
  } catch (e) {
    console.log("Erreur sauvegarde historique : ", e);
  }
}
async function loadLocalHistory() {
  const entries = await readLocalHistory();
  for (const entry of entries) {
    addingReceivedMessage(entry);
  }
}
async function displayAndSave(text) {
  addingReceivedMessage(text);
  await saveToLocalHistory(text);
}
function loadLastIndex() {
  return parseInt(localStorage.getItem(`lastIndex_${globalUserName}`) || "0");
}
function saveLastIndex(index) {
  localStorage.setItem(`lastIndex_${globalUserName}`, index.toString());
}
var lastIndexInHistory = 0;
async function init() {
  while (globalUserName === "") {
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  await loadLocalHistory();
  lastIndexInHistory = loadLastIndex();
  setInterval(refresh, 2e3);
}
init();
async function refresh() {
  try {
    const user = globalUserName;
    const historyRequest = new HistoryRequest(user, lastIndexInHistory);
    const urlParams = new URLSearchParams(window.location.search);
    const request = await fetch("/history/" + ownerName + "?" + urlParams, {
      method: "POST",
      body: JSON.stringify(historyRequest),
      headers: { "Content-type": "application/json; charset=UTF-8" }
    });
    if (!request.ok) throw new Error(`Error! status: ${request.status}`);
    const result = await request.json();
    if (!result.success) {
      alert(result.failureMessage);
    } else {
      lastIndexInHistory = result.index;
      saveLastIndex(result.index);
      for (const m of result.allMessages) {
        await analyseMessage(m);
      }
    }
  } catch (error) {
    console.log("Erreur refresh: ", error);
  }
}
sendButton.onclick = async function() {
  const agentName = globalUserName;
  const receiverName = receiver.value.trim();
  const messageContent = messageG.value.trim();
  if (!receiverName || !messageContent) return;
  try {
    console.log(`Etape 1 : ${agentName} envoie un message a ${receiverName}`);
    const privKeyA = await fetchKey(agentName, false, false);
    const signature = await signWithPrivateKey(privKeyA, "1|" + agentName + "|" + receiverName + "|" + messageContent);
    const pkeyB = await fetchKey(receiverName, true, true);
    const payload = JSON.stringify(["1", agentName, messageContent, signature]);
    const encryptedMessage = await hybridEncrypt(pkeyB, payload);
    const sendResult = await sendMessage(agentName, receiverName, encryptedMessage);
    if (!sendResult.success) return;
    await displayAndSave(`${agentName} -> ${receiverName} : ${messageContent}`);
    messageG.value = "";
  } catch (error) {
    console.log("Erreur envoi : ", error);
  }
};
async function analyseMessage(message) {
  const agentName = globalUserName;
  try {
    if (message.receiver !== agentName) return;
    const privKey = await fetchKey(agentName, false, true);
    const messageInClear = await hybridDecrypt(privKey, message.content);
    const dataArray = JSON.parse(messageInClear);
    const index = parseInt(dataArray[0], 10);
    switch (index) {
      case 1: {
        const senderA = dataArray[1];
        const m = dataArray[2];
        const sig = dataArray[3];
        if (senderA === agentName) return;
        const ackKey = `ack_${agentName}_${senderA}_${m}`;
        if (localStorage.getItem(ackKey)) return;
        const pubKeyA = await fetchKey(senderA, true, false);
        const valid = await verifySignatureWithPublicKey(pubKeyA, "1|" + senderA + "|" + agentName + "|" + m, sig);
        if (!valid) {
          console.log(`Signature invalide, message rejet\xE9.`);
          return;
        }
        await displayAndSave(`${senderA} -> ${agentName} : ${m}`);
        const privKeyB = await fetchKey(agentName, false, false);
        const sigB = await signWithPrivateKey(privKeyB, "2|" + agentName + "|" + senderA + "|" + m);
        const pkeyA = await fetchKey(senderA, true, true);
        const ackPayload = JSON.stringify(["2", agentName, m, sigB]);
        const encryptedAck = await hybridEncrypt(pkeyA, ackPayload);
        await sendMessage(agentName, senderA, encryptedAck);
        localStorage.setItem(ackKey, "1");
        break;
      }
      case 2: {
        const senderB = dataArray[1];
        const m = dataArray[2];
        const sig = dataArray[3];
        const ackDisplayKey = `ackdisplay_${agentName}_${senderB}_${m}`;
        if (localStorage.getItem(ackDisplayKey)) return;
        const pubKeyB = await fetchKey(senderB, true, false);
        const valid = await verifySignatureWithPublicKey(pubKeyB, "2|" + senderB + "|" + agentName + "|" + m, sig);
        if (!valid) return;
        await displayAndSave(`[ACK] ${senderB} a bien recu : "${m}"`);
        localStorage.setItem(ackDisplayKey, "1");
        break;
      }
      default:
        return;
    }
  } catch (error) {
    console.log("Erreur analyseMessage : ", error);
  }
}
//# sourceMappingURL=data:application/json;base64,ewogICJ2ZXJzaW9uIjogMywKICAic291cmNlcyI6IFsiLi4vc3JjL2xpYkNyeXB0by50cyIsICIuLi9zcmMvbWVzc2VuZ2VyLnRzIl0sCiAgInNvdXJjZXNDb250ZW50IjogWyIvKiBTb3VyY2U6IGh0dHBzOi8vZ2lzdC5naXRodWIuY29tL2dyb3VuZHJhY2UvYjUxNDEwNjJiNDdkZDk2YTVjMjFjOTM4MzlkNGI5NTQgKi9cblxuLyogQXZhaWxhYmxlIGZ1bmN0aW9uczpcblxuICAgICMgS2V5L25vbmNlIGdlbmVyYXRpb246XG4gICAgZ2VuZXJhdGVhc3ltbWV0cmljS2V5c0ZvckVuY3J5cHRpb24oKTogUHJvbWlzZTxDcnlwdG9LZXlbXT5cbiAgICBnZW5lcmF0ZWFzeW1tZXRyaWNLZXlzRm9yU2lnbmF0dXJlKCk6IFByb21pc2U8Q3J5cHRvS2V5W10+XG4gICAgZ2VuZXJhdGVTeW1ldHJpY0tleSgpOiBQcm9taXNlPENyeXB0b0tleT5cbiAgICBnZW5lcmF0ZU5vbmNlKCk6IHN0cmluZ1xuXG4gICAgIyBhc3ltbWV0cmljIGtleSBFbmNyeXB0aW9uL0RlY3J5cHRpb24vU2lnbmF0dXJlL1NpZ25hdHVyZSB2ZXJpZmljYXRpb25cbiAgICBlbmNyeXB0V2l0aFB1YmxpY0tleShwa2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPlxuICAgIGRlY3J5cHRXaXRoUHJpdmF0ZUtleShza2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPlxuICAgIHNpZ25XaXRoUHJpdmF0ZUtleShwcml2YXRlS2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPlxuICAgIHZlcmlmeVNpZ25hdHVyZVdpdGhQdWJsaWNLZXkocHVibGljS2V5OiBDcnlwdG9LZXksIG1lc3NhZ2VJbkNsZWFyOiBzdHJpbmcsIHNpZ25lZE1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8Ym9vbGVhbj5cblxuICAgICMgU3ltbWV0cmljIGtleSBFbmNyeXB0aW9uL0RlY3J5cHRpb25cbiAgICBlbmNyeXB0V2l0aFN5bW1ldHJpY0tleShrZXk6IENyeXB0b0tleSwgbWVzc2FnZTogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmdbXT5cbiAgICBkZWNyeXB0V2l0aFN5bW1ldHJpY0tleShrZXk6IENyeXB0b0tleSwgbWVzc2FnZTogc3RyaW5nLCBpbml0VmVjdG9yOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz5cblxuICAgICMgSW1wb3J0aW5nIGtleXMgZnJvbSBzdHJpbmdcbiAgICBzdHJpbmdUb1B1YmxpY0tleUZvckVuY3J5cHRpb24ocGtleUluQmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT5cbiAgICBzdHJpbmdUb1ByaXZhdGVLZXlGb3JFbmNyeXB0aW9uKHNrZXlJbkJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+XG4gICAgc3RyaW5nVG9QdWJsaWNLZXlGb3JTaWduYXR1cmUocGtleUluQmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT5cbiAgICBzdHJpbmdUb1ByaXZhdGVLZXlGb3JTaWduYXR1cmUoc2tleUluQmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT5cbiAgICBzdHJpbmdUb1N5bW1ldHJpY0tleShza2V5QmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT5cblxuICAgICMgRXhwb3J0aW5nIGtleXMgdG8gc3RyaW5nXG4gICAgcHVibGljS2V5VG9TdHJpbmcoa2V5OiBDcnlwdG9LZXkpOiBQcm9taXNlPHN0cmluZz5cbiAgICBwcml2YXRlS2V5VG9TdHJpbmcoa2V5OiBDcnlwdG9LZXkpOiBQcm9taXNlPHN0cmluZz5cbiAgICBzeW1tZXRyaWNLZXlUb1N0cmluZyhrZXk6IENyeXB0b0tleSk6IFByb21pc2U8c3RyaW5nPlxuXG4gICAgIyBIYXNoaW5nXG4gICAgaGFzaCh0ZXh0OiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz5cbiovXG5cbi8vIGltcG9ydCB7IHN1YnRsZSB9IGZyb20gJ2NyeXB0bydcbi8vIExpYkNyeXB0by0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLVxuXG4vKlxuSW1wb3J0cyB0aGUgZ2l2ZW4gcHVibGljIGtleSAoZm9yIGVuY3J5cHRpb24pIGZyb20gdGhlIGltcG9ydCBzcGFjZS5cblRoZSBTdWJ0bGVDcnlwdG8gaW1wb3NlcyB0byB1c2UgdGhlIFwic3BraVwiIGZvcm1hdCBmb3IgZXhwb3J0aW5nIHB1YmxpYyBrZXlzLlxuKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzdHJpbmdUb1B1YmxpY0tleUZvckVuY3J5cHRpb24ocGtleUJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBrZXlBcnJheUJ1ZmZlcjogQXJyYXlCdWZmZXIgPSBiYXNlNjRTdHJpbmdUb0FycmF5QnVmZmVyKHBrZXlCYXNlNjQpXG4gICAgICAgIGNvbnN0IGtleTogQ3J5cHRvS2V5ID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxuICAgICAgICAgICAgXCJzcGtpXCIsXG4gICAgICAgICAgICBrZXlBcnJheUJ1ZmZlcixcbiAgICAgICAgICAgIHtcbiAgICAgICAgICAgICAgICBuYW1lOiBcIlJTQS1PQUVQXCIsXG4gICAgICAgICAgICAgICAgaGFzaDogXCJTSEEtMjU2XCIsXG4gICAgICAgICAgICB9LFxuICAgICAgICAgICAgdHJ1ZSxcbiAgICAgICAgICAgIFtcImVuY3J5cHRcIl1cbiAgICAgICAgKVxuICAgICAgICByZXR1cm4ga2V5XG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIERPTUV4Y2VwdGlvbikgeyBjb25zb2xlLmxvZyhcIlN0cmluZyBmb3IgdGhlIHB1YmxpYyBrZXkgKGZvciBlbmNyeXB0aW9uKSBpcyBpbGwtZm9ybWVkIVwiKSB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwdWJsaWMga2V5IChmb3IgZW5jcnlwdGlvbikgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIHsgY29uc29sZS5sb2coZSkgfVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG4vKlxuSW1wb3J0cyB0aGUgZ2l2ZW4gcHVibGljIGtleSAoZm9yIHNpZ25hdHVyZSB2ZXJpZmljYXRpb24pIGZyb20gdGhlIGltcG9ydCBzcGFjZS5cblRoZSBTdWJ0bGVDcnlwdG8gaW1wb3NlcyB0byB1c2UgdGhlIFwic3BraVwiIGZvcm1hdCBmb3IgZXhwb3J0aW5nIHB1YmxpYyBrZXlzLlxuKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzdHJpbmdUb1B1YmxpY0tleUZvclNpZ25hdHVyZShwa2V5QmFzZTY0OiBzdHJpbmcpOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IGtleUFycmF5QnVmZmVyOiBBcnJheUJ1ZmZlciA9IGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIocGtleUJhc2U2NClcbiAgICAgICAgY29uc3Qga2V5OiBDcnlwdG9LZXkgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXG4gICAgICAgICAgICBcInNwa2lcIixcbiAgICAgICAgICAgIGtleUFycmF5QnVmZmVyLFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIG5hbWU6IFwiUlNBU1NBLVBLQ1MxLXYxXzVcIixcbiAgICAgICAgICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB0cnVlLFxuICAgICAgICAgICAgW1widmVyaWZ5XCJdXG4gICAgICAgIClcbiAgICAgICAgcmV0dXJuIGtleVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwdWJsaWMga2V5IChmb3Igc2lnbmF0dXJlIHZlcmlmaWNhdGlvbikgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgcHVibGljIGtleSAoZm9yIHNpZ25hdHVyZSB2ZXJpZmljYXRpb24pIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuLypcbkltcG9ydHMgdGhlIGdpdmVuIHByaXZhdGUga2V5IChpbiBzdHJpbmcpIGFzIGEgdmFsaWQgcHJpdmF0ZSBrZXkgKGZvciBkZWNyeXB0aW9uKVxuVGhlIFN1YnRsZUNyeXB0byBpbXBvc2VzIHRvIHVzZSB0aGUgXCJwa2NzOFwiID8/IGZvcm1hdCBmb3IgaW1wb3J0aW5nIHB1YmxpYyBrZXlzLlxuKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBzdHJpbmdUb1ByaXZhdGVLZXlGb3JFbmNyeXB0aW9uKHNrZXlCYXNlNjQ6IHN0cmluZyk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3Qga2V5QXJyYXlCdWZmZXI6IEFycmF5QnVmZmVyID0gYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihza2V5QmFzZTY0KVxuICAgICAgICBjb25zdCBrZXk6IENyeXB0b0tleSA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmltcG9ydEtleShcbiAgICAgICAgICAgIFwicGtjczhcIixcbiAgICAgICAgICAgIGtleUFycmF5QnVmZmVyLFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIG5hbWU6IFwiUlNBLU9BRVBcIixcbiAgICAgICAgICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB0cnVlLFxuICAgICAgICAgICAgW1wiZGVjcnlwdFwiXSlcbiAgICAgICAgcmV0dXJuIGtleVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwcml2YXRlIGtleSAoZm9yIGRlY3J5cHRpb24pIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkgeyBjb25zb2xlLmxvZyhcIlN0cmluZyBmb3IgdGhlIHByaXZhdGUga2V5IChmb3IgZGVjcnlwdGlvbikgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIHsgY29uc29sZS5sb2coZSkgfVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG4vKlxuSW1wb3J0cyB0aGUgZ2l2ZW4gcHJpdmF0ZSBrZXkgKGluIHN0cmluZykgYXMgYSB2YWxpZCBwcml2YXRlIGtleSAoZm9yIHNpZ25hdHVyZSlcblRoZSBTdWJ0bGVDcnlwdG8gaW1wb3NlcyB0byB1c2UgdGhlIFwicGtjczhcIiA/PyBmb3JtYXQgZm9yIGltcG9ydGluZyBwdWJsaWMga2V5cy5cbiovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc3RyaW5nVG9Qcml2YXRlS2V5Rm9yU2lnbmF0dXJlKHNrZXlCYXNlNjQ6IHN0cmluZyk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3Qga2V5QXJyYXlCdWZmZXI6IEFycmF5QnVmZmVyID0gYmFzZTY0U3RyaW5nVG9BcnJheUJ1ZmZlcihza2V5QmFzZTY0KVxuICAgICAgICBjb25zdCBrZXk6IENyeXB0b0tleSA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmltcG9ydEtleShcbiAgICAgICAgICAgIFwicGtjczhcIixcbiAgICAgICAgICAgIGtleUFycmF5QnVmZmVyLFxuICAgICAgICAgICAge1xuICAgICAgICAgICAgICAgIG5hbWU6IFwiUlNBU1NBLVBLQ1MxLXYxXzVcIixcbiAgICAgICAgICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcbiAgICAgICAgICAgIH0sXG4gICAgICAgICAgICB0cnVlLFxuICAgICAgICAgICAgW1wic2lnblwiXSlcbiAgICAgICAgcmV0dXJuIGtleVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBwcml2YXRlIGtleSAoZm9yIHNpZ25hdHVyZSkgaXMgaWxsLWZvcm1lZCFcIikgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgcHJpdmF0ZSBrZXkgKGZvciBzaWduYXR1cmUpIGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cbi8qXG5FeHBvcnRzIHRoZSBnaXZlbiBwdWJsaWMga2V5IGludG8gYSB2YWxpZCBzdHJpbmcuXG5UaGUgU3VidGxlQ3J5cHRvIGltcG9zZXMgdG8gdXNlIHRoZSBcInNwa2lcIiBmb3JtYXQgZm9yIGV4cG9ydGluZyBwdWJsaWMga2V5cy5cbiovXG5cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBwdWJsaWNLZXlUb1N0cmluZyhrZXk6IENyeXB0b0tleSk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgY29uc3QgZXhwb3J0ZWRLZXk6IEFycmF5QnVmZmVyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZXhwb3J0S2V5KFwic3BraVwiLCBrZXkpXG4gICAgcmV0dXJuIGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoZXhwb3J0ZWRLZXkpXG59XG5cbi8qXG5FeHBvcnRzIHRoZSBnaXZlbiBwdWJsaWMga2V5IGludG8gYSB2YWxpZCBzdHJpbmcuXG5UaGUgU3VidGxlQ3J5cHRvIGltcG9zZXMgdG8gdXNlIHRoZSBcInNwa2lcIiBmb3JtYXQgZm9yIGV4cG9ydGluZyBwdWJsaWMga2V5cy5cbiovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gcHJpdmF0ZUtleVRvU3RyaW5nKGtleTogQ3J5cHRvS2V5KTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICBjb25zdCBleHBvcnRlZEtleTogQXJyYXlCdWZmZXIgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoXCJwa2NzOFwiLCBrZXkpXG4gICAgcmV0dXJuIGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoZXhwb3J0ZWRLZXkpXG59XG5cbi8qIEdlbmVyYXRlcyBhIHBhaXIgb2YgcHVibGljIGFuZCBwcml2YXRlIFJTQSBrZXlzIGZvciBlbmNyeXB0aW9uL2RlY3J5cHRpb24gKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZWFzeW1tZXRyaWNLZXlzRm9yRW5jcnlwdGlvbigpOiBQcm9taXNlPENyeXB0b0tleVtdPiB7XG4gICAgY29uc3Qga2V5cGFpcjogQ3J5cHRvS2V5UGFpciA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KFxuICAgICAgICB7XG4gICAgICAgICAgICBuYW1lOiBcIlJTQS1PQUVQXCIsXG4gICAgICAgICAgICBtb2R1bHVzTGVuZ3RoOiAyMDQ4LFxuICAgICAgICAgICAgcHVibGljRXhwb25lbnQ6IG5ldyBVaW50OEFycmF5KFsxLCAwLCAxXSksXG4gICAgICAgICAgICBoYXNoOiBcIlNIQS0yNTZcIixcbiAgICAgICAgfSxcbiAgICAgICAgdHJ1ZSxcbiAgICAgICAgW1wiZW5jcnlwdFwiLCBcImRlY3J5cHRcIl1cbiAgICApXG4gICAgcmV0dXJuIFtrZXlwYWlyLnB1YmxpY0tleSwga2V5cGFpci5wcml2YXRlS2V5XVxufVxuXG4vKiBHZW5lcmF0ZXMgYSBwYWlyIG9mIHB1YmxpYyBhbmQgcHJpdmF0ZSBSU0Ega2V5cyBmb3Igc2lnbmluZy92ZXJpZnlpbmcgKi9cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBnZW5lcmF0ZWFzeW1tZXRyaWNLZXlzRm9yU2lnbmF0dXJlKCk6IFByb21pc2U8Q3J5cHRvS2V5W10+IHtcbiAgICBjb25zdCBrZXlwYWlyOiBDcnlwdG9LZXlQYWlyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZ2VuZXJhdGVLZXkoXG4gICAgICAgIHtcbiAgICAgICAgICAgIG5hbWU6IFwiUlNBU1NBLVBLQ1MxLXYxXzVcIixcbiAgICAgICAgICAgIG1vZHVsdXNMZW5ndGg6IDIwNDgsXG4gICAgICAgICAgICBwdWJsaWNFeHBvbmVudDogbmV3IFVpbnQ4QXJyYXkoWzEsIDAsIDFdKSxcbiAgICAgICAgICAgIGhhc2g6IFwiU0hBLTI1NlwiLFxuICAgICAgICB9LFxuICAgICAgICB0cnVlLFxuICAgICAgICBbXCJzaWduXCIsIFwidmVyaWZ5XCJdXG4gICAgKVxuICAgIHJldHVybiBba2V5cGFpci5wdWJsaWNLZXksIGtleXBhaXIucHJpdmF0ZUtleV1cbn1cblxuLyogR2VuZXJhdGVzIGEgcmFuZG9tIG5vbmNlICovXG5leHBvcnQgZnVuY3Rpb24gZ2VuZXJhdGVOb25jZSgpOiBzdHJpbmcge1xuICAgIGNvbnN0IG5vbmNlQXJyYXkgPSBuZXcgVWludDMyQXJyYXkoMSlcbiAgICBzZWxmLmNyeXB0by5nZXRSYW5kb21WYWx1ZXMobm9uY2VBcnJheSlcbiAgICByZXR1cm4gbm9uY2VBcnJheVswXS50b1N0cmluZygpXG59XG5cbi8qIEVuY3J5cHRzIGEgbWVzc2FnZSB3aXRoIGEgcHVibGljIGtleSAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGVuY3J5cHRXaXRoUHVibGljS2V5KHB1YmxpY0tleTogQ3J5cHRvS2V5LCBtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IG1lc3NhZ2VUb0FycmF5QnVmZmVyID0gdGV4dFRvQXJyYXlCdWZmZXIobWVzc2FnZSlcbiAgICAgICAgY29uc3QgY3lwaGVyZWRNZXNzYWdlQUI6IEFycmF5QnVmZmVyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuZW5jcnlwdChcbiAgICAgICAgICAgIHsgbmFtZTogXCJSU0EtT0FFUFwiIH0sXG4gICAgICAgICAgICBwdWJsaWNLZXksXG4gICAgICAgICAgICBtZXNzYWdlVG9BcnJheUJ1ZmZlclxuICAgICAgICApXG4gICAgICAgIHJldHVybiBhcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKGN5cGhlcmVkTWVzc2FnZUFCKVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgaWYgKGUgaW5zdGFuY2VvZiBET01FeGNlcHRpb24pIHsgY29uc29sZS5sb2coZSk7IGNvbnNvbGUubG9nKFwiRW5jcnlwdGlvbiBmYWlsZWQhXCIpIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkgeyBjb25zb2xlLmxvZyhcIlB1YmxpYyBrZXkgb3IgbWVzc2FnZSB0byBlbmNyeXB0IGlzIGlsbC1mb3JtZWRcIikgfVxuICAgICAgICBlbHNlIHsgY29uc29sZS5sb2coZSkgfVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG5cbi8qIFNpZ24gYSBtZXNzYWdlIHdpdGggYSBwcml2YXRlIGtleSAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHNpZ25XaXRoUHJpdmF0ZUtleShwcml2YXRlS2V5OiBDcnlwdG9LZXksIG1lc3NhZ2U6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3QgbWVzc2FnZVRvQXJyYXlCdWZmZXIgPSB0ZXh0VG9BcnJheUJ1ZmZlcihtZXNzYWdlKVxuICAgICAgICBjb25zdCBzaWduZWRNZXNzYWdlQUI6IEFycmF5QnVmZmVyID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuc2lnbihcbiAgICAgICAgICAgIFwiUlNBU1NBLVBLQ1MxLXYxXzVcIixcbiAgICAgICAgICAgIHByaXZhdGVLZXksXG4gICAgICAgICAgICBtZXNzYWdlVG9BcnJheUJ1ZmZlclxuICAgICAgICApXG4gICAgICAgIHJldHVybiBhcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKHNpZ25lZE1lc3NhZ2VBQilcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7IGNvbnNvbGUubG9nKGUpOyBjb25zb2xlLmxvZyhcIlNpZ25hdHVyZSBmYWlsZWQhXCIpIH1cbiAgICAgICAgZWxzZSBpZiAoZSBpbnN0YW5jZW9mIEtleVN0cmluZ0NvcnJ1cHRlZCkgeyBjb25zb2xlLmxvZyhcIlByaXZhdGUga2V5IG9yIG1lc3NhZ2UgdG8gc2lnbiBpcyBpbGwtZm9ybWVkXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuXG4vKiBEZWNyeXB0cyBhIG1lc3NhZ2Ugd2l0aCBhIHByaXZhdGUga2V5ICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gZGVjcnlwdFdpdGhQcml2YXRlS2V5KHByaXZhdGVLZXk6IENyeXB0b0tleSwgbWVzc2FnZTogc3RyaW5nKTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBkZWNyeXRwZWRNZXNzYWdlQUI6IEFycmF5QnVmZmVyID0gYXdhaXRcbiAgICAgICAgICAgIHdpbmRvdy5jcnlwdG8uc3VidGxlLmRlY3J5cHQoXG4gICAgICAgICAgICAgICAgeyBuYW1lOiBcIlJTQS1PQUVQXCIgfSxcbiAgICAgICAgICAgICAgICBwcml2YXRlS2V5LFxuICAgICAgICAgICAgICAgIGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIobWVzc2FnZSlcbiAgICAgICAgICAgIClcbiAgICAgICAgcmV0dXJuIGFycmF5QnVmZmVyVG9UZXh0KGRlY3J5dHBlZE1lc3NhZ2VBQilcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIkludmFsaWQga2V5LCBtZXNzYWdlIG9yIGFsZ29yaXRobSBmb3IgZGVjcnlwdGlvblwiKVxuICAgICAgICB9IGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiUHJpdmF0ZSBrZXkgb3IgbWVzc2FnZSB0byBkZWNyeXB0IGlzIGlsbC1mb3JtZWRcIilcbiAgICAgICAgfVxuICAgICAgICBlbHNlIGNvbnNvbGUubG9nKFwiRGVjcnlwdGlvbiBmYWlsZWRcIilcbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuXG4vKiBWZXJpZmljYXRpb24gb2YgYSBzaWduYXR1cmUgb24gYSBtZXNzYWdlIHdpdGggYSBwdWJsaWMga2V5ICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gdmVyaWZ5U2lnbmF0dXJlV2l0aFB1YmxpY0tleShwdWJsaWNLZXk6IENyeXB0b0tleSwgbWVzc2FnZUluQ2xlYXI6IHN0cmluZywgc2lnbmVkTWVzc2FnZTogc3RyaW5nKTogUHJvbWlzZTxib29sZWFuPiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3Qgc2lnbmVkVG9BcnJheUJ1ZmZlciA9IGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIoc2lnbmVkTWVzc2FnZSlcbiAgICAgICAgY29uc3QgbWVzc2FnZUluQ2xlYXJUb0FycmF5QnVmZmVyID0gdGV4dFRvQXJyYXlCdWZmZXIobWVzc2FnZUluQ2xlYXIpXG4gICAgICAgIGNvbnN0IHZlcmlmaWVkOiBib29sZWFuID0gYXdhaXRcbiAgICAgICAgICAgIHdpbmRvdy5jcnlwdG8uc3VidGxlLnZlcmlmeShcbiAgICAgICAgICAgICAgICBcIlJTQVNTQS1QS0NTMS12MV81XCIsXG4gICAgICAgICAgICAgICAgcHVibGljS2V5LFxuICAgICAgICAgICAgICAgIHNpZ25lZFRvQXJyYXlCdWZmZXIsXG4gICAgICAgICAgICAgICAgbWVzc2FnZUluQ2xlYXJUb0FycmF5QnVmZmVyKVxuICAgICAgICByZXR1cm4gdmVyaWZpZWRcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIkludmFsaWQga2V5LCBtZXNzYWdlIG9yIGFsZ29yaXRobSBmb3Igc2lnbmF0dXJlIHZlcmlmaWNhdGlvblwiKVxuICAgICAgICB9IGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiUHVibGljIGtleSBvciBzaWduZWQgbWVzc2FnZSB0byB2ZXJpZnkgaXMgaWxsLWZvcm1lZFwiKVxuICAgICAgICB9XG4gICAgICAgIGVsc2UgY29uc29sZS5sb2coXCJEZWNyeXB0aW9uIGZhaWxlZFwiKVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG5cbi8qIEdlbmVyYXRlcyBhIHN5bW1ldHJpYyBBRVMtR0NNIGtleSAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGdlbmVyYXRlU3ltZXRyaWNLZXkoKTogUHJvbWlzZTxDcnlwdG9LZXk+IHtcbiAgICBjb25zdCBrZXk6IENyeXB0b0tleSA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmdlbmVyYXRlS2V5KFxuICAgICAgICB7XG4gICAgICAgICAgICBuYW1lOiBcIkFFUy1HQ01cIixcbiAgICAgICAgICAgIGxlbmd0aDogMjU2LFxuICAgICAgICB9LFxuICAgICAgICB0cnVlLFxuICAgICAgICBbXCJlbmNyeXB0XCIsIFwiZGVjcnlwdFwiXVxuICAgIClcbiAgICByZXR1cm4ga2V5XG59XG5cbi8qIGEgc3ltbWV0cmljIEFFUyBrZXkgaW50byBhIHN0cmluZyAqL1xuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIHN5bW1ldHJpY0tleVRvU3RyaW5nKGtleTogQ3J5cHRvS2V5KTogUHJvbWlzZTxzdHJpbmc+IHtcbiAgICBjb25zdCBleHBvcnRlZEtleTogQXJyYXlCdWZmZXIgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5leHBvcnRLZXkoXCJyYXdcIiwga2V5KVxuICAgIHJldHVybiBhcnJheUJ1ZmZlclRvQmFzZTY0U3RyaW5nKGV4cG9ydGVkS2V5KVxufVxuXG4vKiBJbXBvcnRzIHRoZSBnaXZlbiBrZXkgKGluIHN0cmluZykgYXMgYSB2YWxpZCBBRVMga2V5ICovXG5leHBvcnQgYXN5bmMgZnVuY3Rpb24gc3RyaW5nVG9TeW1tZXRyaWNLZXkoc2tleUJhc2U2NDogc3RyaW5nKTogUHJvbWlzZTxDcnlwdG9LZXk+IHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBrZXlBcnJheUJ1ZmZlcjogQXJyYXlCdWZmZXIgPSBiYXNlNjRTdHJpbmdUb0FycmF5QnVmZmVyKHNrZXlCYXNlNjQpXG4gICAgICAgIGNvbnN0IGtleTogQ3J5cHRvS2V5ID0gYXdhaXQgd2luZG93LmNyeXB0by5zdWJ0bGUuaW1wb3J0S2V5KFxuICAgICAgICAgICAgXCJyYXdcIixcbiAgICAgICAgICAgIGtleUFycmF5QnVmZmVyLFxuICAgICAgICAgICAgXCJBRVMtR0NNXCIsXG4gICAgICAgICAgICB0cnVlLFxuICAgICAgICAgICAgW1wiZW5jcnlwdFwiLCBcImRlY3J5cHRcIl0pXG4gICAgICAgIHJldHVybiBrZXlcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7IGNvbnNvbGUubG9nKFwiU3RyaW5nIGZvciB0aGUgc3ltbWV0cmljIGtleSBpcyBpbGwtZm9ybWVkIVwiKSB9XG4gICAgICAgIGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHsgY29uc29sZS5sb2coXCJTdHJpbmcgZm9yIHRoZSBzeW1tZXRyaWMga2V5IGlzIGlsbC1mb3JtZWQhXCIpIH1cbiAgICAgICAgZWxzZSB7IGNvbnNvbGUubG9nKGUpIH1cbiAgICAgICAgdGhyb3cgZVxuICAgIH1cbn1cblxuXG4vLyBXaGVuIGN5cGhlcmluZyBhIG1lc3NhZ2Ugd2l0aCBhIGtleSBpbiBBRVMsIHdlIG9idGFpbiBhIGN5cGhlcmVkIG1lc3NhZ2UgYW5kIGFuIFwiaW5pdGlhbGlzYXRpb24gdmVjdG9yXCIuXG4vLyBJbiB0aGlzIGltcGxlbWVudGF0aW9uLCB0aGUgb3V0cHV0IGlzIGEgdHdvIGVsZW1lbnRzIGFycmF5IHQgc3VjaCB0aGF0IHRbMF0gaXMgdGhlIGN5cGhlcmVkIG1lc3NhZ2Vcbi8vIGFuZCB0WzFdIGlzIHRoZSBpbml0aWFsaXNhdGlvbiB2ZWN0b3IuIFRvIHNpbXBsaWZ5LCB0aGUgaW5pdGlhbGlzYXRpb24gdmVjdG9yIGlzIHJlcHJlc2VudGVkIGJ5IGEgc3RyaW5nLlxuLy8gVGhlIGluaXRpYWxpc2F0aW9uIHZlY3RvcmUgaXMgdXNlZCBmb3IgcHJvdGVjdGluZyB0aGUgZW5jcnlwdGlvbiwgaS5lLCAyIGVuY3J5cHRpb25zIG9mIHRoZSBzYW1lIG1lc3NhZ2UgXG4vLyB3aXRoIHRoZSBzYW1lIGtleSB3aWxsIG5ldmVyIHJlc3VsdCBpbnRvIHRoZSBzYW1lIGVuY3J5cHRlZCBtZXNzYWdlLlxuLy8gXG4vLyBOb3RlIHRoYXQgZm9yIGRlY3lwaGVyaW5nLCB0aGUgKipzYW1lKiogaW5pdGlhbGlzYXRpb24gdmVjdG9yIHdpbGwgYmUgbmVlZGVkLlxuLy8gVGhpcyB2ZWN0b3IgY2FuIHNhZmVseSBiZSB0cmFuc2ZlcnJlZCBpbiBjbGVhciB3aXRoIHRoZSBlbmNyeXB0ZWQgbWVzc2FnZS5cblxuZXhwb3J0IGFzeW5jIGZ1bmN0aW9uIGVuY3J5cHRXaXRoU3ltbWV0cmljS2V5KGtleTogQ3J5cHRvS2V5LCBtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZ1tdPiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3QgbWVzc2FnZVRvQXJyYXlCdWZmZXIgPSB0ZXh0VG9BcnJheUJ1ZmZlcihtZXNzYWdlKVxuICAgICAgICBjb25zdCBpdiA9IHdpbmRvdy5jcnlwdG8uZ2V0UmFuZG9tVmFsdWVzKG5ldyBVaW50OEFycmF5KDEyKSk7XG4gICAgICAgIGNvbnN0IGl2VGV4dCA9IGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoaXYpXG4gICAgICAgIGNvbnN0IGN5cGhlcmVkTWVzc2FnZUFCOiBBcnJheUJ1ZmZlciA9IGF3YWl0IHdpbmRvdy5jcnlwdG8uc3VidGxlLmVuY3J5cHQoXG4gICAgICAgICAgICB7IG5hbWU6IFwiQUVTLUdDTVwiLCBpdiB9LFxuICAgICAgICAgICAga2V5LFxuICAgICAgICAgICAgbWVzc2FnZVRvQXJyYXlCdWZmZXJcbiAgICAgICAgKVxuICAgICAgICByZXR1cm4gW2FycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoY3lwaGVyZWRNZXNzYWdlQUIpLCBpdlRleHRdXG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBpZiAoZSBpbnN0YW5jZW9mIERPTUV4Y2VwdGlvbikgeyBjb25zb2xlLmxvZyhlKTsgY29uc29sZS5sb2coXCJFbmNyeXB0aW9uIGZhaWxlZCFcIikgfVxuICAgICAgICBlbHNlIGlmIChlIGluc3RhbmNlb2YgS2V5U3RyaW5nQ29ycnVwdGVkKSB7IGNvbnNvbGUubG9nKFwiU3ltbWV0cmljIGtleSBvciBtZXNzYWdlIHRvIGVuY3J5cHQgaXMgaWxsLWZvcm1lZFwiKSB9XG4gICAgICAgIGVsc2UgeyBjb25zb2xlLmxvZyhlKSB9XG4gICAgICAgIHRocm93IGVcbiAgICB9XG59XG5cbi8vIEZvciBkZWN5cGhlcmluZywgd2UgbmVlZCB0aGUga2V5LCB0aGUgY3lwaGVyZWQgbWVzc2FnZSBhbmQgdGhlIGluaXRpYWxpemF0aW9uIHZlY3Rvci4gU2VlIGFib3ZlIHRoZSBcbi8vIGNvbW1lbnRzIGZvciB0aGUgZW5jcnlwdFdpdGhTeW1tZXRyaWNLZXkgZnVuY3Rpb25cbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBkZWNyeXB0V2l0aFN5bW1ldHJpY0tleShrZXk6IENyeXB0b0tleSwgbWVzc2FnZTogc3RyaW5nLCBpbml0VmVjdG9yOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIGNvbnN0IGRlY29kZWRJbml0VmVjdG9yOiBBcnJheUJ1ZmZlciA9IGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIoaW5pdFZlY3RvcilcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBkZWNyeXRwZWRNZXNzYWdlQUI6IEFycmF5QnVmZmVyID0gYXdhaXRcbiAgICAgICAgICAgIHdpbmRvdy5jcnlwdG8uc3VidGxlLmRlY3J5cHQoXG4gICAgICAgICAgICAgICAgeyBuYW1lOiBcIkFFUy1HQ01cIiwgaXY6IGRlY29kZWRJbml0VmVjdG9yIH0sXG4gICAgICAgICAgICAgICAga2V5LFxuICAgICAgICAgICAgICAgIGJhc2U2NFN0cmluZ1RvQXJyYXlCdWZmZXIobWVzc2FnZSlcbiAgICAgICAgICAgIClcbiAgICAgICAgcmV0dXJuIGFycmF5QnVmZmVyVG9UZXh0KGRlY3J5dHBlZE1lc3NhZ2VBQilcbiAgICB9IGNhdGNoIChlKSB7XG4gICAgICAgIGlmIChlIGluc3RhbmNlb2YgRE9NRXhjZXB0aW9uKSB7XG4gICAgICAgICAgICBjb25zb2xlLmxvZyhcIkludmFsaWQga2V5LCBtZXNzYWdlIG9yIGFsZ29yaXRobSBmb3IgZGVjcnlwdGlvblwiKVxuICAgICAgICB9IGVsc2UgaWYgKGUgaW5zdGFuY2VvZiBLZXlTdHJpbmdDb3JydXB0ZWQpIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKFwiU3ltbWV0cmljIGtleSBvciBtZXNzYWdlIHRvIGRlY3J5cHQgaXMgaWxsLWZvcm1lZFwiKVxuICAgICAgICB9XG4gICAgICAgIGVsc2UgY29uc29sZS5sb2coXCJEZWNyeXB0aW9uIGZhaWxlZFwiKVxuICAgICAgICB0aHJvdyBlXG4gICAgfVxufVxuXG4vLyBTSEEtMjU2IEhhc2ggZnJvbSBhIHRleHRcbmV4cG9ydCBhc3luYyBmdW5jdGlvbiBoYXNoKHRleHQ6IHN0cmluZyk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgY29uc3QgdGV4dDJhcnJheUJ1ZiA9IHRleHRUb0FycmF5QnVmZmVyKHRleHQpXG4gICAgY29uc3QgaGFzaGVkQXJyYXkgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5kaWdlc3QoXCJTSEEtMjU2XCIsIHRleHQyYXJyYXlCdWYpXG4gICAgcmV0dXJuIGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoaGFzaGVkQXJyYXkpXG59XG5cbmNsYXNzIEtleVN0cmluZ0NvcnJ1cHRlZCBleHRlbmRzIEVycm9yIHsgfVxuXG4vLyBBcnJheUJ1ZmZlciB0byBhIEJhc2U2NCBzdHJpbmdcbmZ1bmN0aW9uIGFycmF5QnVmZmVyVG9CYXNlNjRTdHJpbmcoYXJyYXlCdWZmZXI6IEFycmF5QnVmZmVyKTogc3RyaW5nIHtcbiAgICB2YXIgYnl0ZUFycmF5ID0gbmV3IFVpbnQ4QXJyYXkoYXJyYXlCdWZmZXIpXG4gICAgdmFyIGJ5dGVTdHJpbmcgPSAnJ1xuICAgIGZvciAodmFyIGkgPSAwOyBpIDwgYnl0ZUFycmF5LmJ5dGVMZW5ndGg7IGkrKykge1xuICAgICAgICBieXRlU3RyaW5nICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoYnl0ZUFycmF5W2ldKVxuICAgIH1cbiAgICByZXR1cm4gYnRvYShieXRlU3RyaW5nKVxufVxuXG4vLyBCYXNlNjQgc3RyaW5nIHRvIGFuIGFycmF5QnVmZmVyXG5mdW5jdGlvbiBiYXNlNjRTdHJpbmdUb0FycmF5QnVmZmVyKGI2NHN0cjogc3RyaW5nKTogQXJyYXlCdWZmZXIge1xuICAgIHRyeSB7XG4gICAgICAgIHZhciBieXRlU3RyID0gYXRvYihiNjRzdHIpXG4gICAgICAgIHZhciBieXRlcyA9IG5ldyBVaW50OEFycmF5KGJ5dGVTdHIubGVuZ3RoKVxuICAgICAgICBmb3IgKHZhciBpID0gMDsgaSA8IGJ5dGVTdHIubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgICAgIGJ5dGVzW2ldID0gYnl0ZVN0ci5jaGFyQ29kZUF0KGkpXG4gICAgICAgIH1cbiAgICAgICAgcmV0dXJuIGJ5dGVzLmJ1ZmZlclxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgY29uc29sZS5sb2coYFN0cmluZyBzdGFydGluZyBieSAnJHtiNjRzdHIuc3Vic3RyaW5nKDAsIDEwKX0nIGNhbm5vdCBiZSBjb252ZXJ0ZWQgdG8gYSB2YWxpZCBrZXkgb3IgbWVzc2FnZWApXG4gICAgICAgIHRocm93IG5ldyBLZXlTdHJpbmdDb3JydXB0ZWRcbiAgICB9XG59XG5cbi8vIFN0cmluZyB0byBhcnJheSBidWZmZXJcbmZ1bmN0aW9uIHRleHRUb0FycmF5QnVmZmVyKHN0cjogc3RyaW5nKTogQXJyYXlCdWZmZXIge1xuICAgIHZhciBidWYgPSBlbmNvZGVVUklDb21wb25lbnQoc3RyKSAvLyAyIGJ5dGVzIGZvciBlYWNoIGNoYXJcbiAgICB2YXIgYnVmVmlldyA9IG5ldyBVaW50OEFycmF5KGJ1Zi5sZW5ndGgpXG4gICAgZm9yICh2YXIgaSA9IDA7IGkgPCBidWYubGVuZ3RoOyBpKyspIHtcbiAgICAgICAgYnVmVmlld1tpXSA9IGJ1Zi5jaGFyQ29kZUF0KGkpXG4gICAgfVxuICAgIHJldHVybiBidWZWaWV3XG59XG5cbi8vIEFycmF5IGJ1ZmZlcnMgdG8gc3RyaW5nXG5mdW5jdGlvbiBhcnJheUJ1ZmZlclRvVGV4dChhcnJheUJ1ZmZlcjogQXJyYXlCdWZmZXIpOiBzdHJpbmcge1xuICAgIHZhciBieXRlQXJyYXkgPSBuZXcgVWludDhBcnJheShhcnJheUJ1ZmZlcilcbiAgICB2YXIgc3RyID0gJydcbiAgICBmb3IgKHZhciBpID0gMDsgaSA8IGJ5dGVBcnJheS5ieXRlTGVuZ3RoOyBpKyspIHtcbiAgICAgICAgc3RyICs9IFN0cmluZy5mcm9tQ2hhckNvZGUoYnl0ZUFycmF5W2ldKVxuICAgIH1cbiAgICByZXR1cm4gZGVjb2RlVVJJQ29tcG9uZW50KHN0cilcbn1cblxuIiwgIi8vIFRvIGRldGVjdCBpZiB3ZSBjYW4gdXNlIHdpbmRvdy5jcnlwdG8uc3VidGxlXG5pZiAoIXdpbmRvdy5pc1NlY3VyZUNvbnRleHQpIGFsZXJ0KFwiTm90IHNlY3VyZSBjb250ZXh0IVwiKVxuXG4vLyAtLSBETyBOT1QgTU9ESUZZIFRISVMgUEFSVCEgLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbi8vIE1lc3NhZ2UgZm9yIHVzZXIgbmFtZVxuY2xhc3MgQ2FzVXNlck5hbWUge1xuICAgIGNvbnN0cnVjdG9yKHB1YmxpYyB1c2VybmFtZTogc3RyaW5nKSB7IH1cbn1cblxuLy8gUmVxdWVzdGluZyBrZXlzXG5jbGFzcyBLZXlSZXF1ZXN0IHtcbiAgICBjb25zdHJ1Y3RvcihwdWJsaWMgb3duZXJPZlRoZUtleTogc3RyaW5nLCBwdWJsaWMgcHVibGljS2V5OiBib29sZWFuLCBwdWJsaWMgZW5jcnlwdGlvbjogYm9vbGVhbikgeyB9XG59XG5cbmNsYXNzIEtleVJlc3VsdCB7XG4gICAgY29uc3RydWN0b3IocHVibGljIHN1Y2Nlc3M6IGJvb2xlYW4sIHB1YmxpYyBrZXk6IHN0cmluZywgcHVibGljIGVycm9yTWVzc2FnZTogc3RyaW5nKSB7IH1cbn1cblxuLy8gVGhlIG1lc3NhZ2UgZm9ybWF0XG5jbGFzcyBFeHRNZXNzYWdlIHtcbiAgICBjb25zdHJ1Y3RvcihwdWJsaWMgc2VuZGVyOiBzdHJpbmcsIHB1YmxpYyByZWNlaXZlcjogc3RyaW5nLCBwdWJsaWMgY29udGVudDogc3RyaW5nKSB7IH1cbn1cblxuLy8gU2VuZGluZyBhIG1lc3NhZ2UgUmVzdWx0IGZvcm1hdFxuY2xhc3MgU2VuZFJlc3VsdCB7XG4gICAgY29uc3RydWN0b3IocHVibGljIHN1Y2Nlc3M6IGJvb2xlYW4sIHB1YmxpYyBlcnJvck1lc3NhZ2U6IHN0cmluZykgeyB9XG59XG5cbi8vIE1lc3NhZ2UgZm9yIHJlcXVpcmluZyBoaXN0b3J5XG5jbGFzcyBIaXN0b3J5UmVxdWVzdCB7XG4gICAgY29uc3RydWN0b3IocHVibGljIGFnZW50TmFtZTogc3RyaW5nLCBwdWJsaWMgaW5kZXg6IG51bWJlcikgeyB9XG59XG5cbi8vIFJlc3VsdCBvZiBoaXN0b3J5IHJlcXVlc3RcbmNsYXNzIEhpc3RvcnlBbnN3ZXIge1xuICAgIGNvbnN0cnVjdG9yKHB1YmxpYyBzdWNjZXNzOiBib29sZWFuLFxuICAgICAgICBwdWJsaWMgZmFpbHVyZU1lc3NhZ2U6IHN0cmluZyxcbiAgICAgICAgcHVibGljIGluZGV4OiBudW1iZXIsXG4gICAgICAgIHB1YmxpYyBhbGxNZXNzYWdlczogRXh0TWVzc2FnZVtdKSB7IH1cbn1cblxubGV0IGdsb2JhbFVzZXJOYW1lID0gXCJcIlxuXG4vLyBXQVJOSU5HIVxuLy8gSXQgaXMgbmVjZXNzYXJ5IHRvIHBhc3MgdGhlIFVSTCBwYXJhbWV0ZXJzLCBjYWxsZWQgYHVybFBhcmFtc2AgYmVsb3csIHRvIFxuLy8gZXZlcnkgR0VUL1BPU1QgcXVlcnkgeW91IHNlbmQgdG8gdGhlIHNlcnZlci4gVGhpcyBpcyBtYW5kYXRvcnkgdG8gaGF2ZSB0aGUgcG9zc2liaWxpdHkgXG4vLyB0byB1c2UgYWx0ZXJuYXRpdmUgaWRlbnRpdGllcyBsaWtlIGFsaWNlQHVuaXYtcmVubmVzLmZyLCBib2JAdW5pdi1yZW5uZXMuZnIsIGV0Yy4gXG4vLyBmb3IgZGVidWdnaW5nIHB1cnBvc2VzLlxuXG4vLyBEbyBub3QgbW9kaWZ5IVxuYXN5bmMgZnVuY3Rpb24gZmV0Y2hDYXNOYW1lKCk6IFByb21pc2U8c3RyaW5nPiB7XG4gICAgY29uc3QgdXJsUGFyYW1zID0gbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKTtcbiAgICBjb25zdCBuYW1lcmVxdWVzdCA9IGF3YWl0IGZldGNoKFwiL2dldHVzZXI/XCIgKyB1cmxQYXJhbXMsIHtcbiAgICAgICAgbWV0aG9kOiBcIkdFVFwiLFxuICAgICAgICBoZWFkZXJzOiB7XG4gICAgICAgICAgICBcIkNvbnRlbnQtdHlwZVwiOiBcImFwcGxpY2F0aW9uL2pzb247IGNoYXJzZXQ9VVRGLThcIlxuICAgICAgICB9XG4gICAgfSk7XG4gICAgaWYgKCFuYW1lcmVxdWVzdC5vaykge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYEVycm9yISBzdGF0dXM6ICR7bmFtZXJlcXVlc3Quc3RhdHVzfWApXG4gICAgfVxuICAgIGNvbnN0IG5hbWVSZXN1bHQgPSAoYXdhaXQgbmFtZXJlcXVlc3QuanNvbigpKSBhcyBDYXNVc2VyTmFtZVxuICAgIGNvbnNvbGUubG9nKFwiRmV0Y2hlZCBDQVMgbmFtZT0gXCIgKyBuYW1lUmVzdWx0LnVzZXJuYW1lKVxuICAgIHJldHVybiBuYW1lUmVzdWx0LnVzZXJuYW1lXG59XG5cbi8vIERvIG5vdCBtb2RpZnkhXG5hc3luYyBmdW5jdGlvbiBzZXRDYXNOYW1lKCkge1xuICAgIGdsb2JhbFVzZXJOYW1lID0gYXdhaXQgZmV0Y2hDYXNOYW1lKClcbiAgICAvLyBXZSByZXBsYWNlIHRoZSBuYW1lIG9mIHRoZSB1c2VyIG9mIHRoZSBhcHBsaWNhdGlvbiBhcyB0aGUgZGVmYXVsdCBuYW1lXG4gICAgLy8gSW4gdGhlIHdpbmRvd1xuICAgIHVzZXJCdXR0b25MYWJlbC50ZXh0Q29udGVudCA9IGdsb2JhbFVzZXJOYW1lXG59XG5cbi8vIERvIG5vdCBtb2RpZnkhXG5zZXRDYXNOYW1lKClcblxuLy8gV0FSTklORyFcbi8vIEl0IGlzIG5lY2Vzc2FyeSB0byBwcm92aWRlIHRoZSBuYW1lIG9mIHRoZSBvd25lciBvZiB0aGUgYXBwbGljYXRpb24uIEVhY2ggcGFpciBvZiBzdHVkZW50IGFyZVxuLy8gdGhlIG93bmVyIG9mIHRoZWlyIGFwcGxpY2F0aW9uLiBPdGhlciBzdHVkZW50cyBtYXkgdXNlIGl0IGJ1dCB0aGV5IGFyZSBvbmx5IHVzZXJzIGFuZCBub3Qgb3duZXJzLlxuLy8gTWVzc2FnZXMgc2VudCB0byB0aGUgc2VydmVyIGFyZSBzZXBhcmF0ZWQgdy5yLnQuIHRoZSBuYW1lIG9mIHRoZSBhcHBsaWNhdGlvbiAoaS5lLiB0aGUgbmFtZSBvZiB0aGVpciBvd25lcnMpLlxuLy8gVGhlIG5hbWUgb2YgdGhlIG93bmVycyBpcyB0aGUgbmFtZSBvZiB0aGUgZm9sZGVyIG9mIHRoZSBhcHBsaWNhdGlvbiB3aGVyZSB0aGUgd2ViIHBhZ2VzIG9mIHRoZSBhcHBsaWNhdGlvbiBhcmUgc3RvcmVkLiBcbi8vIEUuZywgZm9yIHRlYWNoZXJzJyBhcHBsaWNhdGlvbiB0aGlzIG5hbWUgaXMgXCJlbnNcIlxuXG4vLyBEbyBub3QgbW9kaWZ5IVxuZnVuY3Rpb24gZ2V0T3duZXJOYW1lKCk6IHN0cmluZyB7XG4gICAgY29uc3QgcGF0aCA9IHdpbmRvdy5sb2NhdGlvbi5wYXRobmFtZVxuICAgIGNvbnN0IG5hbWUgPSBwYXRoLnNwbGl0KFwiL1wiLCAyKVsxXVxuICAgIHJldHVybiBuYW1lXG59XG5cbi8vIERvIG5vdCBtb2RpZnkhXG5sZXQgb3duZXJOYW1lID0gZ2V0T3duZXJOYW1lKClcblxuLy8gV0FSTklORyFcbi8vIEl0IGlzIG5lY2Vzc2FyeSB0byBwYXNzIHRoZSBVUkwgcGFyYW1ldGVycywgY2FsbGVkIGB1cmxQYXJhbXNgIGJlbG93LCB0byBcbi8vIGV2ZXJ5IEdFVC9QT1NUIHF1ZXJ5IHlvdSBzZW5kIHRvIHRoZSBzZXJ2ZXIuIFRoaXMgaXMgbWFuZGF0b3J5IHRvIGhhdmUgdGhlIHBvc3NpYmlsaXR5IFxuLy8gdG8gdXNlIGFsdGVybmF0aXZlIGlkZW50aXRpZXMgbGlrZSBhbGljZUB1bml2LXJlbm5lcy5mciwgYm9iQHVuaXYtcmVubmVzLmZyLCBldGMuIFxuLy8gZm9yIGRlYnVnZ2luZyBwdXJwb3Nlcy5cblxuLy8gRG8gbm90IG1vZGlmeVxuYXN5bmMgZnVuY3Rpb24gZmV0Y2hLZXkodXNlcjogc3RyaW5nLCBwdWJsaWNLZXk6IGJvb2xlYW4sIGVuY3J5cHRpb246IGJvb2xlYW4pOiBQcm9taXNlPENyeXB0b0tleT4ge1xuICAgIC8vIEdldHRpbmcgdGhlIHB1YmxpYy9wcml2YXRlIGtleSBvZiB1c2VyLlxuICAgIC8vIEZvciBwdWJsaWMga2V5IHRoZSBib29sZWFuICdwdWJsaWNLZXknIGlzIHRydWUuXG4gICAgLy8gRm9yIHByaXZhdGUga2V5IHRoZSBib29sZWFuICdwdWJsaWNLZXknIGlzIGZhbHNlLlxuICAgIC8vIElmIHRoZSBrZXkgaXMgdXNlZCBmb3IgZW5jcnlwdGlvbi9kZWNyeXB0aW9uIHRoZW4gdGhlIGJvb2xlYW4gJ2VuY3J5cHRpb24nIGlzIHRydWUuXG4gICAgLy8gSWYgdGhlIGtleSBpcyB1c2VkIGZvciBzaWduYXR1cmUvc2lnbmF0dXJlIHZlcmlmaWNhdGlvbiB0aGVuIHRoZSBib29sZWFuIGlzIGZhbHNlLlxuICAgIGNvbnN0IGtleVJlcXVlc3RNZXNzYWdlID1cbiAgICAgICAgbmV3IEtleVJlcXVlc3QodXNlciwgcHVibGljS2V5LCBlbmNyeXB0aW9uKVxuICAgIC8vIEZvciBDQVMgYXV0aGVudGljYXRpb24gd2UgbmVlZCB0byBhZGQgdGhlIGF1dGhlbnRpY2F0aW9uIHRpY2tldFxuICAgIC8vIEl0IGlzIGNvbnRhaW5lZCBpbiB1cmxQYXJhbXNcbiAgICBjb25zdCB1cmxQYXJhbXMgPSBuZXcgVVJMU2VhcmNoUGFyYW1zKHdpbmRvdy5sb2NhdGlvbi5zZWFyY2gpO1xuICAgIC8vIEZvciBnZXR0aW5nIGEga2V5IHdlIGRvIG5vdCBuZWVkIHRoZSBvd25lck5hbWUgcGFyYW1cbiAgICAvLyBCZWNhdXNlIGtleXMgYXJlIGluZGVwZW5kYW50IG9mIHRoZSBhcHBsaWNhdGlvbnNcbiAgICBjb25zdCBrZXlyZXF1ZXN0ID0gYXdhaXQgZmV0Y2goXCIvZ2V0S2V5P1wiICsgdXJsUGFyYW1zLCB7XG4gICAgICAgIG1ldGhvZDogXCJQT1NUXCIsXG4gICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KGtleVJlcXVlc3RNZXNzYWdlKSxcbiAgICAgICAgaGVhZGVyczoge1xuICAgICAgICAgICAgXCJDb250ZW50LXR5cGVcIjogXCJhcHBsaWNhdGlvbi9qc29uOyBjaGFyc2V0PVVURi04XCJcbiAgICAgICAgfVxuICAgIH0pO1xuICAgIGlmICgha2V5cmVxdWVzdC5vaykge1xuICAgICAgICB0aHJvdyBuZXcgRXJyb3IoYEVycm9yISBzdGF0dXM6ICR7a2V5cmVxdWVzdC5zdGF0dXN9YCk7XG4gICAgfVxuICAgIGNvbnN0IGtleVJlc3VsdCA9IChhd2FpdCBrZXlyZXF1ZXN0Lmpzb24oKSkgYXMgS2V5UmVzdWx0O1xuICAgIGlmICgha2V5UmVzdWx0LnN1Y2Nlc3MpIGFsZXJ0KGtleVJlc3VsdC5lcnJvck1lc3NhZ2UpXG4gICAgZWxzZSB7XG4gICAgICAgIGlmIChwdWJsaWNLZXkgJiYgZW5jcnlwdGlvbikgcmV0dXJuIGF3YWl0IHN0cmluZ1RvUHVibGljS2V5Rm9yRW5jcnlwdGlvbihrZXlSZXN1bHQua2V5KVxuICAgICAgICBlbHNlIGlmICghcHVibGljS2V5ICYmIGVuY3J5cHRpb24pIHJldHVybiBhd2FpdCBzdHJpbmdUb1ByaXZhdGVLZXlGb3JFbmNyeXB0aW9uKGtleVJlc3VsdC5rZXkpXG4gICAgICAgIGVsc2UgaWYgKHB1YmxpY0tleSAmJiAhZW5jcnlwdGlvbikgcmV0dXJuIGF3YWl0IHN0cmluZ1RvUHVibGljS2V5Rm9yU2lnbmF0dXJlKGtleVJlc3VsdC5rZXkpXG4gICAgICAgIGVsc2UgaWYgKCFwdWJsaWNLZXkgJiYgIWVuY3J5cHRpb24pIHJldHVybiBhd2FpdCBzdHJpbmdUb1ByaXZhdGVLZXlGb3JTaWduYXR1cmUoa2V5UmVzdWx0LmtleSlcbiAgICB9XG59XG5cbi8vIFdBUk5JTkchXG4vLyBJdCBpcyBuZWNlc3NhcnkgdG8gcGFzcyB0aGUgVVJMIHBhcmFtZXRlcnMsIGNhbGxlZCBgdXJsUGFyYW1zYCBiZWxvdywgdG8gXG4vLyBldmVyeSBHRVQvUE9TVCBxdWVyeSB5b3Ugc2VuZCB0byB0aGUgc2VydmVyLiBUaGlzIGlzIG1hbmRhdG9yeSB0byBoYXZlIHRoZSBwb3NzaWJpbGl0eSBcbi8vIHRvIHVzZSBhbHRlcm5hdGl2ZSBpZGVudGl0aWVzIGxpa2UgYWxpY2VAdW5pdi1yZW5uZXMuZnIsIGJvYkB1bml2LXJlbm5lcy5mciwgZXRjLiBcbi8vIGZvciBkZWJ1Z2dpbmcgcHVycG9zZXMuXG4vLyBcbi8vIFdlIGFsc28gbmVlZCB0byBwcm92aWRlIHRoZSBvd25lck5hbWVcblxuLy8gRG8gbm90IG1vZGlmeSFcbmFzeW5jIGZ1bmN0aW9uIHNlbmRNZXNzYWdlKGFnZW50TmFtZTogc3RyaW5nLCByZWNlaXZlck5hbWU6IHN0cmluZywgbWVzc2FnZUNvbnRlbnQ6IHN0cmluZyk6IFByb21pc2U8U2VuZFJlc3VsdD4ge1xuICAgIHRyeSB7XG4gICAgICAgIGxldCBtZXNzYWdlVG9TZW5kID1cbiAgICAgICAgICAgIG5ldyBFeHRNZXNzYWdlKGFnZW50TmFtZSwgcmVjZWl2ZXJOYW1lLCBtZXNzYWdlQ29udGVudClcbiAgICAgICAgY29uc3QgdXJsUGFyYW1zID0gbmV3IFVSTFNlYXJjaFBhcmFtcyh3aW5kb3cubG9jYXRpb24uc2VhcmNoKTtcblxuICAgICAgICBjb25zdCByZXF1ZXN0ID0gYXdhaXQgZmV0Y2goXCIvc2VuZGluZ01lc3NhZ2UvXCIgKyBvd25lck5hbWUgKyBcIj9cIiArIHVybFBhcmFtcywge1xuICAgICAgICAgICAgbWV0aG9kOiBcIlBPU1RcIixcbiAgICAgICAgICAgIGJvZHk6IEpTT04uc3RyaW5naWZ5KG1lc3NhZ2VUb1NlbmQpLFxuICAgICAgICAgICAgaGVhZGVyczoge1xuICAgICAgICAgICAgICAgIFwiQ29udGVudC10eXBlXCI6IFwiYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD1VVEYtOFwiXG4gICAgICAgICAgICB9XG4gICAgICAgIH0pO1xuICAgICAgICBpZiAoIXJlcXVlc3Qub2spIHtcbiAgICAgICAgICAgIHRocm93IG5ldyBFcnJvcihgRXJyb3IhIHN0YXR1czogJHtyZXF1ZXN0LnN0YXR1c31gKTtcbiAgICAgICAgfVxuICAgICAgICAvLyBEZWFsaW5nIHdpdGggdGhlIGFuc3dlciBvZiB0aGUgbWVzc2FnZSBzZXJ2ZXJcbiAgICAgICAgY29uc29sZS5sb2coYFNlbnQgbWVzc2FnZSBmcm9tICR7YWdlbnROYW1lfSB0byAke3JlY2VpdmVyTmFtZX06ICR7bWVzc2FnZUNvbnRlbnR9YClcbiAgICAgICAgcmV0dXJuIChhd2FpdCByZXF1ZXN0Lmpzb24oKSkgYXMgU2VuZFJlc3VsdFxuICAgIH1cbiAgICBjYXRjaCAoZXJyb3IpIHtcbiAgICAgICAgaWYgKGVycm9yIGluc3RhbmNlb2YgRXJyb3IpIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKCdlcnJvciBtZXNzYWdlOiAnLCBlcnJvci5tZXNzYWdlKTtcbiAgICAgICAgICAgIHJldHVybiBuZXcgU2VuZFJlc3VsdChmYWxzZSwgZXJyb3IubWVzc2FnZSlcbiAgICAgICAgfSBlbHNlIHtcbiAgICAgICAgICAgIGNvbnNvbGUubG9nKCd1bmV4cGVjdGVkIGVycm9yOiAnLCBlcnJvcik7XG4gICAgICAgICAgICByZXR1cm4gbmV3IFNlbmRSZXN1bHQoZmFsc2UsICdBbiB1bmV4cGVjdGVkIGVycm9yIG9jY3VycmVkJylcbiAgICAgICAgfVxuICAgIH1cbn1cblxuLy8gLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS1cbi8vIC0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tXG4vLyBZb3UgY2FuIG1vZGlmeSB0aGUgY29kZSBiZWxvd1xuXG5pbXBvcnQge1xuICAgIHN0cmluZ1RvUHJpdmF0ZUtleUZvckVuY3J5cHRpb24sIHN0cmluZ1RvUHVibGljS2V5Rm9yRW5jcnlwdGlvbixcbiAgICBzdHJpbmdUb1ByaXZhdGVLZXlGb3JTaWduYXR1cmUsXG4gICAgc3RyaW5nVG9QdWJsaWNLZXlGb3JTaWduYXR1cmUsXG4gICAgZW5jcnlwdFdpdGhQdWJsaWNLZXksXG4gICAgZGVjcnlwdFdpdGhQcml2YXRlS2V5LFxuICAgIHNpZ25XaXRoUHJpdmF0ZUtleSxcbiAgICB2ZXJpZnlTaWduYXR1cmVXaXRoUHVibGljS2V5LFxuICAgIGVuY3J5cHRXaXRoU3ltbWV0cmljS2V5LFxuICAgIGRlY3J5cHRXaXRoU3ltbWV0cmljS2V5LFxuICAgIGdlbmVyYXRlU3ltZXRyaWNLZXksXG4gICAgc3ltbWV0cmljS2V5VG9TdHJpbmcsXG4gICAgc3RyaW5nVG9TeW1tZXRyaWNLZXksXG4gICAgcHJpdmF0ZUtleVRvU3RyaW5nLFxuICAgIGhhc2gsXG59IGZyb20gJy4vbGliQ3J5cHRvJ1xuXG5jb25zdCB1c2VyQnV0dG9uTGFiZWwgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcInVzZXItbmFtZVwiKSBhcyBIVE1MTGFiZWxFbGVtZW50XG5jb25zdCBzZW5kQnV0dG9uID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJzZW5kLWJ1dHRvblwiKSBhcyBIVE1MQnV0dG9uRWxlbWVudFxuY29uc3QgcmVjZWl2ZXIgPSBkb2N1bWVudC5nZXRFbGVtZW50QnlJZChcInJlY2VpdmVyXCIpIGFzIEhUTUxJbnB1dEVsZW1lbnRcbmNvbnN0IG1lc3NhZ2VHID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJtZXNzYWdlXCIpIGFzIEhUTUxJbnB1dEVsZW1lbnRcbmNvbnN0IHJlY2VpdmVkX21lc3NhZ2VzID0gZG9jdW1lbnQuZ2V0RWxlbWVudEJ5SWQoXCJleGNoYW5nZWQtbWVzc2FnZXNcIikgYXMgSFRNTExhYmVsRWxlbWVudFxuXG4vLyBBZmZpY2hlIGxlIG1lc3NhZ2UgZW4gdGV4dGUgYnJ1dCAoU1x1MDBFOWN1cml0XHUwMEU5KVxuZnVuY3Rpb24gYWRkaW5nUmVjZWl2ZWRNZXNzYWdlKG1lc3NhZ2U6IHN0cmluZykge1xuICAgIGNvbnN0IHAgPSBkb2N1bWVudC5jcmVhdGVFbGVtZW50KCdwJyk7XG4gICAgcC50ZXh0Q29udGVudCA9IG1lc3NhZ2U7XG4gICAgcmVjZWl2ZWRfbWVzc2FnZXMuYXBwZW5kKHApO1xufVxuXG4vLyAtLS0gQ0hJRkZSRU1FTlQgSFlCUklERSA6IEFzc3VyZSBQcm9wIDEgKFNlY3JldCkgZXQgUHJvcCA3IChNZXNzYWdlcyBsb25ncykgXG5hc3luYyBmdW5jdGlvbiBoeWJyaWRFbmNyeXB0KHJzYVB1YmxpY0tleTogQ3J5cHRvS2V5LCBtZXNzYWdlOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIGNvbnN0IGFlc0tleSA9IGF3YWl0IGdlbmVyYXRlU3ltZXRyaWNLZXkoKSAvLyBDbFx1MDBFOSBBRVMgcG91ciBjaGlmZnJlciBsZSBjb250ZW51ICh2aXRlc3NlKVxuICAgIGNvbnN0IFtjeXBoZXJlZCwgaXZdID0gYXdhaXQgZW5jcnlwdFdpdGhTeW1tZXRyaWNLZXkoYWVzS2V5LCBtZXNzYWdlKVxuICAgIGNvbnN0IGFlc0tleVN0ciA9IGF3YWl0IHN5bW1ldHJpY0tleVRvU3RyaW5nKGFlc0tleSlcbiAgICBjb25zdCBlbmNyeXB0ZWRBZXNLZXkgPSBhd2FpdCBlbmNyeXB0V2l0aFB1YmxpY0tleShyc2FQdWJsaWNLZXksIGFlc0tleVN0cikgLy8gUlNBIHByb3RcdTAwRThnZSBsYSBjbFx1MDBFOSBBRVNcbiAgICByZXR1cm4gSlNPTi5zdHJpbmdpZnkoeyByc2FrZXk6IGVuY3J5cHRlZEFlc0tleSwgY3lwaGVyZWQsIGl2IH0pXG59XG5cbmFzeW5jIGZ1bmN0aW9uIGh5YnJpZERlY3J5cHQocnNhUHJpdmF0ZUtleTogQ3J5cHRvS2V5LCBlbmNyeXB0ZWRQYXlsb2FkOiBzdHJpbmcpOiBQcm9taXNlPHN0cmluZz4ge1xuICAgIGNvbnN0IHsgcnNha2V5LCBjeXBoZXJlZCwgaXYgfSA9IEpTT04ucGFyc2UoZW5jcnlwdGVkUGF5bG9hZClcbiAgICBjb25zdCBhZXNLZXlTdHIgPSBhd2FpdCBkZWNyeXB0V2l0aFByaXZhdGVLZXkocnNhUHJpdmF0ZUtleSwgcnNha2V5KVxuICAgIGNvbnN0IGFlc0tleSA9IGF3YWl0IHN0cmluZ1RvU3ltbWV0cmljS2V5KGFlc0tleVN0cilcbiAgICByZXR1cm4gYXdhaXQgZGVjcnlwdFdpdGhTeW1tZXRyaWNLZXkoYWVzS2V5LCBjeXBoZXJlZCwgaXYpXG59XG5cbi8vICBISVNUT1JJUVVFIExPQ0FMIDogQXNzdXJlIFByb3AgNSAoUGVyc2lzdGFuY2UpIGV0IFByb3AgNiAoU3RvY2thZ2UgY2hpZmZyXHUwMEU5KSAtLS1cbmxldCBsb2NhbFN0b3JhZ2VBZXNLZXk6IENyeXB0b0tleSB8IG51bGwgPSBudWxsXG5cbmFzeW5jIGZ1bmN0aW9uIGdldExvY2FsQWVzS2V5KCk6IFByb21pc2U8Q3J5cHRvS2V5PiB7XG4gICAgaWYgKGxvY2FsU3RvcmFnZUFlc0tleSkgcmV0dXJuIGxvY2FsU3RvcmFnZUFlc0tleVxuICAgIGNvbnN0IHByaXZLZXlSU0EgPSBhd2FpdCBmZXRjaEtleShnbG9iYWxVc2VyTmFtZSwgZmFsc2UsIHRydWUpXG4gICAgY29uc3QgcHJpdktleVN0ciA9IGF3YWl0IHByaXZhdGVLZXlUb1N0cmluZyhwcml2S2V5UlNBKVxuICAgIGNvbnN0IGhhc2hPZktleSA9IGF3YWl0IGhhc2gocHJpdktleVN0cikgLy8gQ2xcdTAwRTkgQUVTIGxvY2FsZSBkXHUwMEU5cml2XHUwMEU5ZSBkdSBzZWNyZXQgUlNBIGRlIGwndXRpbGlzYXRldXJcbiAgICBjb25zdCByYXdCeXRlcyA9IGF0b2IoaGFzaE9mS2V5KS5zbGljZSgwLCAzMilcbiAgICBjb25zdCByYXdBcnJheSA9IG5ldyBVaW50OEFycmF5KHJhd0J5dGVzLmxlbmd0aClcbiAgICBmb3IgKGxldCBpID0gMDsgaSA8IHJhd0J5dGVzLmxlbmd0aDsgaSsrKSByYXdBcnJheVtpXSA9IHJhd0J5dGVzLmNoYXJDb2RlQXQoaSlcbiAgICBsb2NhbFN0b3JhZ2VBZXNLZXkgPSBhd2FpdCB3aW5kb3cuY3J5cHRvLnN1YnRsZS5pbXBvcnRLZXkoXG4gICAgICAgIFwicmF3XCIsIHJhd0FycmF5LCBcIkFFUy1HQ01cIiwgZmFsc2UsIFtcImVuY3J5cHRcIiwgXCJkZWNyeXB0XCJdXG4gICAgKVxuICAgIHJldHVybiBsb2NhbFN0b3JhZ2VBZXNLZXlcbn1cblxuZnVuY3Rpb24gbG9jYWxTdG9yYWdlS2V5TmFtZSgpOiBzdHJpbmcge1xuICAgIHJldHVybiBgaGlzdG9yeV8ke2dsb2JhbFVzZXJOYW1lfWBcbn1cblxuYXN5bmMgZnVuY3Rpb24gcmVhZExvY2FsSGlzdG9yeSgpOiBQcm9taXNlPHN0cmluZ1tdPiB7XG4gICAgdHJ5IHtcbiAgICAgICAgY29uc3QgcmF3ID0gbG9jYWxTdG9yYWdlLmdldEl0ZW0obG9jYWxTdG9yYWdlS2V5TmFtZSgpKVxuICAgICAgICBpZiAoIXJhdykgcmV0dXJuIFtdXG4gICAgICAgIGNvbnN0IHsgY3lwaGVyZWQsIGl2IH0gPSBKU09OLnBhcnNlKHJhdylcbiAgICAgICAgY29uc3QgYWVzS2V5ID0gYXdhaXQgZ2V0TG9jYWxBZXNLZXkoKVxuICAgICAgICBjb25zdCBkZWNyeXB0ZWQgPSBhd2FpdCBkZWNyeXB0V2l0aFN5bW1ldHJpY0tleShhZXNLZXksIGN5cGhlcmVkLCBpdilcbiAgICAgICAgcmV0dXJuIEpTT04ucGFyc2UoZGVjcnlwdGVkKSBhcyBzdHJpbmdbXVxuICAgIH0gY2F0Y2ggKGUpIHtcbiAgICAgICAgY29uc29sZS5sb2coXCJFcnJldXIgbGVjdHVyZSBoaXN0b3JpcXVlIDogXCIsIGUpXG4gICAgICAgIHJldHVybiBbXVxuICAgIH1cbn1cblxuYXN5bmMgZnVuY3Rpb24gc2F2ZVRvTG9jYWxIaXN0b3J5KGVudHJ5OiBzdHJpbmcpIHtcbiAgICB0cnkge1xuICAgICAgICBjb25zdCBleGlzdGluZyA9IGF3YWl0IHJlYWRMb2NhbEhpc3RvcnkoKVxuICAgICAgICBleGlzdGluZy5wdXNoKGVudHJ5KVxuICAgICAgICBjb25zdCBhZXNLZXkgPSBhd2FpdCBnZXRMb2NhbEFlc0tleSgpXG4gICAgICAgIGNvbnN0IFtjeXBoZXJlZCwgaXZdID0gYXdhaXQgZW5jcnlwdFdpdGhTeW1tZXRyaWNLZXkoYWVzS2V5LCBKU09OLnN0cmluZ2lmeShleGlzdGluZykpXG4gICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKGxvY2FsU3RvcmFnZUtleU5hbWUoKSwgSlNPTi5zdHJpbmdpZnkoeyBjeXBoZXJlZCwgaXYgfSkpXG4gICAgfSBjYXRjaCAoZSkge1xuICAgICAgICBjb25zb2xlLmxvZyhcIkVycmV1ciBzYXV2ZWdhcmRlIGhpc3RvcmlxdWUgOiBcIiwgZSlcbiAgICB9XG59XG5cbmFzeW5jIGZ1bmN0aW9uIGxvYWRMb2NhbEhpc3RvcnkoKSB7XG4gICAgY29uc3QgZW50cmllcyA9IGF3YWl0IHJlYWRMb2NhbEhpc3RvcnkoKVxuICAgIGZvciAoY29uc3QgZW50cnkgb2YgZW50cmllcykge1xuICAgICAgICBhZGRpbmdSZWNlaXZlZE1lc3NhZ2UoZW50cnkpXG4gICAgfVxufVxuXG5hc3luYyBmdW5jdGlvbiBkaXNwbGF5QW5kU2F2ZSh0ZXh0OiBzdHJpbmcpIHtcbiAgICBhZGRpbmdSZWNlaXZlZE1lc3NhZ2UodGV4dCkgLy8gUHJvcCAwIDogVmlzaWJpbGl0XHUwMEU5IHN1ciBsJ2ludGVyZmFjZVxuICAgIGF3YWl0IHNhdmVUb0xvY2FsSGlzdG9yeSh0ZXh0KVxufVxuXG5mdW5jdGlvbiBsb2FkTGFzdEluZGV4KCk6IG51bWJlciB7XG4gICAgcmV0dXJuIHBhcnNlSW50KGxvY2FsU3RvcmFnZS5nZXRJdGVtKGBsYXN0SW5kZXhfJHtnbG9iYWxVc2VyTmFtZX1gKSB8fCBcIjBcIilcbn1cblxuZnVuY3Rpb24gc2F2ZUxhc3RJbmRleChpbmRleDogbnVtYmVyKSB7XG4gICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oYGxhc3RJbmRleF8ke2dsb2JhbFVzZXJOYW1lfWAsIGluZGV4LnRvU3RyaW5nKCkpXG59XG5cbmxldCBsYXN0SW5kZXhJbkhpc3RvcnkgPSAwXG5cbi8vIEluaXRpYWxpc2F0aW9uIDogY2hhcmdlIGwnaGlzdG9yaXF1ZSBldCBsYW5jZSBsYSBQcm9wIDQgKFJcdTAwRTljZXB0aW9uIGFzeW5jaHJvbmUpXG5hc3luYyBmdW5jdGlvbiBpbml0KCkge1xuICAgIHdoaWxlIChnbG9iYWxVc2VyTmFtZSA9PT0gXCJcIikge1xuICAgICAgICBhd2FpdCBuZXcgUHJvbWlzZShyZXNvbHZlID0+IHNldFRpbWVvdXQocmVzb2x2ZSwgNTApKVxuICAgIH1cbiAgICBhd2FpdCBsb2FkTG9jYWxIaXN0b3J5KClcbiAgICBsYXN0SW5kZXhJbkhpc3RvcnkgPSBsb2FkTGFzdEluZGV4KClcbiAgICBzZXRJbnRlcnZhbChyZWZyZXNoLCAyMDAwKVxufVxuXG5pbml0KClcblxuLy8gUlx1MDBFOWN1cFx1MDBFOXJhdGlvbiBwXHUwMEU5cmlvZGlxdWUgZGVzIG1lc3NhZ2VzIHN1ciBsZSBzZXJ2ZXVyIChQcm9wIDQpXG5hc3luYyBmdW5jdGlvbiByZWZyZXNoKCkge1xuICAgIHRyeSB7XG4gICAgICAgIGNvbnN0IHVzZXIgPSBnbG9iYWxVc2VyTmFtZVxuICAgICAgICBjb25zdCBoaXN0b3J5UmVxdWVzdCA9IG5ldyBIaXN0b3J5UmVxdWVzdCh1c2VyLCBsYXN0SW5kZXhJbkhpc3RvcnkpXG4gICAgICAgIGNvbnN0IHVybFBhcmFtcyA9IG5ldyBVUkxTZWFyY2hQYXJhbXMod2luZG93LmxvY2F0aW9uLnNlYXJjaCk7XG4gICAgICAgIGNvbnN0IHJlcXVlc3QgPSBhd2FpdCBmZXRjaChcIi9oaXN0b3J5L1wiICsgb3duZXJOYW1lICsgXCI/XCIgKyB1cmxQYXJhbXMsIHtcbiAgICAgICAgICAgIG1ldGhvZDogXCJQT1NUXCIsXG4gICAgICAgICAgICBib2R5OiBKU09OLnN0cmluZ2lmeShoaXN0b3J5UmVxdWVzdCksXG4gICAgICAgICAgICBoZWFkZXJzOiB7IFwiQ29udGVudC10eXBlXCI6IFwiYXBwbGljYXRpb24vanNvbjsgY2hhcnNldD1VVEYtOFwiIH1cbiAgICAgICAgfSk7XG4gICAgICAgIGlmICghcmVxdWVzdC5vaykgdGhyb3cgbmV3IEVycm9yKGBFcnJvciEgc3RhdHVzOiAke3JlcXVlc3Quc3RhdHVzfWApO1xuICAgICAgICBjb25zdCByZXN1bHQgPSAoYXdhaXQgcmVxdWVzdC5qc29uKCkpIGFzIEhpc3RvcnlBbnN3ZXJcbiAgICAgICAgaWYgKCFyZXN1bHQuc3VjY2VzcykgeyBhbGVydChyZXN1bHQuZmFpbHVyZU1lc3NhZ2UpIH1cbiAgICAgICAgZWxzZSB7XG4gICAgICAgICAgICBsYXN0SW5kZXhJbkhpc3RvcnkgPSByZXN1bHQuaW5kZXhcbiAgICAgICAgICAgIHNhdmVMYXN0SW5kZXgocmVzdWx0LmluZGV4KVxuICAgICAgICAgICAgZm9yIChjb25zdCBtIG9mIHJlc3VsdC5hbGxNZXNzYWdlcykge1xuICAgICAgICAgICAgICAgIGF3YWl0IGFuYWx5c2VNZXNzYWdlKG0pXG4gICAgICAgICAgICB9XG4gICAgICAgIH1cbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICBjb25zb2xlLmxvZygnRXJyZXVyIHJlZnJlc2g6ICcsIGVycm9yKTtcbiAgICB9XG59XG5cbi8vIEJPVVRPTiBFTlZPWUVSIDogXHUwMEM5dGFwZSAxIGR1IHByb3RvY29sZVxuc2VuZEJ1dHRvbi5vbmNsaWNrID0gYXN5bmMgZnVuY3Rpb24gKCkge1xuICAgIGNvbnN0IGFnZW50TmFtZSA9IGdsb2JhbFVzZXJOYW1lO1xuICAgIGNvbnN0IHJlY2VpdmVyTmFtZSA9IHJlY2VpdmVyLnZhbHVlLnRyaW0oKTtcbiAgICBjb25zdCBtZXNzYWdlQ29udGVudCA9IG1lc3NhZ2VHLnZhbHVlLnRyaW0oKTtcbiAgICBpZiAoIXJlY2VpdmVyTmFtZSB8fCAhbWVzc2FnZUNvbnRlbnQpIHJldHVybjtcblxuICAgIHRyeSB7XG4gICAgICAgIGNvbnNvbGUubG9nKGBFdGFwZSAxIDogJHthZ2VudE5hbWV9IGVudm9pZSB1biBtZXNzYWdlIGEgJHtyZWNlaXZlck5hbWV9YClcblxuICAgICAgICBjb25zdCBwcml2S2V5QSA9IGF3YWl0IGZldGNoS2V5KGFnZW50TmFtZSwgZmFsc2UsIGZhbHNlKVxuICAgICAgICAvLyBTaWduYXR1cmUgRnVsbCBDb250ZXh0IDogQXNzdXJlIFByb3AgMiAoQXV0aGVudGljaXRcdTAwRTkpXG4gICAgICAgIGNvbnN0IHNpZ25hdHVyZSA9IGF3YWl0IHNpZ25XaXRoUHJpdmF0ZUtleShwcml2S2V5QSwgXCIxfFwiICsgYWdlbnROYW1lICsgXCJ8XCIgKyByZWNlaXZlck5hbWUgKyBcInxcIiArIG1lc3NhZ2VDb250ZW50KVxuICAgICAgICBcbiAgICAgICAgY29uc3QgcGtleUIgPSBhd2FpdCBmZXRjaEtleShyZWNlaXZlck5hbWUsIHRydWUsIHRydWUpXG4gICAgICAgIGNvbnN0IHBheWxvYWQgPSBKU09OLnN0cmluZ2lmeShbXCIxXCIsIGFnZW50TmFtZSwgbWVzc2FnZUNvbnRlbnQsIHNpZ25hdHVyZV0pXG4gICAgICAgIGNvbnN0IGVuY3J5cHRlZE1lc3NhZ2UgPSBhd2FpdCBoeWJyaWRFbmNyeXB0KHBrZXlCLCBwYXlsb2FkKVxuXG4gICAgICAgIGNvbnN0IHNlbmRSZXN1bHQgPSBhd2FpdCBzZW5kTWVzc2FnZShhZ2VudE5hbWUsIHJlY2VpdmVyTmFtZSwgZW5jcnlwdGVkTWVzc2FnZSlcbiAgICAgICAgaWYgKCFzZW5kUmVzdWx0LnN1Y2Nlc3MpIHJldHVyblxuXG4gICAgICAgIGF3YWl0IGRpc3BsYXlBbmRTYXZlKGAke2FnZW50TmFtZX0gLT4gJHtyZWNlaXZlck5hbWV9IDogJHttZXNzYWdlQ29udGVudH1gKVxuICAgICAgICBtZXNzYWdlRy52YWx1ZSA9IFwiXCJcbiAgICB9IGNhdGNoIChlcnJvcikge1xuICAgICAgICBjb25zb2xlLmxvZyhcIkVycmV1ciBlbnZvaSA6IFwiLCBlcnJvcilcbiAgICB9XG59XG5cbi8vICBBTkFMWVNFIERFUyBNRVNTQUdFUyA6IEdlc3Rpb24gZGVzIFx1MDBFOXRhcGVzIDEgZXQgMiBcbmFzeW5jIGZ1bmN0aW9uIGFuYWx5c2VNZXNzYWdlKG1lc3NhZ2U6IEV4dE1lc3NhZ2UpOiBQcm9taXNlPHZvaWQ+IHtcbiAgICBjb25zdCBhZ2VudE5hbWUgPSBnbG9iYWxVc2VyTmFtZTtcblxuICAgIHRyeSB7XG4gICAgICAgIGlmIChtZXNzYWdlLnJlY2VpdmVyICE9PSBhZ2VudE5hbWUpIHJldHVybjtcblxuICAgICAgICBjb25zdCBwcml2S2V5ID0gYXdhaXQgZmV0Y2hLZXkoYWdlbnROYW1lLCBmYWxzZSwgdHJ1ZSlcbiAgICAgICAgY29uc3QgbWVzc2FnZUluQ2xlYXIgPSBhd2FpdCBoeWJyaWREZWNyeXB0KHByaXZLZXksIG1lc3NhZ2UuY29udGVudClcbiAgICAgICAgY29uc3QgZGF0YUFycmF5ID0gSlNPTi5wYXJzZShtZXNzYWdlSW5DbGVhcikgYXMgc3RyaW5nW11cbiAgICAgICAgY29uc3QgaW5kZXggPSBwYXJzZUludChkYXRhQXJyYXlbMF0sIDEwKVxuXG4gICAgICAgIHN3aXRjaCAoaW5kZXgpIHtcblxuICAgICAgICAgICAgY2FzZSAxOiB7IC8vIFJcdTAwRTljZXB0aW9uIGQndW4gbm91dmVhdSBtZXNzYWdlXG4gICAgICAgICAgICAgICAgY29uc3Qgc2VuZGVyQSA9IGRhdGFBcnJheVsxXVxuICAgICAgICAgICAgICAgIGNvbnN0IG0gPSBkYXRhQXJyYXlbMl1cbiAgICAgICAgICAgICAgICBjb25zdCBzaWcgPSBkYXRhQXJyYXlbM11cblxuICAgICAgICAgICAgICAgIGlmIChzZW5kZXJBID09PSBhZ2VudE5hbWUpIHJldHVyblxuXG4gICAgICAgICAgICAgICAgLy8gQW50aS1yZWpldSA6IEFzc3VyZSBQcm9wIDggKFVuIG1lc3NhZ2Ugbidlc3QgdHJhaXRcdTAwRTkgcXUndW5lIGZvaXMpXG4gICAgICAgICAgICAgICAgY29uc3QgYWNrS2V5ID0gYGFja18ke2FnZW50TmFtZX1fJHtzZW5kZXJBfV8ke219YFxuICAgICAgICAgICAgICAgIGlmIChsb2NhbFN0b3JhZ2UuZ2V0SXRlbShhY2tLZXkpKSByZXR1cm5cblxuICAgICAgICAgICAgICAgIC8vIFZcdTAwRTlyaWZpY2F0aW9uIHNpZ25hdHVyZSA6IFZhbGlkZSBQcm9wIDIgKElkZW50aXRcdTAwRTkgZGUgbCdleHBcdTAwRTlkaXRldXIpXG4gICAgICAgICAgICAgICAgY29uc3QgcHViS2V5QSA9IGF3YWl0IGZldGNoS2V5KHNlbmRlckEsIHRydWUsIGZhbHNlKVxuICAgICAgICAgICAgICAgIGNvbnN0IHZhbGlkID0gYXdhaXQgdmVyaWZ5U2lnbmF0dXJlV2l0aFB1YmxpY0tleShwdWJLZXlBLCBcIjF8XCIgKyBzZW5kZXJBICsgXCJ8XCIgKyBhZ2VudE5hbWUgKyBcInxcIiArIG0sIHNpZylcbiAgICAgICAgICAgICAgICBpZiAoIXZhbGlkKSB7XG4gICAgICAgICAgICAgICAgICAgIGNvbnNvbGUubG9nKGBTaWduYXR1cmUgaW52YWxpZGUsIG1lc3NhZ2UgcmVqZXRcdTAwRTkuYCk7XG4gICAgICAgICAgICAgICAgICAgIHJldHVyblxuICAgICAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgICAgIGF3YWl0IGRpc3BsYXlBbmRTYXZlKGAke3NlbmRlckF9IC0+ICR7YWdlbnROYW1lfSA6ICR7bX1gKVxuXG4gICAgICAgICAgICAgICAgLy8gIFx1MDBDOXRhcGUgMiA6IEVudm9pIGRlIGwnQWNjdXNcdTAwRTkgKFByb3AgMyA6IENvbmZpcm1hdGlvbiBkZSByXHUwMEU5Y2VwdGlvbikgXG4gICAgICAgICAgICAgICAgY29uc3QgcHJpdktleUIgPSBhd2FpdCBmZXRjaEtleShhZ2VudE5hbWUsIGZhbHNlLCBmYWxzZSlcbiAgICAgICAgICAgICAgICBjb25zdCBzaWdCID0gYXdhaXQgc2lnbldpdGhQcml2YXRlS2V5KHByaXZLZXlCLCBcIjJ8XCIgKyBhZ2VudE5hbWUgKyBcInxcIiArIHNlbmRlckEgKyBcInxcIiArIG0pXG4gICAgICAgICAgICAgICAgY29uc3QgcGtleUEgPSBhd2FpdCBmZXRjaEtleShzZW5kZXJBLCB0cnVlLCB0cnVlKVxuICAgICAgICAgICAgICAgIGNvbnN0IGFja1BheWxvYWQgPSBKU09OLnN0cmluZ2lmeShbXCIyXCIsIGFnZW50TmFtZSwgbSwgc2lnQl0pXG4gICAgICAgICAgICAgICAgY29uc3QgZW5jcnlwdGVkQWNrID0gYXdhaXQgaHlicmlkRW5jcnlwdChwa2V5QSwgYWNrUGF5bG9hZClcbiAgICAgICAgICAgICAgICBhd2FpdCBzZW5kTWVzc2FnZShhZ2VudE5hbWUsIHNlbmRlckEsIGVuY3J5cHRlZEFjaylcblxuICAgICAgICAgICAgICAgIGxvY2FsU3RvcmFnZS5zZXRJdGVtKGFja0tleSwgXCIxXCIpIC8vIE1hcnF1ZSBsZSBtZXNzYWdlIGNvbW1lIHRyYWl0XHUwMEU5IChQcm9wIDgpXG4gICAgICAgICAgICAgICAgYnJlYWtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgY2FzZSAyOiB7IC8vIFJcdTAwRTljZXB0aW9uIGQndW4gYWNjdXNcdTAwRTkgKEFDSylcbiAgICAgICAgICAgICAgICBjb25zdCBzZW5kZXJCID0gZGF0YUFycmF5WzFdXG4gICAgICAgICAgICAgICAgY29uc3QgbSA9IGRhdGFBcnJheVsyXVxuICAgICAgICAgICAgICAgIGNvbnN0IHNpZyA9IGRhdGFBcnJheVszXVxuXG4gICAgICAgICAgICAgICAgLy8gRW1wXHUwMEVBY2hlIGQnYWZmaWNoZXIgcGx1c2lldXJzIGZvaXMgbGUgbVx1MDBFQW1lIEFDSyAoUHJvcCA4KVxuICAgICAgICAgICAgICAgIGNvbnN0IGFja0Rpc3BsYXlLZXkgPSBgYWNrZGlzcGxheV8ke2FnZW50TmFtZX1fJHtzZW5kZXJCfV8ke219YFxuICAgICAgICAgICAgICAgIGlmIChsb2NhbFN0b3JhZ2UuZ2V0SXRlbShhY2tEaXNwbGF5S2V5KSkgcmV0dXJuXG5cbiAgICAgICAgICAgICAgICAvLyBWXHUwMEU5cmlmaWNhdGlvbiBzaWduYXR1cmUgQUNLIDogVmFsaWRlIFByb3AgMyAoQm9iIGEgYmllbiByZVx1MDBFN3UgTEUgbWVzc2FnZSlcbiAgICAgICAgICAgICAgICBjb25zdCBwdWJLZXlCID0gYXdhaXQgZmV0Y2hLZXkoc2VuZGVyQiwgdHJ1ZSwgZmFsc2UpXG4gICAgICAgICAgICAgICAgY29uc3QgdmFsaWQgPSBhd2FpdCB2ZXJpZnlTaWduYXR1cmVXaXRoUHVibGljS2V5KHB1YktleUIsIFwiMnxcIiArIHNlbmRlckIgKyBcInxcIiArIGFnZW50TmFtZSArIFwifFwiICsgbSwgc2lnKVxuICAgICAgICAgICAgICAgIGlmICghdmFsaWQpIHJldHVyblxuXG4gICAgICAgICAgICAgICAgYXdhaXQgZGlzcGxheUFuZFNhdmUoYFtBQ0tdICR7c2VuZGVyQn0gYSBiaWVuIHJlY3UgOiBcIiR7bX1cImApXG4gICAgICAgICAgICAgICAgbG9jYWxTdG9yYWdlLnNldEl0ZW0oYWNrRGlzcGxheUtleSwgXCIxXCIpXG4gICAgICAgICAgICAgICAgYnJlYWtcbiAgICAgICAgICAgIH1cblxuICAgICAgICAgICAgZGVmYXVsdDpcbiAgICAgICAgICAgICAgICByZXR1cm5cbiAgICAgICAgfVxuICAgIH0gY2F0Y2ggKGVycm9yKSB7XG4gICAgICAgIGNvbnNvbGUubG9nKFwiRXJyZXVyIGFuYWx5c2VNZXNzYWdlIDogXCIsIGVycm9yKVxuICAgIH1cbn0iXSwKICAibWFwcGluZ3MiOiAiO0FBMkNBLGVBQXNCLCtCQUErQixZQUF3QztBQUN6RixNQUFJO0FBQ0EsVUFBTSxpQkFBOEIsMEJBQTBCLFVBQVU7QUFDeEUsVUFBTSxNQUFpQixNQUFNLE9BQU8sT0FBTyxPQUFPO0FBQUEsTUFDOUM7QUFBQSxNQUNBO0FBQUEsTUFDQTtBQUFBLFFBQ0ksTUFBTTtBQUFBLFFBQ04sTUFBTTtBQUFBLE1BQ1Y7QUFBQSxNQUNBO0FBQUEsTUFDQSxDQUFDLFNBQVM7QUFBQSxJQUNkO0FBQ0EsV0FBTztBQUFBLEVBQ1gsU0FBUyxHQUFHO0FBQ1IsUUFBSSxhQUFhLGNBQWM7QUFBRSxjQUFRLElBQUksMkRBQTJEO0FBQUEsSUFBRSxXQUNqRyxhQUFhLG9CQUFvQjtBQUFFLGNBQVEsSUFBSSwyREFBMkQ7QUFBQSxJQUFFLE9BQ2hIO0FBQUUsY0FBUSxJQUFJLENBQUM7QUFBQSxJQUFFO0FBQ3RCLFVBQU07QUFBQSxFQUNWO0FBQ0o7QUFNQSxlQUFzQiw4QkFBOEIsWUFBd0M7QUFDeEYs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
