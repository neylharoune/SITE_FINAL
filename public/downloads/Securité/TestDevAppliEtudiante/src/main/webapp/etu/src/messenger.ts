// To detect if we can use window.crypto.subtle
if (!window.isSecureContext) alert("Not secure context!")

// -- DO NOT MODIFY THIS PART! --------------------------------------------------------------------
// Message for user name
class CasUserName {
    constructor(public username: string) { }
}

// Requesting keys
class KeyRequest {
    constructor(public ownerOfTheKey: string, public publicKey: boolean, public encryption: boolean) { }
}

class KeyResult {
    constructor(public success: boolean, public key: string, public errorMessage: string) { }
}

// The message format
class ExtMessage {
    constructor(public sender: string, public receiver: string, public content: string) { }
}

// Sending a message Result format
class SendResult {
    constructor(public success: boolean, public errorMessage: string) { }
}

// Message for requiring history
class HistoryRequest {
    constructor(public agentName: string, public index: number) { }
}

// Result of history request
class HistoryAnswer {
    constructor(public success: boolean,
        public failureMessage: string,
        public index: number,
        public allMessages: ExtMessage[]) { }
}

let globalUserName = ""

// WARNING!
// It is necessary to pass the URL parameters, called `urlParams` below, to 
// every GET/POST query you send to the server. This is mandatory to have the possibility 
// to use alternative identities like alice@univ-rennes.fr, bob@univ-rennes.fr, etc. 
// for debugging purposes.

// Do not modify!
async function fetchCasName(): Promise<string> {
    const urlParams = new URLSearchParams(window.location.search);
    const namerequest = await fetch("/getuser?" + urlParams, {
        method: "GET",
        headers: {
            "Content-type": "application/json; charset=UTF-8"
        }
    });
    if (!namerequest.ok) {
        throw new Error(`Error! status: ${namerequest.status}`)
    }
    const nameResult = (await namerequest.json()) as CasUserName
    console.log("Fetched CAS name= " + nameResult.username)
    return nameResult.username
}

// Do not modify!
async function setCasName() {
    globalUserName = await fetchCasName()
    // We replace the name of the user of the application as the default name
    // In the window
    userButtonLabel.textContent = globalUserName
}

// Do not modify!
setCasName()

// WARNING!
// It is necessary to provide the name of the owner of the application. Each pair of student are
// the owner of their application. Other students may use it but they are only users and not owners.
// Messages sent to the server are separated w.r.t. the name of the application (i.e. the name of their owners).
// The name of the owners is the name of the folder of the application where the web pages of the application are stored. 
// E.g, for teachers' application this name is "ens"

// Do not modify!
function getOwnerName(): string {
    const path = window.location.pathname
    const name = path.split("/", 2)[1]
    return name
}

// Do not modify!
let ownerName = getOwnerName()

// WARNING!
// It is necessary to pass the URL parameters, called `urlParams` below, to 
// every GET/POST query you send to the server. This is mandatory to have the possibility 
// to use alternative identities like alice@univ-rennes.fr, bob@univ-rennes.fr, etc. 
// for debugging purposes.

// Do not modify
async function fetchKey(user: string, publicKey: boolean, encryption: boolean): Promise<CryptoKey> {
    // Getting the public/private key of user.
    // For public key the boolean 'publicKey' is true.
    // For private key the boolean 'publicKey' is false.
    // If the key is used for encryption/decryption then the boolean 'encryption' is true.
    // If the key is used for signature/signature verification then the boolean is false.
    const keyRequestMessage =
        new KeyRequest(user, publicKey, encryption)
    // For CAS authentication we need to add the authentication ticket
    // It is contained in urlParams
    const urlParams = new URLSearchParams(window.location.search);
    // For getting a key we do not need the ownerName param
    // Because keys are independant of the applications
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
    const keyResult = (await keyrequest.json()) as KeyResult;
    if (!keyResult.success) alert(keyResult.errorMessage)
    else {
        if (publicKey && encryption) return await stringToPublicKeyForEncryption(keyResult.key)
        else if (!publicKey && encryption) return await stringToPrivateKeyForEncryption(keyResult.key)
        else if (publicKey && !encryption) return await stringToPublicKeyForSignature(keyResult.key)
        else if (!publicKey && !encryption) return await stringToPrivateKeyForSignature(keyResult.key)
    }
}

// WARNING!
// It is necessary to pass the URL parameters, called `urlParams` below, to 
// every GET/POST query you send to the server. This is mandatory to have the possibility 
// to use alternative identities like alice@univ-rennes.fr, bob@univ-rennes.fr, etc. 
// for debugging purposes.
// 
// We also need to provide the ownerName

// Do not modify!
async function sendMessage(agentName: string, receiverName: string, messageContent: string): Promise<SendResult> {
    try {
        let messageToSend =
            new ExtMessage(agentName, receiverName, messageContent)
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
        // Dealing with the answer of the message server
        console.log(`Sent message from ${agentName} to ${receiverName}: ${messageContent}`)
        return (await request.json()) as SendResult
    }
    catch (error) {
        if (error instanceof Error) {
            console.log('error message: ', error.message);
            return new SendResult(false, error.message)
        } else {
            console.log('unexpected error: ', error);
            return new SendResult(false, 'An unexpected error occurred')
        }
    }
}

// -----------------------------------------------------------------------------------------------
// -----------------------------------------------------------------------------------------------
// You can modify the code below

import {
    stringToPrivateKeyForEncryption, stringToPublicKeyForEncryption,
    stringToPrivateKeyForSignature,
    stringToPublicKeyForSignature,
    encryptWithPublicKey,
    decryptWithPrivateKey,
    signWithPrivateKey,
    verifySignatureWithPublicKey,
    encryptWithSymmetricKey,
    decryptWithSymmetricKey,
    generateSymetricKey,
    symmetricKeyToString,
    stringToSymmetricKey,
    privateKeyToString,
    hash,
} from './libCrypto'

const userButtonLabel = document.getElementById("user-name") as HTMLLabelElement
const sendButton = document.getElementById("send-button") as HTMLButtonElement
const receiver = document.getElementById("receiver") as HTMLInputElement
const messageG = document.getElementById("message") as HTMLInputElement
const received_messages = document.getElementById("exchanged-messages") as HTMLLabelElement

// Affiche le message en texte brut (Sécurité)
function addingReceivedMessage(message: string) {
    const p = document.createElement('p');
    p.textContent = message;
    received_messages.append(p);
}

// chiffrement hybride, assure prop 1 (secret) et prop 7  
async function hybridEncrypt(rsaPublicKey: CryptoKey, message: string): Promise<string> {
    const aesKey = await generateSymetricKey() 
    const [cyphered, iv] = await encryptWithSymmetricKey(aesKey, message)
    const aesKeyStr = await symmetricKeyToString(aesKey)
    const encryptedAesKey = await encryptWithPublicKey(rsaPublicKey, aesKeyStr) // RSA protège la clé AES
    return JSON.stringify({ rsakey: encryptedAesKey, cyphered, iv })
}

async function hybridDecrypt(rsaPrivateKey: CryptoKey, encryptedPayload: string): Promise<string> {
    const { rsakey, cyphered, iv } = JSON.parse(encryptedPayload)
    const aesKeyStr = await decryptWithPrivateKey(rsaPrivateKey, rsakey)
    const aesKey = await stringToSymmetricKey(aesKeyStr)
    return await decryptWithSymmetricKey(aesKey, cyphered, iv)
}

//  historique local, assure prop 5 et prop 6 (Stockage chiffré) 
let localStorageAesKey: CryptoKey | null = null

async function getLocalAesKey(): Promise<CryptoKey> {
    if (localStorageAesKey) return localStorageAesKey
    const privKeyRSA = await fetchKey(globalUserName, false, true)
    const privKeyStr = await privateKeyToString(privKeyRSA)
    const hashOfKey = await hash(privKeyStr) // clé AES locale dérivée du secret RSA de l'utilisateur
    const rawBytes = atob(hashOfKey).slice(0, 32)
    const rawArray = new Uint8Array(rawBytes.length)
    for (let i = 0; i < rawBytes.length; i++) rawArray[i] = rawBytes.charCodeAt(i)
    localStorageAesKey = await window.crypto.subtle.importKey(
        "raw", rawArray, "AES-GCM", false, ["encrypt", "decrypt"]
    )
    return localStorageAesKey
}

function localStorageKeyName(): string {
    return `history_${globalUserName}`
}

async function readLocalHistory(): Promise<string[]> {
    try {
        const raw = localStorage.getItem(localStorageKeyName())
        if (!raw) return []
        const { cyphered, iv } = JSON.parse(raw)
        const aesKey = await getLocalAesKey()
        const decrypted = await decryptWithSymmetricKey(aesKey, cyphered, iv)
        return JSON.parse(decrypted) as string[]
    } catch (e) {
        console.log("Erreur lecture historique : ", e)
        return []
    }
}

async function saveToLocalHistory(entry: string) {
    try {
        const existing = await readLocalHistory()
        existing.push(entry)
        const aesKey = await getLocalAesKey()
        const [cyphered, iv] = await encryptWithSymmetricKey(aesKey, JSON.stringify(existing))
        localStorage.setItem(localStorageKeyName(), JSON.stringify({ cyphered, iv }))
    } catch (e) {
        console.log("Erreur sauvegarde historique : ", e)
    }
}

async function loadLocalHistory() {
    const entries = await readLocalHistory()
    for (const entry of entries) {
        addingReceivedMessage(entry)
    }
}

async function displayAndSave(text: string) {
    addingReceivedMessage(text) // prop 0 
    await saveToLocalHistory(text)
}

function loadLastIndex(): number {
    return parseInt(localStorage.getItem(`lastIndex_${globalUserName}`) || "0")
}

function saveLastIndex(index: number) {
    localStorage.setItem(`lastIndex_${globalUserName}`, index.toString())
}

let lastIndexInHistory = 0

// Initialisation, charge l'historique et lance la prop 4 
async function init() {
    while (globalUserName === "") {
        await new Promise(resolve => setTimeout(resolve, 50))
    }
    await loadLocalHistory()
    lastIndexInHistory = loadLastIndex()
    setInterval(refresh, 2000)
}

init()

// récupération périodique des messages sur le serveur (prop 4)
async function refresh() {
    try {
        const user = globalUserName
        const historyRequest = new HistoryRequest(user, lastIndexInHistory)
        const urlParams = new URLSearchParams(window.location.search);
        const request = await fetch("/history/" + ownerName + "?" + urlParams, {
            method: "POST",
            body: JSON.stringify(historyRequest),
            headers: { "Content-type": "application/json; charset=UTF-8" }
        });
        if (!request.ok) throw new Error(`Error! status: ${request.status}`);
        const result = (await request.json()) as HistoryAnswer
        if (!result.success) { alert(result.failureMessage) }
        else {
            lastIndexInHistory = result.index
            saveLastIndex(result.index)
            for (const m of result.allMessages) {
                await analyseMessage(m)
            }
        }
    } catch (error) {
        console.log('Erreur refresh: ', error);
    }
}

// bouton envoyer, Étape 1 du protocole
sendButton.onclick = async function () {
    const agentName = globalUserName;
    const receiverName = receiver.value.trim();
    const messageContent = messageG.value.trim();
    if (!receiverName || !messageContent) return;

    try {
        console.log(`Etape 1 : ${agentName} envoie un message a ${receiverName}`)

        const privKeyA = await fetchKey(agentName, false, false)
        // Signature, Assure prop 2  :)
        const signature = await signWithPrivateKey(privKeyA, "1|" + agentName + "|" + receiverName + "|" + messageContent)
        
        const pkeyB = await fetchKey(receiverName, true, true)
        const payload = JSON.stringify(["1", agentName, messageContent, signature])
        const encryptedMessage = await hybridEncrypt(pkeyB, payload)

        const sendResult = await sendMessage(agentName, receiverName, encryptedMessage)
        if (!sendResult.success) return

        await displayAndSave(`${agentName} -> ${receiverName} : ${messageContent}`)
        messageG.value = ""
    } catch (error) {
        console.log("Erreur envoi : ", error)
    }
}

//  analyse des messages, gestion des étapes 1 et 2 
async function analyseMessage(message: ExtMessage): Promise<void> {
    const agentName = globalUserName;

    try {
        if (message.receiver !== agentName) return;

        const privKey = await fetchKey(agentName, false, true)
        const messageInClear = await hybridDecrypt(privKey, message.content)
        const dataArray = JSON.parse(messageInClear) as string[]
        const index = parseInt(dataArray[0], 10)

        switch (index) {

            case 1: { // réception d'un nouveau message
                const senderA = dataArray[1]
                const m = dataArray[2]
                const sig = dataArray[3]

                if (senderA === agentName) return

                // anti-rejeu,assure prop 8 (un message n'est traité qu'une fois !)
                const ackKey = `ack_${agentName}_${senderA}_${m}`
                if (localStorage.getItem(ackKey)) return

                // Vérification signature,valide prop 2 (identité de l'expéditeur)
                const pubKeyA = await fetchKey(senderA, true, false)
                const valid = await verifySignatureWithPublicKey(pubKeyA, "1|" + senderA + "|" + agentName + "|" + m, sig)
                if (!valid) {
                    console.log(`Signature invalide, message rejeté.`);
                    return
                }

                await displayAndSave(`${senderA} -> ${agentName} : ${m}`)

                //  etape 2, envoi de l'accusé (prop 3 confirmation de réception) 
                const privKeyB = await fetchKey(agentName, false, false)
                const sigB = await signWithPrivateKey(privKeyB, "2|" + agentName + "|" + senderA + "|" + m)
                const pkeyA = await fetchKey(senderA, true, true)
                const ackPayload = JSON.stringify(["2", agentName, m, sigB])
                const encryptedAck = await hybridEncrypt(pkeyA, ackPayload)
                await sendMessage(agentName, senderA, encryptedAck)

                localStorage.setItem(ackKey, "1") // marque le message comme traité (Prop 8)
                break
            }

            case 2: { // reception d'un accusé (ACK)
                const senderB = dataArray[1]
                const m = dataArray[2]
                const sig = dataArray[3]

                // empeche d'afficher plusieurs fois le même ACK (prop 8)
                const ackDisplayKey = `ackdisplay_${agentName}_${senderB}_${m}`
                if (localStorage.getItem(ackDisplayKey)) return

                // vérification signature ACK, valideprop 3 (bob a bien reçu LE message)
                const pubKeyB = await fetchKey(senderB, true, false)
                const valid = await verifySignatureWithPublicKey(pubKeyB, "2|" + senderB + "|" + agentName + "|" + m, sig)
                if (!valid) return

                await displayAndSave(`[ACK] ${senderB} a bien recu : "${m}"`)
                localStorage.setItem(ackDisplayKey, "1")
                break
            }

            default:
                return
        }
    } catch (error) {
        console.log("Erreur analyseMessage : ", error)
    }
}