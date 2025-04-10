// Encrypt
async function encryptMessage(message, keyBase64, ivBase64) {
    // Convert Base64 to ArrayBuffer for key and IV
    const keyBuffer = base64ToArrayBuffer(keyBase64);
    const iv = base64ToArrayBuffer(ivBase64);
    try {
        // Import the encryption key
        const key = await window.crypto.subtle.importKey(
            "raw",
            keyBuffer,
            { name: "AES-GCM" },
            false,
            ["encrypt"]
        );
        // Encoding the message using TextEncoder
        const encodedMessage = new TextEncoder().encode(message);
        // Encrypt the encoded message
        const encrypted = await window.crypto.subtle.encrypt(
            { name: "AES-GCM", iv: iv },
            key,
            encodedMessage
        );
        // Convert the encrypted ArrayBuffer to Base64
        const base64Encrypted = arrayBufferToBase64(encrypted);
        return base64Encrypted;
    } catch (error) {
        console.error("Error during encryption:", error);
        throw error;
    }
}

async function decryptMessage(encryptedBase64, keyBase64, ivBase64) {
    try {
        const keyBuffer = base64ToArrayBuffer(keyBase64);
        const iv = base64ToArrayBuffer(ivBase64);
        const encryptedData = base64ToArrayBuffer(encryptedBase64);

        const key = await window.crypto.subtle.importKey(
            "raw",
            keyBuffer,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            encryptedData
        );
        
        try {
            const decryptedText = new TextDecoder().decode(decrypted);

            try {
                const parsedJson = JSON.parse(decryptedText);
                return parsedJson;
            } catch (jsonError) {
                console.error("Error parsing JSON:", jsonError);
                return decryptedText; 
            }
        } catch (error) {
            console.error("Error decoding text:", error);
            return decrypted;
        }
    } catch (error) {
        console.error("Decryption error:", error);
        if (error instanceof DOMException) {
            console.error("Decryption failed -> DOMException.");
        }
        throw error;
    }
}

//helper functions
function base64ToArrayBuffer(base64) {
    const binaryString = window.atob(base64);
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    return window.btoa(String.fromCharCode(...bytes));
}


/*

 key pairs
 
*/
// Generate key pair
window.generateKeyPair = async () => {
    try {
        const keyPair = await window.crypto.subtle.generateKey(
            {
                name: "ECDH",
                namedCurve: "P-256",
            },
            true,
            ["deriveKey"]
        );

        const publicKey = await window.crypto.subtle.exportKey(
            "spki", // Export the public key in SPKI format
            keyPair.publicKey
        );

        return {
            publicKey: arrayBufferToBase64(publicKey),
            privateKey: await window.crypto.subtle.exportKey(
                "jwk", // Export the private key in JWK format
                keyPair.privateKey
            )
        };
    } catch (error) {
        console.error("Key generation failed:", error);
        throw error;
    }
};


function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    return btoa(String.fromCharCode(...bytes));
}


async function deriveSharedSecret(peerPublicKeyBase64, myPrivateKeyJwk) {
    try {
        // Convert peer's public key from Base64 to ArrayBuffer
        const peerKeyBuffer = base64ToArrayBuffer(peerPublicKeyBase64);

        // Import peer's public key (SPKI format)
        const peerPublicKey = await crypto.subtle.importKey(
            "raw",
            peerKeyBuffer,
            { name: "ECDH", namedCurve: "P-256" },
            true,
            []
        );

        // Import user's private key (JWK format)
        const myPrivateKey = await crypto.subtle.importKey(
            "jwk",
            JSON.parse(myPrivateKeyJwk),
            { name: "ECDH", namedCurve: "P-256" },
            false,
            ["deriveBits"] // Allow deriving bits
        );

        // 1. Derive raw ECDH shared secret (bits)
        const rawSharedBits = await crypto.subtle.deriveBits(
            { name: "ECDH", public: peerPublicKey },
            myPrivateKey,
            256 // Matches P-256 curve size
        );

        // 2. Use HKDF to derive AES key from the raw bits
        const aesKey = await crypto.subtle.deriveKey(
            {
                name: "HKDF",
                salt: new Uint8Array(),
                info: new TextEncoder().encode("AES-GCM-256"),
                hash: "SHA-256",
            },
            await crypto.subtle.importKey(
                "raw",
                rawSharedBits,
                { name: "HKDF" },
                false,
                ["deriveKey"]
            ),
            { name: "AES-GCM", length: 256 },
            true,
            ["encrypt", "decrypt"]
        );

        // Export the AES key as Base64
        const exportedKey = await crypto.subtle.exportKey("raw", aesKey);
        return arrayBufferToBase64(exportedKey);
    } catch (error) {
        console.error("Error deriving shared secret:", error);
        throw error;
    }
}


window.importPrivateKey = async function (jwkJson) {
    const jwk = JSON.parse(jwkJson);

    const importedKey = await window.crypto.subtle.importKey(
        "jwk",
        jwk,
        { name: "ECDH", namedCurve: "P-256" },
        true,
        ["deriveKey", "deriveBits"]
    );
    
    return importedKey;
};
