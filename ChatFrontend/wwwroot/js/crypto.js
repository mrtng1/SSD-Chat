async function encryptMessage(message, keyBase64, ivBase64) {
    const key = await window.crypto.subtle.importKey(
        "raw",
        base64ToArrayBuffer(keyBase64),
        { name: "AES-GCM" },
        false,
        ["encrypt"]
    );

    const iv = base64ToArrayBuffer(ivBase64);
    const encodedMessage = new TextEncoder().encode(message);

    const encrypted = await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: iv },
        key,
        encodedMessage
    );

    return arrayBufferToBase64(encrypted);
}

// Decrypt with AES-GCM
async function decryptMessage(encryptedBase64, keyBase64, ivBase64) {
    try {
        // Convert Base64 strings to ArrayBuffers
        const keyBuffer = base64ToArrayBuffer(keyBase64);
        const iv = base64ToArrayBuffer(ivBase64);
        const encryptedData = base64ToArrayBuffer(encryptedBase64);

        // Import the key for AES-GCM decryption
        const key = await window.crypto.subtle.importKey(
            "raw",
            keyBuffer,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
        );

        // Decrypt the message
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            encryptedData
        );

        const decryptedText = new TextDecoder().decode(decrypted);
        return decryptedText;
    } catch (error) {
        console.error("Decryption error:", error);
        throw error;
    }
}


// Helper functions
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