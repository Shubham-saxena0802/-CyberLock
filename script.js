"use strict";

const passwordInput = document.getElementById("password");
const togglePasswordButton = document.getElementById("togglePassword");
const strengthText = document.getElementById("strengthText");
const strengthScore = document.getElementById("strengthScore");
const strengthBar = document.getElementById("strengthBar");
const strengthProgress = document.getElementById("strengthProgress");
const analyzerMessage = document.getElementById("analyzerMessage");

const requirementLabels = {
    length: "At least 12 characters",
    uppercase: "Uppercase letter (A–Z)",
    lowercase: "Lowercase letter (a–z)",
    number: "Number (0–9)",
    symbol: "Special character (!@#$)"
};

function analyzePassword() {
    const password = passwordInput.value;

    const checks = {
        length: password.length >= 12,
        uppercase: /[A-Z]/.test(password),
        lowercase: /[a-z]/.test(password),
        number: /[0-9]/.test(password),
        symbol: /[^A-Za-z0-9]/.test(password)
    };

    let score = 0;

    Object.entries(checks).forEach(([key, passed]) => {
        const item = document.getElementById(key);
        if (passed) score += 1;

        item.classList.toggle("valid", passed);
        item.textContent = `${passed ? "✓" : "✗"} ${requirementLabels[key]}`;
    });

    strengthScore.textContent = `${score} / 5`;
    strengthProgress.setAttribute("aria-valuenow", String(score));
    strengthBar.style.width = `${score * 20}%`;

    if (password.length === 0) {
        strengthText.textContent = "Not tested";
        strengthBar.style.width = "0%";
        strengthBar.style.background = "#29394f";
        analyzerMessage.textContent = "Enter a password to begin analysis.";
        analyzerMessage.className = "feedback neutral";
        return;
    }

    if (score <= 2) {
        strengthText.textContent = "Weak";
        strengthBar.style.background = "#fb7185";
        analyzerMessage.textContent = "Try meeting more of the requirements and avoid predictable patterns.";
        analyzerMessage.className = "feedback error";
    } else if (score <= 4) {
        strengthText.textContent = "Moderate";
        strengthBar.style.background = "#fbbf24";
        analyzerMessage.textContent = "Some requirements are met. Review the remaining items.";
        analyzerMessage.className = "feedback neutral";
    } else {
        strengthText.textContent = "All checks passed";
        strengthBar.style.background = "#2dd4bf";
        analyzerMessage.textContent = "All five basic checks are satisfied. This score does not guarantee password security.";
        analyzerMessage.className = "feedback success";
    }
}

function togglePasswordVisibility() {
    const isHidden = passwordInput.type === "password";
    passwordInput.type = isHidden ? "text" : "password";
    togglePasswordButton.textContent = isHidden ? "Hide" : "Show";
    togglePasswordButton.setAttribute("aria-pressed", String(isHidden));
}

const lengthRange = document.getElementById("lengthRange");
const lengthValue = document.getElementById("lengthValue");

function updateLength() {
    lengthValue.textContent = lengthRange.value;
}

function secureRandomInt(max) {
    if (!Number.isSafeInteger(max) || max < 1 || max > 0x100000000) {
        throw new Error("Invalid random range.");
    }

    const range = 0x100000000;
    const limit = range - (range % max);
    const values = new Uint32Array(1);

    do {
        crypto.getRandomValues(values);
    } while (values[0] >= limit);

    return values[0] % max;
}

function secureShuffle(items) {
    for (let i = items.length - 1; i > 0; i -= 1) {
        const j = secureRandomInt(i + 1);
        [items[i], items[j]] = [items[j], items[i]];
    }
    return items;
}

function generatePassword() {
    const output = document.getElementById("generatedPassword");
    const message = document.getElementById("generatorMessage");
    const length = Number(lengthRange.value);

    const availableSets = [];

    if (document.getElementById("includeUpper").checked) {
        availableSets.push("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
    }
    if (document.getElementById("includeLower").checked) {
        availableSets.push("abcdefghijklmnopqrstuvwxyz");
    }
    if (document.getElementById("includeNumbers").checked) {
        availableSets.push("0123456789");
    }
    if (document.getElementById("includeSymbols").checked) {
        availableSets.push("!@#$%^&*()_+-=[]{}");
    }

    if (availableSets.length === 0) {
        output.value = "";
        message.textContent = "Select at least one character type.";
        message.className = "feedback error";
        return;
    }

    if (!window.crypto || typeof window.crypto.getRandomValues !== "function") {
        output.value = "";
        message.textContent = "Secure random generation is unavailable in this browser context. Use localhost or HTTPS.";
        message.className = "feedback error";
        return;
    }

    try {
        const characters = availableSets.map(set => set[secureRandomInt(set.length)]);
        const allCharacters = availableSets.join("");

        while (characters.length < length) {
            characters.push(allCharacters[secureRandomInt(allCharacters.length)]);
        }

        output.value = secureShuffle(characters).join("");
        message.textContent = "Password generated using the browser's cryptographic random generator.";
        message.className = "feedback success";
    } catch (error) {
        output.value = "";
        message.textContent = "Could not generate a password: " + error.message;
        message.className = "feedback error";
    }
}

async function copyGeneratedPassword() {
    const output = document.getElementById("generatedPassword");
    const message = document.getElementById("generatorMessage");

    if (!output.value) {
        message.textContent = "Generate a password first.";
        message.className = "feedback error";
        return;
    }

    try {
        await navigator.clipboard.writeText(output.value);
        message.textContent = "Generated password copied to clipboard.";
        message.className = "feedback success";
    } catch (error) {
        output.focus();
        output.select();
        message.textContent = "Automatic copy was blocked. Press Ctrl+C to copy the selected password.";
        message.className = "feedback neutral";
    }
}

passwordInput.addEventListener("input", analyzePassword);
togglePasswordButton.addEventListener("click", togglePasswordVisibility);
lengthRange.addEventListener("input", updateLength);
document.getElementById("generateButton").addEventListener("click", generatePassword);
document.getElementById("copyButton").addEventListener("click", copyGeneratedPassword);


updateLength();
analyzePassword();


const PBKDF2_ITERATIONS = 310000;

function bytesToBase64Url(bytes) {
    let binary = "";

    for (const byte of bytes) {
        binary += String.fromCharCode(byte);
    }

    return btoa(binary)
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/g, "");
}

function base64UrlToBytes(value) {
    if (typeof value !== "string" ||
        !/^[A-Za-z0-9_-]+$/.test(value)) {
        throw new Error("Invalid encrypted package encoding.");
    }

    let base64 = value
        .replace(/-/g, "+")
        .replace(/_/g, "/");

    base64 += "=".repeat((4 - base64.length % 4) % 4);

    const binary = atob(base64);

    return Uint8Array.from(
        binary,
        character => character.charCodeAt(0)
    );
}

async function deriveEncryptionKey(password, salt) {
    const encoder = new TextEncoder();

    const passwordKey = await crypto.subtle.importKey(
        "raw",
        encoder.encode(password),
        "PBKDF2",
        false,
        ["deriveKey"]
    );

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },
        passwordKey,
        {
            name: "AES-GCM",
            length: 256
        },
        false,
        ["encrypt", "decrypt"]
    );
}


async function encryptMessage() {
    const message = document.getElementById("plainMessage").value;
    const password = document.getElementById("encryptPassword").value;

    const output = document.getElementById("encryptedPackage");
    const status = document.getElementById("encryptMessage");

    output.value = "";

    if (!message.trim() || !password) {
        status.textContent = "Enter both a message and password.";
        status.className = "feedback error";
        return;
    }

    if (!window.crypto || !crypto.subtle) {
        status.textContent = "Web Crypto is unavailable. Use localhost or HTTPS.";
        status.className = "feedback error";
        return;
    }

    try {
        status.textContent = "Encrypting message...";
        status.className = "feedback neutral";

        const salt = crypto.getRandomValues(new Uint8Array(16));
        const iv = crypto.getRandomValues(new Uint8Array(12));

        const key = await deriveEncryptionKey(password, salt);

        const encoder = new TextEncoder();
        const messageBytes = encoder.encode(message);

        const encryptedData = await crypto.subtle.encrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            messageBytes
        );

        const packageData = {
            version: 1,
            algorithm: "AES-256-GCM",
            kdf: "PBKDF2-SHA256",
            iterations: PBKDF2_ITERATIONS,
            salt: bytesToBase64Url(salt),
            iv: bytesToBase64Url(iv),
            ciphertext: bytesToBase64Url(
                new Uint8Array(encryptedData)
            )
        };

        const packageText = bytesToBase64Url(
            encoder.encode(JSON.stringify(packageData))
        );

        output.value = packageText;

        status.textContent = "Saving encrypted message to server...";
        status.className = "feedback neutral";

      
        const response = await fetch("http://localhost:8080/api/messages", {
            method: "POST",
            headers: {
                "Content-Type": "text/plain"
            },
            body: packageText
        });

        const result = await response.json();

        if (!response.ok || !result.message_id) {
            throw new Error("Server could not save the encrypted message.");
        }

        status.textContent =
            "Encrypted and saved! Message ID: " + result.message_id;

        status.className = "feedback success";

    } catch (error) {
        console.error("Encryption or server save failed:", error);

        status.textContent =
            "Encryption may be complete, but saving failed. " +
            "Your encrypted package is still available above.";

        status.className = "feedback error";
    }
}



async function decryptMessage() {
    const packageText = document.getElementById("packageInput").value.trim();
    const password = document.getElementById("decryptPassword").value;

    const output = document.getElementById("decryptedMessage");
    const status = document.getElementById("decryptMessage");

    output.value = "";

    if (!packageText || !password) {
        status.textContent = "Enter the encrypted package and password.";
        status.className = "feedback error";
        return;
    }

    if (!window.crypto || !crypto.subtle) {
        status.textContent = "Web Crypto is unavailable. Use localhost or HTTPS.";
        status.className = "feedback error";
        return;
    }

    try {
        status.textContent = "Decrypting message...";
        status.className = "feedback neutral";

   
        const packageBytes = base64UrlToBytes(packageText);

        const packageJSON = new TextDecoder().decode(packageBytes);
        const packageData = JSON.parse(packageJSON);

     
        if (
            packageData.version !== 1 ||
            packageData.algorithm !== "AES-256-GCM" ||
            packageData.kdf !== "PBKDF2-SHA256" ||
            packageData.iterations !== PBKDF2_ITERATIONS
        ) {
            throw new Error("Unsupported or invalid package.");
        }

        const salt = base64UrlToBytes(packageData.salt);
        const iv = base64UrlToBytes(packageData.iv);
        const ciphertext = base64UrlToBytes(packageData.ciphertext);

        if (
            salt.length !== 16 ||
            iv.length !== 12 ||
            ciphertext.length < 16
        ) {
            throw new Error("Invalid encrypted package.");
        }

      
        const key = await deriveEncryptionKey(password, salt);

        const decryptedData = await crypto.subtle.decrypt(
            {
                name: "AES-GCM",
                iv: iv
            },
            key,
            ciphertext
        );

   
        const decoder = new TextDecoder("utf-8", {
            fatal: true
        });

        output.value = decoder.decode(decryptedData);

        status.textContent = "Message decrypted successfully!";
        status.className = "feedback success";

    } catch (error) {
        console.error("Decryption failed:", error);

        output.value = "";

        status.textContent =
            "Decryption failed. Check the password and encrypted package.";

        status.className = "feedback error";
    }
}
async function retrieveSavedMessage() {
    const messageID = document.getElementById("messageIDInput").value.trim();
    const status = document.getElementById("retrieveMessage");
    const packageInput = document.getElementById("packageInput");

    if (!messageID) {
        status.textContent = "Please enter a Message ID.";
        status.className = "feedback error";
        return;
    }

    try {
        status.textContent = "Retrieving message from server...";
        status.className = "feedback neutral";

        const response = await fetch(
            "http://localhost:8080/api/messages/" + encodeURIComponent(messageID)
        );

        if (!response.ok) {
            if (response.status === 404) {
                throw new Error("Message not found. Check your Message ID.");
            }

            throw new Error("Server error while retrieving the message.");
        }

        const encryptedPackage = await response.text();

       
        packageInput.value = encryptedPackage;

        status.textContent =
            "Message retrieved successfully! You can now decrypt it.";

        status.className = "feedback success";

    } catch (error) {
        console.error("Message retrieval failed:", error);

        status.textContent = error.message ||
            "Could not retrieve the message from the server.";

        status.className = "feedback error";
    }
}
async function deleteSavedMessage() {
    const messageID = document.getElementById("deleteMessageIDInput").value.trim();
    const status = document.getElementById("deleteMessage");

    if (!messageID) {
        status.textContent = "Please enter a Message ID.";
        status.className = "feedback error";
        return;
    }

    if (!confirm("Are you sure you want to permanently delete this saved message?")) {
        return;
    }

    try {
        status.textContent = "Deleting saved message...";
        status.className = "feedback neutral";

        const response = await fetch(
            "http://localhost:8080/api/messages/" + encodeURIComponent(messageID),
            { method: "DELETE" }
        );

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.message || "Message deletion failed.");
        }

        status.textContent = "Saved message deleted successfully!";
        status.className = "feedback success";

    } catch (error) {
        console.error("Message deletion failed:", error);
        status.textContent = error.message || "Could not delete the saved message.";
        status.className = "feedback error";
    }
}


document.querySelectorAll(".message-tool-button").forEach(button => {
    button.addEventListener("click", () => {

        const targetView = button.dataset.messageView;

        document.querySelectorAll(".message-view").forEach(view => {
            view.hidden = view.id !== targetView;
        });

        document.querySelectorAll(".message-tool-button").forEach(item => {
            item.classList.toggle("active", item === button);
        });

    });
});     

document.getElementById("encryptButton")
    .addEventListener("click", encryptMessage);

document.getElementById("decryptButton")
    .addEventListener("click", decryptMessage);

    document.getElementById("retrieveButton")
    .addEventListener("click", retrieveSavedMessage);

    document.getElementById("deleteButton")
    .addEventListener("click", deleteSavedMessage);

    // Password Security tool selector

document.querySelectorAll(".password-tool-button").forEach(button => {
    button.addEventListener("click", () => {
        const targetView = button.dataset.passwordView;

        document.querySelectorAll(".password-tool-view").forEach(view => {
            view.hidden = view.id !== targetView;
        });

        document.querySelectorAll(".password-tool-button").forEach(item => {
            item.classList.toggle("active", item === button);
        });
    });
});