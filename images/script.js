const crypto = require('crypto');
const axios = require('axios');

const passwordLength = 16;

function secureRandomNumber(max) {
    const randomBytes = crypto.randomBytes(4);
    const randomInt = randomBytes.readUInt32LE(0);
    return Math.floor(randomInt / 0x100000000 * max);
}

async function isPasswordBreached(password) {
    const sha1Hash = crypto.createHash('sha1').update(password).digest('hex').toUpperCase();
    const prefix = sha1Hash.substring(0, 5);
    const suffix = sha1Hash.substring(5);

    try {
        const response = await axios.get(`https://api.pwnedpasswords.com/range/${prefix}`);
        const hashList = response.data.split('\n');
        for (const hash of hashList) {
            const [hashSuffix, count] = hash.split(':');
            if (hashSuffix === suffix) {
                return parseInt(count);
            }
        }
    } catch (error) {
        console.error("Failed to check against breached passwords:", error);
    }

    return 0; // Password is not breached
}

function generateSecurePassword(length = 12) {
    const characters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=[]{}|;':,.<>?/~";
    let password;
    do {
        password = '';
        for (let i = 0; i < length; i++) {
            const randomIndex = secureRandomNumber(characters.length);
            password += characters.charAt(randomIndex);
        }
    } while (isPasswordBreached(password) > 0);

    return password;
}

const display = document.querySelector('.display');
const passwordInput = document.getElementById('password');
const generateButton = document.getElementById('generateButton');
const copyButton = document.getElementById('copyButton');

generateButton.addEventListener('click', () => {
    const generatedPassword = generateSecurePassword(passwordLength);
    passwordInput.value = generatedPassword;
    display.textContent = 'Your Password Has Been Generated';
});

copyButton.addEventListener('click', () => {
    if (passwordInput.value) {
        passwordInput.select();
        document.execCommand('copy');
        display.textContent = 'Password Copied to Clipboard';
    }
});