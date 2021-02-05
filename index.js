// Nodejs encryption with CTR
const crypto = require('crypto');

const IV_LENGTH = 16; // For AES, this is always 16, checked with php


function encrypt(text, password,aes_method) {
    if (process.versions.openssl <= '1.0.1f') {
        throw new Error('OpenSSL Version too old, vulnerability to Heartbleed')
    }

    let iv = crypto.randomBytes(IV_LENGTH);
    let cipher = crypto.createCipheriv(aes_method, password, iv);
    let encrypted = cipher.update(text);
    encrypted = Buffer.concat([encrypted, cipher.final()]);

    return Buffer.concat([iv, encrypted]).toString('base64');
}

function decrypt(text) {
    let textParts = text.split(':');
    let iv = new Buffer(textParts.shift(), 'hex');
    let encryptedText = new Buffer(textParts.join(':'), 'hex');
    let decipher = crypto.createDecipheriv('aes-256-cbc', new Buffer($password), iv);
    let decrypted = decipher.update(encryptedText);

    decrypted = Buffer.concat([decrypted, decipher.final()]);

    return decrypted.toString();
}



module.exports.templateTags = [{
    name: 'cryptIT',
    displayName: 'cryptIT',
    description: 'Encrypt value using Crypt',
    args: [
        {
            displayName: 'Public key',
            type: 'string',
            placeholder: 'LS0tLS1......'
        },
        {
            displayName: 'AES method',
            type: 'enum',
            options: crypto.getCiphers().map((el)=>{
                return {
                    displayName: el,
                    value: el
                };

            })
        },
        {
            displayName: 'Secret Text to encrypt',
            type: 'string',
            placeholder: 'Secret Text'
        }
    ],
    run (_, key, aes_method, value) {
        key = key || '';
        value = value || '';
        aes_method = aes_method || 'aes-256-cbc';
        return encrypt(new Array(32).join().replace(/(.|$)/g, function(){return ((Math.random()*36)|0).toString(36);})+value, key,aes_method);
    }
}];
