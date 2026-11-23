
function processNoEncryption(message) {
    const plaintext = String(message ?? '');

    return {
        method: 'no-encryption',
        encrypted: false,
        originalMessage: plaintext,
        receivedMessage: plaintext,
        integrityVerified: null
    };
}

module.exports = {
    processNoEncryption
};
