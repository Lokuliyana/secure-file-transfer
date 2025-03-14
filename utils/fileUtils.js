const fs = require('fs');
const crypto = require('crypto');

const algorithm = 'aes-256-cbc';
const password = 'password'; // This should be replaced with a more secure key management system
const key = crypto.scryptSync(password, 'salt', 32);
const iv = crypto.randomBytes(16); // IV should be unique for each encryption but can be static for simplicity here

// Function to segment a file buffer into chunks
function segmentFile(buffer, segmentSize) {
    const segments = [];
    for (let start = 0; start < buffer.length; start += segmentSize) {
        const end = Math.min(start + segmentSize, buffer.length);
        const segment = buffer.slice(start, end);
        segments.push(segment);
    }
    return segments;
}

// Function to reassemble file segments into a single buffer
function reassembleFile(segments) {
    return Buffer.concat(segments);
}

// Encrypts a buffer
function encrypt(buffer) {
    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const part1 = cipher.update(buffer);
    const part2 = cipher.final();
    return Buffer.concat([part1, part2]);
}

// Decrypts a buffer
function decrypt(buffer) {
    const decipher = crypto.createDecipheriv(algorithm, key, iv);
    const part1 = decipher.update(buffer);
    const part2 = decipher.final();
    return Buffer.concat([part1, part2]);
}

module.exports = { segmentFile, reassembleFile, encrypt, decrypt };
