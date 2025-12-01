const mongoose = require('mongoose');

const fileSchema = new mongoose.Schema({
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: { type: String, required: true },
    fileUrl: { type: String, required: true },
    fileHash: { type: String, required: true }, // ✅ File hash for integrity checking
    encryptedAesKey: { type: String, required: true }, // Encrypted AES Key
    iv: { type: String, required: true }, // AES Initialization Vector
    fileData: { type: String}, // Encrypted file content
    // models/File.js
    fileChunks: [{ type: String }], // base64-encoded encrypted chunks
    size: { type: Number, required: true },  // in bytes
    visibility: {
        type: String,
        enum: ['private', 'friends', 'closeFriends', 'public'],
        default: 'private'
    },
    encryptedKeysForRecipients: { type: Object, default: {} }, // ✅ Stores encrypted AES keys for recipients
    sharedWith: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    expiresAt: { type: Date },
    createdAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('File', fileSchema);
