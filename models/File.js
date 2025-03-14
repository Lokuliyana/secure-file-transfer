const mongoose = require('mongoose');

const fileSchema = new mongoose.Schema({
    owner: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
    name: { type: String, required: true },
    fileUrl: { type: String, required: true },
    fileHash: { type: String, required: true },
    visibility: {
        type: String,
        enum: ['private', 'friends', 'closeFriends', 'public'],
        default: 'private'
    },
    sharedWith: [{
        userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        accessLevel: { type: String, enum: ['read', 'write'], default: 'read' }
    }],
    createdAt: { type: Date, default: Date.now },
    expiresAt: { type: Date, index: { expires: '1d' } }  // Files expire 1 day after `expiresAt`
});

module.exports = mongoose.model('File', fileSchema);
