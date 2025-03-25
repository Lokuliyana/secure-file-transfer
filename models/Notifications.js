const mongoose = require('mongoose');

// Define the schema for notifications
const notificationSchema = new mongoose.Schema({
    userId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User',
        required: true
    },
    type: {
        type: String,
        enum: ['Friend Request', 'Accept Friend Request', 'File Uploaded','File Downloaded', 'File Expiry', 'Security Alert', 'File Hash Altered', 'Unauthorized Login Attempt', 'Two-Factor Authentication', 'Storage Capacity', 'Privacy Settings Change'],
        required: true
    },
    timestamp: {
        type: Date,
        default: Date.now
    },
    status: {
        type: String,
        enum: ['Read', 'Unread'],
        default: 'Unread'
    },
    title: {
        type: String,
        required: true
    },
    message: {
        type: String,
        required: true
    },
    associatedId: {
        type: mongoose.Schema.Types.ObjectId,
        ref: 'File',
        required: false
    }
});

// Compile and export the model
module.exports = mongoose.model('Notification', notificationSchema);
