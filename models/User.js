const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    mobileNumber: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    profilePicture: { type: String, default: null },  // URL to the profile picture
    publicKey: { type: String, required: true }, // Store the user's RSA public key
    createdAt: { type: Date, default: Date.now },
    friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    friendRequests: [{
        userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
        createdAt: { type: Date, default: Date.now }
    }],
    closeFriends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    otp: { type: String },
    otpExpiry: { type: Date }
});

module.exports = mongoose.model('User', userSchema);
