const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    mobileNumber: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    profilePicture: { type: String, default: null },
    publicKey: { type: String, required: true },
    createdAt: { type: Date, default: Date.now },

    downloadedFiles: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: "File"
    }],
    removedUploads: [{ type: mongoose.Schema.Types.ObjectId, ref: 'File' }],
    removedDownloads: [{ type: mongoose.Schema.Types.ObjectId, ref: 'File' }],

    friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    friendRequests: [{
      userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
      createdAt: { type: Date, default: Date.now }
    }],
    closeFriends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
  
    otp: { type: String },
    otpExpiry: { type: Date },
  
    // ✅ Add this field for privacy
    privacySetting: {
      type: String,
      enum: ['public', 'private'],
      default: 'public'
    }
  });
  
module.exports = mongoose.model('User', userSchema);
