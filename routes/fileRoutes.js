const express = require('express');
const router = express.Router();
const File = require('../models/File');
const User = require('../models/User');
const crypto = require('crypto');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const verifyToken = require('../middleware/verifyToken');

// Multer setup for file uploads
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadPath = './uploads/';
        fs.mkdirSync(uploadPath, { recursive: true }); // Ensure the directory exists
        cb(null, uploadPath);
    },
    filename: function (req, file, cb) {
        const filename = Date.now() + path.extname(file.originalname); // Unique filename
        cb(null, filename);
    }
});

const upload = multer({ storage: storage });

// Function to calculate SHA-256 hash for file integrity verification
function calculateFileHash(data) {
    return crypto.createHash('sha256').update(data).digest('hex');
}

// Encrypt AES key with RSA public key
function encryptKeyWithPublicKey(aesKey, publicKey) {
    try {
        return crypto.publicEncrypt(
            {
                key: publicKey,
                padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
                oaepHash: "sha256",
            },
            aesKey
        );
    } catch (error) {
        console.error("RSA Encryption Error:", error.message);
        throw new Error('RSA Encryption Failed');
    }
}

// AES encryption of file data
function encryptFileData(data) {
    const aesKey = crypto.randomBytes(32); // AES-256 key
    const iv = crypto.randomBytes(16); // Initialization vector
    const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
    let encrypted = cipher.update(data);
    encrypted = Buffer.concat([encrypted, cipher.final()]);
    return { encryptedData: encrypted, iv, aesKey };
}

// Upload file with hashing and encryption
router.post('/upload', verifyToken, upload.single('file'), async (req, res) => {
  try {
      // Fetch uploader's public key
      const uploader = await User.findById(req.user._id);
      if (!uploader || !uploader.publicKey) {
          return res.status(400).send("Public key not found for this user.");
      }

      const fileData = fs.readFileSync(req.file.path);
      const { encryptedData, iv, aesKey } = encryptFileData(fileData);
      const fileHash = calculateFileHash(fileData);

      // Encrypt AES key with uploader's public key
      const encryptedAesKey = encryptKeyWithPublicKey(aesKey, uploader.publicKey);

      // ✅ Directly use the visibility string from frontend (fix the error)
      let visibility = req.body.visibility;

      // Encrypt AES key for friends and close friends
      const encryptedKeysForRecipients = {};
      if (visibility === "friends" || visibility === "closeFriends") {
          const recipients = visibility === "friends"
              ? await User.find({ _id: { $in: uploader.friends } }).select('publicKey')
              : await User.find({ _id: { $in: uploader.closeFriends } }).select('publicKey');

          recipients.forEach(recipient => {
              encryptedKeysForRecipients[recipient._id] = encryptKeyWithPublicKey(aesKey, recipient.publicKey).toString('base64');
          });
      }

      // Create the file document
      const newFile = new File({
          owner: req.user._id,
          name: req.file.originalname,
          fileUrl: req.file.path,
          fileHash: fileHash,  
          encryptedAesKey: encryptedAesKey.toString('base64'),
          iv: iv.toString('base64'),
          fileData: encryptedData.toString('base64'),
          visibility: visibility,  // ✅ Store as a plain string
          encryptedKeysForRecipients: encryptedKeysForRecipients,
          expiresAt: new Date(Date.now() + 1000 * 60 * 60 * 24 * parseInt(req.body.expiration, 10))
      });

      await newFile.save();
      res.status(201).json({ message: "File uploaded successfully." });

  } catch (error) {
      console.error("Upload Error:", error);
      res.status(500).json({ message: "Error uploading file", error: error.toString() });
  }
});

router.post('/download/:fileId', verifyToken, async (req, res) => {
  try {
      const file = await File.findById(req.params.fileId).populate('owner');
      if (!file) return res.status(404).send('File not found.');

      // Validate if user has permission to access the file
      if (
          file.visibility !== 'public' &&
          !file.owner._id.equals(req.user._id) &&
          !file.sharedWith.includes(req.user._id)
      ) {
          return res.status(403).send('Access denied.');
      }

      const privateKey = req.body.privateKey;
      if (!privateKey) return res.status(400).send("Private key is required for decryption.");

      // Decrypt AES key with user's private key
      const encryptedAesKey = req.user._id.equals(file.owner._id)
          ? file.encryptedAesKey
          : file.encryptedKeysForRecipients[req.user._id];

      if (!encryptedAesKey) {
          return res.status(403).send("You do not have access to decrypt this file.");
      }

      const aesKey = crypto.privateDecrypt(
          {
              key: privateKey,
              padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
              oaepHash: "sha256",
          },
          Buffer.from(encryptedAesKey, 'base64')
      );

      // Decrypt file
      const decryptedData = decryptDataWithAes(
          Buffer.from(file.fileData, 'base64'),
          aesKey,
          Buffer.from(file.iv, 'base64')
      );

      // Recalculate hash for integrity check
      const recalculatedHash = calculateFileHash(decryptedData);
      if (recalculatedHash !== file.fileHash) {
          console.warn(`File integrity compromised for ${file.name}`);
          return res.status(403).send("File integrity compromised! Please contact the sender.");
      }

      res.send(decryptedData);
  } catch (error) {
      console.error("Download Error:", error);
      res.status(500).json({ message: "Error downloading file", error: error.toString() });
  }
});

router.get('/files', verifyToken, async (req, res) => {
  try {
      const requestingUserId = req.user._id; // Logged-in user's ID
      const targetUserId = req.query.userId; // The friend's user ID

      if (!targetUserId) {
          return res.status(400).json({ error: "User ID is required" });
      }

      // Find the target user
      const targetUser = await User.findById(targetUserId);
      if (!targetUser) {
          return res.status(404).json({ message: "User not found" });
      }

      // Check if the requesting user is a friend or close friend
      const isFriend = targetUser.friends.includes(requestingUserId);
      const isCloseFriend = targetUser.closeFriends.includes(requestingUserId);
      const isOwner = targetUserId.toString() === requestingUserId.toString(); // Self-check

      // Fetch files with proper permissions
      let files;
      if (isOwner) {
          // Fetch all files the owner has uploaded
          files = await File.find({ owner: targetUserId });
      } else {
          // Fetch files that are public, shared, or accessible via encryption
          files = await File.find({
              owner: targetUserId,
              $or: [
                  { visibility: "public" }, // Public files
                  { sharedWith: requestingUserId }, // Files explicitly shared
                  { "encryptedKeysForRecipients": { $exists: true, $ne: {} } } // Files with encrypted access
              ]
          });

          // If the user is a friend, allow them to access "friends" visibility files
          if (isFriend) {
              files = files.concat(await File.find({ owner: targetUserId, visibility: "friends" }));
          }

          // If the user is a close friend, also fetch "closeFriends" visibility files
          if (isCloseFriend) {
              files = files.concat(await File.find({ owner: targetUserId, visibility: "closeFriends" }));
          }
      }

      // Remove duplicates
      files = [...new Map(files.map(file => [file._id.toString(), file])).values()];

      res.json(files.map(file => ({
          _id: file._id,
          name: file.name,
          owner: file.owner,
          fileHash: file.fileHash,
          visibility: file.visibility,
          expiresAt: file.expiresAt,
      })));
  } catch (error) {
      console.error("Files fetch error:", error.message);
      res.status(500).json({ error: 'Error fetching files' });
  }
});

module.exports = router;
