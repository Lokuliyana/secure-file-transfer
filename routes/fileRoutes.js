const express = require('express');
const router = express.Router();
const File = require('../models/File');
const User = require('../models/User');
const crypto = require('crypto');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const verifyToken = require('../middleware/verifyToken');
const mongoose = require("mongoose");
const Notification = require('../models/Notifications'); // Assuming this is the correct path
const { segmentFile, reassembleFile } = require('../utils/fileUtils');

function getMimeType(ext) {
    const mimeMap = {
      '.pdf': 'application/pdf',
      '.txt': 'text/plain',
      '.jpg': 'image/jpeg',
      '.jpeg': 'image/jpeg',
      '.png': 'image/png',
      '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      '.xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      '.zip': 'application/zip',
      '.mp4': 'video/mp4'
      // ➕ Add more extensions as needed
    };
    return mimeMap[ext] || 'application/octet-stream'; // fallback
}

  
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

function encryptChunk(chunk, aesKey, iv) {
  const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
  let encrypted = cipher.update(chunk);
  encrypted = Buffer.concat([encrypted, cipher.final()]);
  return encrypted.toString('base64'); // Store as string
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

function decryptDataWithAes(encryptedDataBuffer, keyBuffer, ivBuffer) {
    const decipher = crypto.createDecipheriv('aes-256-cbc', keyBuffer, ivBuffer);
    let decrypted = decipher.update(encryptedDataBuffer);
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted;
}

// Upload file with hashing, segmentation, and encryption
router.post('/upload', verifyToken, upload.single('file'), async (req, res) => {
  try {
    const uploader = await User.findById(req.user._id);
    if (!uploader) return res.status(400).send("Uploader not found.");

    const fileBuffer = fs.readFileSync(req.file.path);
    const fileHash = calculateFileHash(fileBuffer);
    const visibility = req.body.visibility;
    const fileSize = req.file.size;

    const aesKey = crypto.randomBytes(32);
    const iv = crypto.randomBytes(16);

    const segments = segmentFile(fileBuffer, 1024 * 256); // 256 KB chunks
    const encryptedChunks = segments.map(chunk => encryptChunk(chunk, aesKey, iv));

    let encryptedAesKey = null;
    const encryptedKeysForRecipients = {};

    if (visibility === "public") {
      encryptedAesKey = aesKey.toString('base64');
    } else {
      if (!uploader.publicKey) return res.status(400).send("Public key not found for uploader.");
      encryptedAesKey = encryptKeyWithPublicKey(aesKey, uploader.publicKey).toString('base64');

      const recipientIds = visibility === "friends" ? uploader.friends : uploader.closeFriends;
      const recipients = await User.find({ _id: { $in: recipientIds } }).select('publicKey');

      recipients.forEach(recipient => {
        if (recipient.publicKey) {
          encryptedKeysForRecipients[recipient._id] = encryptKeyWithPublicKey(aesKey, recipient.publicKey).toString('base64');
        }
      });
    }

    const newFile = new File({
      owner: uploader._id,
      name: req.file.originalname,
      size: fileSize,
      fileUrl: req.file.path,
      fileHash,
      encryptedAesKey,
      iv: iv.toString('base64'),
      fileChunks: encryptedChunks,
      visibility,
      encryptedKeysForRecipients,
      expiresAt: parseExpiration(req.body.expiration),
    });

    await newFile.save();

    await new Notification({
      userId: req.user._id,
      type: 'File Uploaded',
      title: 'File Upload Successful',
      message: `Your file ${req.file.originalname} has been securely uploaded.`,
    }).save();

    res.status(201).json({ message: "✅ Chunked file uploaded successfully." });
  } catch (err) {
    console.error("Chunked Upload Error:", err);
    res.status(500).json({ message: "Failed to upload file", error: err.toString() });
  }
});

  function parseExpiration(expStr) {
    const now = Date.now();
    if (expStr === "never") return null;
  
    const multipliers = {
      h: 1000 * 60 * 60,
      d: 1000 * 60 * 60 * 24,
      m: 1000 * 60 * 60 * 24 * 30,
      y: 1000 * 60 * 60 * 24 * 365,
    };
  
    const unit = expStr.slice(-1);
    const value = parseInt(expStr.slice(0, -1), 10);
  
    if (!multipliers[unit] || isNaN(value)) return null; // fallback
  
    return new Date(now + value * multipliers[unit]);
  }
  
  const decryptChunk = (chunkBase64, key, iv) => {
    const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv);
    let decrypted = decipher.update(Buffer.from(chunkBase64, 'base64'));
    decrypted = Buffer.concat([decrypted, decipher.final()]);
    return decrypted;
  };
    
  router.post('/download/:fileId', verifyToken, async (req, res) => {
    try {
      const file = await File.findById(req.params.fileId).populate('owner');
      if (!file) return res.status(404).send("File not found");
  
      const userId = req.user._id.toString();
      const hasAccess =
        file.visibility === 'public' ||
        file.owner._id.toString() === userId ||
        file.sharedWith.map(id => id.toString()).includes(userId) ||
        file.encryptedKeysForRecipients[userId];
  
      if (!hasAccess) return res.status(403).send("Access denied");
  
      const privateKey = req.body.privateKey;
      if (!privateKey) return res.status(400).send("Private key required");
  
      let aesKey;
      if (file.visibility === "public") {
        aesKey = Buffer.from(file.encryptedAesKey, 'base64');
      } else {
        const encryptedKey = file.owner._id.toString() === userId
          ? file.encryptedAesKey
          : file.encryptedKeysForRecipients[userId];
  
        aesKey = crypto.privateDecrypt({
          key: privateKey,
          padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: "sha256"
        }, Buffer.from(encryptedKey, 'base64'));
      }
  
      const iv = Buffer.from(file.iv, 'base64');
      const decryptedChunks = file.fileChunks.map(chunk => decryptChunk(chunk, aesKey, iv));
      const fullData = Buffer.concat(decryptedChunks);
  
      const recalculatedHash = calculateFileHash(fullData);
      if (recalculatedHash !== file.fileHash) {
        console.warn(`⚠️ File integrity compromised for ${file.name}`);
        return res.status(403).send("File integrity compromised.");
      }
  
      const ext = path.extname(file.name).toLowerCase();
      const mimeType = getMimeType(ext);
  
      res.setHeader("Content-Disposition", `attachment; filename="${file.name}"`);
      res.setHeader("Content-Type", mimeType);
      res.send(fullData);
  
      await User.findByIdAndUpdate(req.user._id, {
        $addToSet: { downloadedFiles: file._id }
      });
  
      await new Notification({
        userId: file.owner._id,
        type: 'File Downloaded',
        title: 'File Downloaded',
        message: `Your file ${file.name} was downloaded by ${req.user.username}.`,
      }).save();
  
    } catch (err) {
      console.error("Download Error:", err);
      res.status(500).json({ message: "Download failed", error: err.toString() });
    }
  });


// File integrity check before download or on system check
router.get('/verify-file/:fileId', verifyToken, async (req, res) => {
  try {
      const file = await File.findById(req.params.fileId);
      if (!file) return res.status(404).send('File not found.');

      const fileData = fs.readFileSync(file.fileUrl);
      const recalculatedHash = calculateFileHash(fileData);

      if (recalculatedHash !== file.fileHash) {
          console.warn(`⚠️ Potential Integrity Issue Detected for file ID: ${file._id}`);

          // Notifying the file owner and users who have access
          const usersToNotify = [file.owner].concat(file.sharedWith);
          const uniqueUsers = [...new Set(usersToNotify)]; // Ensure unique users

          uniqueUsers.forEach(async (userId) => {
              const newNotification = new Notification({
                  userId: userId,
                  type: 'File Hash Altered',
                  title: 'File Integrity Alert',
                  message: `A potential unauthorized modification has been detected in the file: ${file.name}. Please verify the file's integrity.`,
              });
              await newNotification.save();
          });

          return res.status(403).send("File integrity compromised, all stakeholders have been notified.");
      }

      res.send("File integrity verified.");
  } catch (error) {
      console.error("Integrity Check Error:", error);
      res.status(500).json({ message: "Error checking file integrity", error: error.toString() });
  }
});


// GET /api/user/storage-usage
router.get("/storage-usage", verifyToken, async (req, res) => {
    try {
      const userId = req.user._id;
  
      const uploadedFiles = await File.find({ owner: userId });
      const downloadedUser = await User.findById(userId).populate("downloadedFiles");
  
      const uploadedSize = uploadedFiles.reduce((sum, file) => sum + (file.size || 0), 0);
      const downloadedSize = downloadedUser.downloadedFiles.reduce((sum, file) => sum + (file.size || 0), 0);
  
      const totalUsed = uploadedSize + downloadedSize;
      const totalLimit = 5 * 1024 * 1024; // 50GB in bytes

      if (totalUsed > totalLimit * 0.9) { // If usage exceeds 90% of the limit
        const newNotification = new Notification({
            userId: req.user._id,
            type: 'Storage Capacity',
            title: 'Storage Capacity Warning',
            message: `You are using ${totalUsed} bytes of your ${totalLimit} byte limit. Consider upgrading your storage plan.`,
        });
        await newNotification.save();
    }
    
    // Returning the storage usage info to the user
    res.json({
        uploadedSize,
        downloadedSize,
        totalUsed,
        totalLimit
    });
    } catch (error) {
      console.error("❌ Storage calc error:", error);
      res.status(500).json({ message: "Failed to calculate storage usage" });
    }
  });
  

router.get('/files', verifyToken, async (req, res) => {
    try {
      const requestingUserId = req.user._id.toString();
      const targetUserId = req.query.userId;
  
      if (!targetUserId) {
        return res.status(400).json({ error: "User ID is required" });
      }
  
      const targetUser = await User.findById(targetUserId);
      if (!targetUser) {
        return res.status(404).json({ message: "User not found" });
      }
  
      const isOwner = targetUserId === requestingUserId;
      const isFriend = targetUser.friends.includes(requestingUserId);
      const isCloseFriend = targetUser.closeFriends.includes(requestingUserId);
  
      let queryConditions = [];
  
      if (isOwner) {
        // Owner can see all their files
        queryConditions.push({ owner: targetUserId });
      } else {
        // Public files are visible to everyone
        queryConditions.push({ owner: targetUserId, visibility: "public" });
  
        // Explicitly shared files
        queryConditions.push({ owner: targetUserId, sharedWith: requestingUserId });
  
        // Files where AES key is encrypted for this user
        queryConditions.push({ owner: targetUserId, [`encryptedKeysForRecipients.${requestingUserId}`]: { $exists: true } });
  
        // Friends/Close Friends — but only if AES key is included
        if (isFriend) {
          queryConditions.push({
            owner: targetUserId,
            visibility: "friends",
            [`encryptedKeysForRecipients.${requestingUserId}`]: { $exists: true }
          });
        }
  
        if (isCloseFriend) {
          queryConditions.push({
            owner: targetUserId,
            visibility: "closeFriends",
            [`encryptedKeysForRecipients.${requestingUserId}`]: { $exists: true }
          });
        }
      }
  
      const files = await File.find({ $or: queryConditions });
  
      // ✅ Remove duplicates
      const uniqueFiles = [...new Map(files.map(file => [file._id.toString(), file])).values()];
  
      // Return only metadata (not encrypted data or keys)
      res.json(uniqueFiles.map(file => ({
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
    
  // GET /api/file/downloaded
router.get('/downloaded', verifyToken, async (req, res) => {
    try {
      const user = await User.findById(req.user._id).populate('downloadedFiles');
      if (!user) return res.status(404).json({ message: "User not found" });
  
      const files = user.downloadedFiles.map(file => ({
        _id: file._id,
        name: file.name,
        fileHash: file.fileHash,
        visibility: file.visibility,
        expiresAt: file.expiresAt
      }));
  
      res.json(files);
    } catch (error) {
      console.error("Fetch downloaded files error:", error);
      res.status(500).json({ message: "Failed to fetch downloaded files" });
    }
  });
  
// POST /api/file/re-encrypt-for-friend/:friendId
router.post('/re-encrypt-for-friend/:friendId', verifyToken, async (req, res) => {
    try {
      const currentUser = await User.findById(req.user._id);
      const friendId = req.params.friendId;
      const privateKey = req.body.privateKey;
  
      if (!currentUser.friends.includes(friendId)) {
        console.warn("⚠️ Friend not found in currentUser.friends — skipping check for immediate re-encryption.");
      }      
  
      const friend = await User.findById(friendId);
      if (!friend || !friend.publicKey) {
        return res.status(404).json({ message: "Friend not found or missing public key." });
      }
  
      const files = await File.find({
        owner: currentUser._id,
        visibility: { $in: ['friends', 'closeFriends'] },
        expiresAt: { $gte: new Date() }
      });
  
      let updatedCount = 0;
      for (const file of files) {
        if (!file.encryptedKeysForRecipients[friendId]) {
          const aesKeyBuffer = crypto.privateDecrypt(
            {
              key: privateKey,
              padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
              oaepHash: "sha256",
            },
            Buffer.from(file.encryptedAesKey, 'base64')
          );
  
          const encryptedKey = encryptKeyWithPublicKey(aesKeyBuffer, friend.publicKey);
          file.encryptedKeysForRecipients[friendId.toString()] = encryptedKey.toString('base64');
          await file.save();
          updatedCount++;
          console.log(`🔐 Re-encrypted '${file.name}' for ${friend.username}`);
        }
      }
  
      res.json({ message: `Re-encrypted AES keys for ${updatedCount} file(s).` });
    } catch (error) {
      console.error("Re-encryption error:", error);
      res.status(500).json({ message: "Error re-encrypting AES keys", error: error.toString() });
    }
  });

  // PUT /api/file/soft-delete/:fileId
router.put("/soft-delete/:fileId", verifyToken, async (req, res) => {
    try {
      const fileId = req.params.fileId;
      const userId = req.user._id.toString();
  
      const file = await File.findById(fileId);
      if (!file) return res.status(404).json({ message: "File not found." });
  
      const updates = {};
  
      // If the user is the owner
      if (file.owner.toString() === userId) {
        updates.$addToSet = { ...(updates.$addToSet || {}), removedUploads: fileId };
      }
  
      // If the user has it in their downloads
      updates.$pull = { ...(updates.$pull || {}), downloadedFiles: fileId };
      updates.$addToSet = { ...(updates.$addToSet || {}), removedDownloads: fileId };
  
      await User.findByIdAndUpdate(userId, updates);
  
      res.json({ message: "File moved to trash (soft deleted)." });
  
    } catch (error) {
      console.error("❌ Unified Soft Delete Error:", error);
      res.status(500).json({ message: "Failed to soft delete", error: error.toString() });
    }
  });


// ♻️ Restore deleted file (either upload or download)
router.put("/restore/:fileId", verifyToken, async (req, res) => {
    try {
      const fileId = req.params.fileId;
      const userId = req.user._id.toString();
  
      const user = await User.findById(userId);
      if (!user) return res.status(404).json({ message: "User not found." });
  
      await User.findByIdAndUpdate(userId, {
        $pull: {
          removedUploads: fileId,
          removedDownloads: fileId
        },
        $addToSet: {
          downloadedFiles: fileId // Optional: re-add to downloads if restored from trash
        }
      });
  
      res.json({ message: "File restored successfully." });
    } catch (error) {
      console.error("♻️ Restore Error:", error);
      res.status(500).json({ message: "Failed to restore file.", error: error.toString() });
    }
  });
  
  // ❌ Permanently delete or clean up file
router.delete("/permanent-delete/:fileId", verifyToken, async (req, res) => {
    try {
      const fileId = req.params.fileId;
      const userId = req.user._id.toString();
  
      const file = await File.findById(fileId);
      if (!file) {
        return res.status(404).json({ message: "File not found." });
      }
  
      // If the user is the owner, allow full delete
      if (file.owner.toString() === userId) {
        // Delete from disk
        if (fs.existsSync(file.fileUrl)) {
          fs.unlinkSync(file.fileUrl);
        }
  
        // Delete file from DB
        await File.findByIdAndDelete(fileId);
  
        // Remove file from all user arrays
        await User.updateMany({}, {
          $pull: {
            downloadedFiles: fileId,
            removedDownloads: fileId,
            removedUploads: fileId
          }
        });
  
        return res.json({ message: "File permanently deleted." });
      }
  
      // 🚫 Not owner – just clean up from this user's account
      await User.findByIdAndUpdate(userId, {
        $pull: {
          downloadedFiles: fileId,
          removedDownloads: fileId
        }
      });
  
      return res.json({ message: "File removed from your trash." });
  
    } catch (error) {
      console.error("❌ Permanent Delete Error:", error);
      return res.status(500).json({ message: "Failed to delete permanently.", error: error.toString() });
    }
  });
  
  // ✅ Get all soft-deleted (trashed) files for current user
router.get("/trash", verifyToken, async (req, res) => {
    try {
      const userId = req.user._id.toString();
  
      const user = await User.findById(userId)
        .populate("removedUploads")
        .populate("removedDownloads");
  
      if (!user) return res.status(404).json({ message: "User not found" });
  
      // Combine and de-duplicate the removed files
      const allRemovedFiles = [
        ...(user.removedUploads || []),
        ...(user.removedDownloads || [])
      ];
  
      const uniqueFilesMap = new Map();
      allRemovedFiles.forEach(file => {
        if (!uniqueFilesMap.has(file._id.toString())) {
          uniqueFilesMap.set(file._id.toString(), file);
        }
      });
  
      const files = Array.from(uniqueFilesMap.values());
  
      const simplifiedFiles = files.map(file => ({
        _id: file._id,
        name: file.name,
        fileHash: file.fileHash,
        owner: file.owner,
        visibility: file.visibility,
        expiresAt: file.expiresAt
      }));
  
      res.json(simplifiedFiles);
    } catch (error) {
      console.error("🗑️ Fetch Trash Error:", error);
      res.status(500).json({ message: "Failed to fetch trashed files", error: error.toString() });
    }
  });
  
  
  
module.exports = router;
