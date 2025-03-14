const express = require('express');
const router = express.Router();
const File = require('../models/File');
const verifyToken = require('../middleware/verifyToken');
const logger = require('../utils/logger'); // Assuming logger is set up in the 'utils' directory
const { segmentFile, reassembleFile, encrypt, decrypt } = require('../utils/fileUtils'); // Import utilities
const crypto = require('crypto');

// Function to calculate SHA-256 hash
function calculateHash(buffer) {
    return crypto.createHash('sha256').update(buffer).digest('hex');
}

// Endpoint to upload files
router.post('/upload', verifyToken, async (req, res) => {
    try {
        const { name, fileContent, visibility } = req.body; // Assume fileContent is base64 encoded
        const buffer = Buffer.from(fileContent, 'base64'); // Convert from base64 to buffer

        // Calculate SHA-256 hash of the original file content
        const fileHash = calculateHash(buffer);

        // Segment the file into smaller chunks, encrypt each segment
        const segments = segmentFile(buffer, 1024 * 1024); // Segment the file into 1MB chunks
        const encryptedSegments = segments.map(segment => encrypt(segment));

        // The storage or handling of encrypted segments needs to be implemented based on your storage solution
        // For now, let's assume you serialize them or store their paths

        const file = new File({
            owner: req.user._id,
            name,
            fileUrl: 'path/to/storage', // Placeholder, adjust according to your file storage handling
            fileHash,
            visibility
        });

        await file.save();
        logger.info(`File Upload: User ${req.user._id} uploaded ${name}`);
        res.status(201).send('File uploaded successfully');
    } catch (error) {
        logger.error("Upload Error: " + error.message);
        res.status(500).json({ message: "Error uploading file", error });
    }
});

// Endpoint to download files and verify integrity
router.get('/file/:fileId', verifyToken, async (req, res) => {
    try {
        const file = await File.findById(req.params.fileId);
        if (!file) {
            return res.status(404).send('File not found.');
        }

        // Assuming you retrieve the encrypted segments and decrypt them
        const encryptedSegments = retrieveEncryptedSegments(file.fileUrl); // Implement this based on your storage
        const segments = encryptedSegments.map(segment => decrypt(segment));
        const buffer = reassembleFile(segments);
        const currentHash = calculateHash(buffer);

        if (currentHash !== file.fileHash) {
            return res.status(403).send('File integrity check failed.');
        }

        // Send the decrypted file content
        res.json({ file: buffer.toString('base64') }); // Send as base64 for example
    } catch (error) {
        logger.error("Download Error: " + error.message);
        res.status(500).json({ message: "Error accessing file", error });
    }
});

// Endpoint to update file visibility
router.patch('/file/:fileId/visibility', verifyToken, async (req, res) => {
    try {
        const file = await File.findOneAndUpdate(
            { _id: req.params.fileId, owner: req.user._id },
            { visibility: req.body.visibility },
            { new: true }
        );
        res.json(file);
    } catch (error) {
        res.status(500).json({ message: "Error updating file visibility", error });
    }
});

// Endpoint to access files based on visibility settings
router.get('/file/:fileId', verifyToken, async (req, res) => {
    try {
        const file = await File.findById(req.params.fileId).populate('owner');
        const owner = file.owner;
        const isFriend = owner.friends.includes(req.user._id);
        const isCloseFriend = owner.closeFriends.includes(req.user._id);

        if (file.visibility === 'private' && file.owner._id.toString() !== req.user._id.toString()) {
            return res.status(403).send('Access denied.');
        } else if (file.visibility === 'friends' && !isFriend) {
            return res.status(403).send('Access denied.');
        } else if (file.visibility === 'closeFriends' && !isCloseFriend) {
            return res.status(403).send('Access denied.');
        }

        res.json(file);
    } catch (error) {
        res.status(500).json({ message: "Error accessing file", error });
    }
});

module.exports = router;
