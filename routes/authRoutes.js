const fs = require('fs');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const { generateKeyPairSync } = require('crypto');
const nodemailer = require('nodemailer');
const { check } = require('express-validator');
const router = express.Router();

// Middleware to validate user tokens
const verifyToken = require('../middleware/verifyToken');

// Multer and path imports
const multer = require('multer');
const path = require('path');

const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        const dir = './uploads/profile-pictures/';
        fs.mkdirSync(dir, { recursive: true }); // Ensure directory exists
        cb(null, dir);
    },
    filename: (req, file, cb) => {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, file.fieldname + '-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });


const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 10 login/register requests per windowMs
    message: 'Too many accounts created from this IP, please try again after 15 minutes'
});

// Function to generate RSA key pair
function generateRSAKeys() {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    return { publicKey, privateKey };
}

router.post('/register', [
    body('name').not().isEmpty().trim().escape(),
    body('username').not().isEmpty().trim().escape(),
    body('email').isEmail().normalizeEmail(),
    body('mobileNumber').not().isEmpty().trim().escape(),
    body('password').isLength({ min: 6 })
], async (req, res) => {
    const { name, username, email, mobileNumber, password } = req.body;

    try {
        // Check if user already exists
        const existingUser = await User.findOne({ $or: [{ email }, { username }, { mobileNumber }] });
        if (existingUser) {
            return res.status(409).json({ message: "An account already exists with provided email, username, or mobile number." });
        }

        // Hash password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Generate RSA key pair
        const { publicKey, privateKey } = generateRSAKeys();

        // Create new user with public key stored
        const newUser = new User({
            name,
            username,
            email,
            mobileNumber,
            password: hashedPassword,
            publicKey // Store public key in database
        });

        await newUser.save();

        // Respond with private key (user must save it securely)
        res.status(201).json({
            message: 'User registered successfully',
            privateKey // Send private key once
        });

    } catch (error) {
        res.status(500).json({ message: "Error registering new user", error: error.toString() });
    }
});

module.exports = router;
router.post('/login', [
    check('emailOrUsername')
        .trim()
        .escape()
        .notEmpty()
        .withMessage('Email or username is required')
        .custom(value => value.includes('@') ? check('emailOrUsername').isEmail().withMessage('Invalid email format') : true),
    check('password').notEmpty().withMessage('Password is required')
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { emailOrUsername, password } = req.body;

    try {
        // Find user by email OR username
        const user = await User.findOne({ 
            $or: [{ email: emailOrUsername }, { username: emailOrUsername }]
        });

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
            return res.status(401).json({ message: "Invalid password" });
        }

        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.header('auth-token', token).json({ 
            token: token, 
            message: 'Logged in successfully' 
        });

    } catch (error) {
        console.error("Login error: ", error);
        res.status(500).json({ message: "Error on login", error });
    }
});

router.post('/upload-profile-picture', verifyToken, upload.single('profilePicture'), async (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: "No file uploaded." });
    }
    
    try {
        const user = await User.findByIdAndUpdate(req.user._id, {
            profilePicture: req.file.path
        }, { new: true });

        res.json({ message: 'Profile picture updated successfully', profilePicture: req.file.path });
    } catch (error) {
        res.status(500).json({ message: "Error updating profile picture", error: error.toString() });
    }
});

router.get('/profile', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('-password'); // Exclude password from result
        if (!user) return res.status(404).send('User not found');
        res.json({ user, profilePicture: user.profilePicture });
    } catch (error) {
        res.status(500).json({ message: "Error fetching user profile", error });
    }
});

router.put('/profile', verifyToken, [
    body('email').optional().isEmail().normalizeEmail(),
    body('username').optional().not().isEmpty().trim().escape(),
    body('name').optional().not().isEmpty().trim().escape(), // Validate name
    body('mobileNumber').optional().matches(/^[0-9]+$/).withMessage('Invalid mobile number'), // Validate mobile number as digits
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    try {
        const updateData = req.body;
        if (updateData.password) {
            const salt = await bcrypt.genSalt(10);
            updateData.password = await bcrypt.hash(updateData.password, salt);
        }
        const user = await User.findByIdAndUpdate(req.user._id, { $set: updateData }, { new: true }).select('-password');
        res.json({ message: "Profile updated successfully", user });
    } catch (error) {
        res.status(500).json({ message: "Error updating user profile", error });
    }
});


// Update user privacy settings
router.patch('/update-privacy', verifyToken, async (req, res) => {
    const { privacySetting } = req.body; // 'public' or 'private'
    try {
        const updatedUser = await User.findByIdAndUpdate(req.user._id, { privacySetting }, { new: true });
        res.json({ message: 'Privacy settings updated successfully', updatedUser });
    } catch (error) {
        res.status(500).json({ message: "Error updating privacy settings", error });
    }
});


module.exports = router;
