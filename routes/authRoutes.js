const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const nodemailer = require('nodemailer');

const router = express.Router();

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 10 login/register requests per windowMs
    message: 'Too many accounts created from this IP, please try again after 15 minutes'
});

async function sendOtpEmail(userEmail, otp) {
    const transporter = nodemailer.createTransport({
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD
        }
    });

    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: userEmail,
        subject: 'Your OTP',
        text: `Your OTP is: ${otp}`
    };

    try {
        await transporter.sendMail(mailOptions);
    } catch (error) {
        console.error("Error sending email: ", error);
        throw new Error('Failed to send OTP email');
    }
}

router.post('/register', [
    body('name').not().isEmpty().trim().escape(),
    body('username').not().isEmpty().trim().escape(),
    body('email').isEmail().normalizeEmail(),
    body('mobileNumber').not().isEmpty().trim().escape(), // Add validation as per your requirement
    body('password').isLength({ min: 6 })
], async (req, res) => {
    const { name, username, email, mobileNumber, password } = req.body;
    try {
        const existingUser = await User.findOne({ $or: [{ email }, { username }, { mobileNumber }] });
        if (existingUser) {
            return res.status(409).json({ message: "An account already exists with provided email, username, or mobile number." });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({ name, username, email, mobileNumber, password: hashedPassword });
        await newUser.save();
        res.status(201).send('User registered successfully');
    } catch (error) {
        res.status(500).json({ message: "Error registering new user", error: error });
    }
});

// Login User
router.post('/login', [
    body('email').isEmail().normalizeEmail(),
    body('password').not().isEmpty()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(404).json({ message: "User not found" });

        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) return res.status(401).json({ message: "Invalid password" });

        const otp = Math.floor(100000 + Math.random() * 900000); // Generate a 6-digit OTP
        await sendOtpEmail(email, otp.toString()); // Send OTP to the user's email

        user.otp = otp.toString();
        user.otpExpiry = new Date(Date.now() + 300000); // OTP expires in 5 minutes
        await user.save();

        res.json({ message: 'OTP sent to your email, please verify to continue.' });
    } catch (error) {
        console.error("Login error: ", error);
        res.status(500).json({ message: "Error on login", error });
    }
});

// Verify OTP - Second step
router.post('/verify-otp', [
    body('email').isEmail().normalizeEmail(),
    body('otp').not().isEmpty()
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { email, otp } = req.body;
    try {
        const user = await User.findOne({ email, otp, otpExpiry: { $gt: new Date() } });
        if (!user) return res.status(400).json({ message: "Invalid OTP or OTP expired" });

        // Clear OTP from the database
        user.otp = null;
        user.otpExpiry = null;
        await user.save();

        const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.header('auth-token', token).json({ token, message: 'Logged in successfully' });
    } catch (error) {
        res.status(500).json({ message: "Error verifying OTP", error });
    }
});

// Middleware to validate user tokens
const verifyToken = require('../middleware/verifyToken');

router.get('/profile', verifyToken, async (req, res) => {
    try {
        const user = await User.findById(req.user._id).select('-password'); // Exclude password from result
        if (!user) return res.status(404).send('User not found');
        res.json(user);
    } catch (error) {
        res.status(500).json({ message: "Error fetching user profile", error });
    }
});

router.put('/profile', verifyToken, [
    body('email').optional().isEmail().normalizeEmail(),
    body('username').optional().not().isEmpty().trim().escape()
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
        res.json(user);
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
