require('dotenv').config();
const express = require('express');
const nodemailer = require('nodemailer');
const { check, validationResult, body } = require('express-validator');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const rateLimit = require('express-rate-limit');
const { generateKeyPairSync } = require('crypto');
const User = require('../models/User');
const router = express.Router();
const Notification = require('../models/Notifications'); // Assuming this is the correct path

const otpStorage = {}; // Temporary in-memory storage for OTPs
const verifyToken = require('../middleware/verifyToken'); // Adjust path as needed


// Configure Nodemailer Transporter
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Function to generate OTP
function generateOTP() {
    return Math.floor(100000 + Math.random() * 900000); // 6-digit OTP
}

// Function to send OTP via email
async function sendOTP(email, otp, message) {
    const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Your One-Time Password (OTP) for Authentication",
        text: `${message}\n\nYour OTP is: ${otp}\nThis OTP is valid for 5 minutes.`
    };

    try {
        await transporter.sendMail(mailOptions);
    } catch (error) {
        console.error("Error sending OTP email:", error);
    }
}

// RSA Key Generation
function generateRSAKeys() {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', {
        modulusLength: 2048,
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' }
    });
    return { publicKey, privateKey };
}

// ✅ Storage Configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
      const dir = './uploads/profile-pictures/';
      fs.mkdirSync(dir, { recursive: true });
      cb(null, dir);
    },
    filename: async (req, file, cb) => {
      const userId = req.user._id;
      const ext = path.extname(file.originalname);
      const filePath = path.join(__dirname, `../uploads/profile-pictures/${userId}${ext}`);
  
      // ✅ Delete old image if exists
      fs.readdir(path.join(__dirname, '../uploads/profile-pictures'), (err, files) => {
        if (!err) {
          files.forEach(filename => {
            if (filename.startsWith(userId)) {
              fs.unlinkSync(path.join(__dirname, `../uploads/profile-pictures/${filename}`));
            }
          });
        }
        cb(null, `${userId}${ext}`);
      });
    }
  });

  // ✅ Image File Filter
const fileFilter = (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const ext = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mime = allowedTypes.test(file.mimetype);
    if (ext && mime) {
      cb(null, true);
    } else {
      cb(new Error('Only image files are allowed (jpeg, jpg, png, gif)'));
    }
  };
  
  const upload = multer({ storage, fileFilter });

// Rate Limiting
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    message: 'Too many accounts created from this IP, please try again after 15 minutes'
});

// **REGISTER USER (Without Saving to Database)**
router.post('/register', [
    body('name').not().isEmpty().trim().escape(),
    body('username').not().isEmpty().trim().escape(),
    body('email').isEmail().normalizeEmail(),
    body('mobileNumber').not().isEmpty().trim().escape(),
    body('password').isLength({ min: 6 })
], async (req, res) => {
    const { name, username, email, mobileNumber, password } = req.body;

    try {
        const existingUser = await User.findOne({ $or: [{ email }, { username }, { mobileNumber }] });
        if (existingUser) {
            return res.status(409).json({ message: "An account already exists with the provided email, username, or mobile number." });
        }

        // Hash password but don't save to DB yet
        const hashedPassword = await bcrypt.hash(password, 10);
        const { publicKey, privateKey } = generateRSAKeys();

        // Store user details temporarily in `otpStorage`
        const otp = generateOTP();
        otpStorage[email] = { otp, userData: { name, username, email, mobileNumber, password: hashedPassword, publicKey } };

        // Send OTP Email
        await sendOTP(email, otp, "Welcome to our platform! Please verify your email by entering the OTP below.");

        res.status(201).json({
            message: 'OTP sent to your email. Please verify to complete registration.'
        });

    } catch (error) {
        res.status(500).json({ message: "Error registering user", error: error.toString() });
    }
});

// **VERIFY OTP & SAVE USER TO DATABASE**
router.post('/verify-registration-otp', async (req, res) => {
    const { email, otp } = req.body;

    if (!otpStorage[email] || otpStorage[email].otp != otp) {
        return res.status(400).json({ message: "Invalid or expired OTP!" });
    }

    // Retrieve stored user data
    const { userData } = otpStorage[email];
    const privateKey = userData.privateKey;

    try {
        const newUser = new User(userData);
        await newUser.save();

        delete otpStorage[email]; // Clean up after use

        // ✅ Send private key back to frontend
        res.json({
            message: "Email verified and account created successfully.",
            privateKey
        });
    } catch (error) {
        res.status(500).json({ message: "Error saving user data", error: error.toString() });
    }
});

router.post('/login', async (req, res) => {
    const { emailOrUsername, password } = req.body;

    try {
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

        // Generate OTP and store it temporarily
        const otp = generateOTP();
        otpStorage[user.email] = otp;

        // Send OTP Email
        await sendOTP(user.email, otp, "A login attempt was detected. Enter the OTP below to proceed.");

        res.json({ 
            message: "OTP sent to your registered email. Enter the OTP to proceed.",
            email: user.email  // ✅ Send email to frontend
        });

    } catch (error) {
        console.error("Login error: ", error);
        res.status(500).json({ message: "Error on login", error });
    }
});


router.post('/verify-login-otp', async (req, res) => {
    const { email, otp } = req.body;

    // Ensure email exists and has a stored OTP
    if (!otpStorage[email]) {
        return res.status(400).json({ message: "OTP request not found for this email. Please request a new OTP." });
    }

    // Validate OTP
    if (otpStorage[email] != otp) {
        return res.status(400).json({ message: "Invalid or expired OTP!" });
    }

    const user = await User.findOne({ email });
    if (!user) return res.status(404).json({ message: "User not found" });

    const token = jwt.sign({ _id: user._id, email: user.email}, process.env.JWT_SECRET, { expiresIn: '1h' });
    if (!user.privacySetting) {
        user.privacySetting = 'public';
        await user.save(); // Save default
      }      

    delete otpStorage[email]; // Remove OTP after successful login
    res.header('auth-token', token).json({ 
        token: token, 
        message: 'Logged in successfully' 
    });
});

// Update public key
router.patch('/update-public-key', verifyToken, async (req, res) => {
    const { publicKey } = req.body;
    if (!publicKey) return res.status(400).json({ message: "Public key is required" });

    try {
        const updated = await User.findByIdAndUpdate(req.user._id, { publicKey }, { new: true });
        res.json({ message: "Public key updated successfully", updatedUser: updated });
    } catch (error) {
        console.error("Public key update error:", error);
        res.status(500).json({ message: "Error updating public key", error });
    }
});

router.get('/profile', verifyToken, async (req, res) => {
    try {
      const user = await User.findById(req.user._id).select('-password');
      if (!user) return res.status(404).send('User not found');
  
      // Check if profile picture exists in known extensions
      const extensions = ['.jpg', '.jpeg', '.png', '.gif'];
      const basePath = path.join(__dirname, '../uploads/profile-pictures');
      let profilePictureUrl = null;
  
      for (let ext of extensions) {
        const filePath = path.join(basePath, `${user._id}${ext}`);
        if (fs.existsSync(filePath)) {
          profilePictureUrl = `http://localhost:3000/uploads/profile-pictures/${user._id}${ext}`;
          break;
        }
      }
  
      res.json({ user, profilePicture: profilePictureUrl });
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

// ✅ Upload Profile Picture Route
router.post('/upload-profile-picture', verifyToken, upload.single('profilePicture'), async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ message: "No image uploaded." });
    }
  
    const filename = req.file.filename;
    const fileUrl = `/uploads/profile-pictures/${filename}`;
  
    try {
      await User.findByIdAndUpdate(req.user._id, { profilePicture: fileUrl }, { new: true });
      res.json({ message: "✅ Profile picture updated successfully", profilePicture: `http://localhost:3000${fileUrl}` });
    } catch (error) {
      console.error("❌ Error saving profile picture:", error);
      res.status(500).json({ message: "Error saving profile picture", error });
    }
  });

  router.patch('/update-privacy', verifyToken, async (req, res) => {
    const { privacySetting } = req.body;
    console.log("🛡️ Incoming privacy setting:", privacySetting); // ✅ log this

    if (!['public', 'private'].includes(privacySetting)) {
        return res.status(400).json({ message: "Invalid privacy setting value." });
    }

    try {
        const updatedUser = await User.findByIdAndUpdate(req.user._id, { privacySetting }, { new: true });

        const newNotification = new Notification({
            userId: req.user._id,
            type: 'Privacy Settings Change',
            title: 'Privacy Settings Updated',
            message: `Your privacy settings have been updated to ${privacySetting}.`,
        });
        await newNotification.save();

        res.json({ message: 'Privacy settings updated successfully', updatedUser });
    } catch (error) {
        res.status(500).json({ message: "Error updating privacy settings", error });
    }
});

// Search Users by name, username, or email
router.get('/search', verifyToken, async (req, res) => {
    const { search } = req.query;
    if (!search) {
        return res.status(400).send('Search query is required.');
    }

    try {
        const users = await User.find({
            $or: [
                { name: { $regex: search, $options: 'i' } },
                { username: { $regex: search, $options: 'i' } },
                { email: { $regex: search, $options: 'i' } }
            ]
        }).select('-password -otp -otpExpiry'); // Exclude sensitive information

        res.json(users);
    } catch (error) {
        res.status(500).json({ message: "Error fetching users", error });
    }
});

router.get('/notifications', verifyToken, async (req, res) => {
    console.log("Fetching notifications for user:", req.user._id);
    try {
        const userId = req.user._id;
        const notifications = await Notification.find({ userId: userId })
            .sort({ timestamp: -1 })
            .limit(25);

        if (!notifications.length) {
            console.log("No notifications found for user:", userId);
            return res.status(404).json({ message: "No notifications found." });
        }

        res.json(notifications);
    } catch (error) {
        console.error("Error fetching notifications:", error);
        res.status(500).json({ message: "Failed to fetch notifications", error: error.toString() });
    }
});


module.exports = router;
