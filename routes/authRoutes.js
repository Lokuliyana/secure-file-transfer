const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');

const router = express.Router();

const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 10 login/register requests per windowMs
    message: 'Too many accounts created from this IP, please try again after 15 minutes'
});

// Register User
router.post('/register', authLimiter, [
    body('username').not().isEmpty().trim().escape(),
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 6 })
], async (req, res) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ errors: errors.array() });
    }
    const { username, email, password } = req.body;
    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(409).json({ message: "User already exists with that email." });
        }

        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();
        res.status(201).send('User registered');
    } catch (error) {
        res.status(500).json({ message: "Error registering new user", error: error });
    }
});

// Login User
router.post('/login', authLimiter, [
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

      const token = jwt.sign({ _id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
      console.log('Generated Token:', token); // Log the token for debugging
      res.header('auth-token', token).json({ token: token, message: 'Logged in' }); // Send token in body for easy access
  } catch (error) {
      res.status(500).json({ message: "Error logging in", error: error });
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

module.exports = router;
