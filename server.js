const express = require('express');
require('dotenv').config();
const mongoose = require('mongoose');
const helmet = require('helmet');
const app = express();

// Middleware
app.use(express.json()); // Parses JSON bodies
app.use(helmet()); // Adds security headers to responses

// Connect to MongoDB without deprecated options
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.log(err));

// Routes
const authRoutes = require('./routes/authRoutes');
const friendRoutes = require('./routes/friendRoutes');

// Route middleware
app.use('/api/user', authRoutes);
app.use('/api/friends', friendRoutes);

// Server listening
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
