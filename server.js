const express = require('express');
const cors = require('cors');
require('dotenv').config();
const mongoose = require('mongoose');
const helmet = require('helmet');
const app = express();

require('./tasks/scheduler');

app.use(cors({
    origin: '*', // Be more specific in production
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));


// Middleware
app.use(express.json()); // Parses JSON bodies
app.use(helmet()); // Adds security headers to responses

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.log(err));

// Routes
const authRoutes = require('./routes/authRoutes');
const friendRoutes = require('./routes/friendRoutes');
const fileRoutes = require('./routes/fileRoutes'); // Correctly declare a separate variable for file routes

// Route middleware
app.use('/api/user', authRoutes);
app.use('/api/friends', friendRoutes);
app.use('/api/file', fileRoutes);

// Server listening
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
