const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cors = require('cors');
const app = express();
const path = require('path');

require('dotenv').config();
require('./tasks/scheduler');

app.use(cors({
    origin: '*', // Be more specific in production
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Middleware
app.use(express.json());
app.use(helmet());
app.use(cors());

// Database Connection
mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.log(err));

// Serve uploaded profile pictures statically
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  setHeaders: (res, filePath) => {
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin'); // ✅ Fix CORP error
  }
}));


// Route Imports
const authRoutes = require('./routes/authRoutes');
const friendRoutes = require('./routes/friendRoutes');
const fileRoutes = require('./routes/fileRoutes');

// Routes
app.use('/api/user', authRoutes);
app.use('/api/friends', friendRoutes);
app.use('/api/file', fileRoutes);

// Start Server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));