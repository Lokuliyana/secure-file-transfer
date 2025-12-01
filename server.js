const express = require('express');
const mongoose = require('mongoose');
const helmet = require('helmet');
const cors = require('cors');
const app = express();
const path = require('path');
const fs = require('fs');
require('dotenv').config();
require('./tasks/scheduler'); // If you’re using cron-based tasks

// Models
const File = require('./models/File');

// Basic CORS setup (be specific in prod)
app.use(cors({
    origin: '*',
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Middleware
app.use(helmet());
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Serve uploaded files
app.use('/uploads', express.static(path.join(__dirname, 'uploads'), {
  setHeaders: (res, filePath) => {
    res.setHeader('Cross-Origin-Resource-Policy', 'cross-origin');
  }
}));

// Routes
const authRoutes = require('./routes/authRoutes');
const friendRoutes = require('./routes/friendRoutes');
const fileRoutes = require('./routes/fileRoutes');

app.use('/api/user', authRoutes);
app.use('/api/friends', friendRoutes);
app.use('/api/file', fileRoutes);

// 🔥 Auto-delete expired files on server start
async function deleteExpiredFilesOnStartup() {
  try {
    const now = new Date();
    const expiredFiles = await File.find({ expiresAt: { $lte: now } });

    for (const file of expiredFiles) {
      if (fs.existsSync(file.fileUrl)) {
        fs.unlinkSync(file.fileUrl); // Delete file from disk
      }
      await File.findByIdAndDelete(file._id); // Delete from DB
      console.log(`🗑️ Deleted expired file: ${file.name}`);
    }

    console.log('✅ Expired file cleanup complete.');
  } catch (error) {
    console.error('❌ Expired file cleanup error:', error);
  }
}

// Start Server only after DB connection is ready
const PORT = process.env.PORT || 3000;
mongoose.connect(process.env.MONGO_URI)
  .then(async () => {
    console.log('✅ MongoDB connected');
    await deleteExpiredFilesOnStartup(); // 🧹 Clean expired files
    app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
  })
  .catch(err => console.error('❌ MongoDB connection error:', err));
