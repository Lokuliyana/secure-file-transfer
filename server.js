const express = require('express');
const mongoose = require('mongoose');

const app = express();

app.use(express.json()); // Middleware to parse JSON

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
