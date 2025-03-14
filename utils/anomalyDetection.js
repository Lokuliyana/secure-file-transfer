// utils/anomalyDetection.js
const fs = require('fs');
const logger = require('./logger');

const analyzeLogs = () => {
    fs.readFile('application.log', 'utf8', (err, data) => {
        if (err) {
            logger.error("Error reading log file: " + err.message);
            return;
        }

        const accessPattern = {};
        data.split('\n').forEach(line => {
            if (line.includes('File Download')) {
                const match = line.match(/file (\S+)/);
                const fileId = match ? match[1] : null;
                if (fileId) {
                    accessPattern[fileId] = (accessPattern[fileId] || 0) + 1;
                }
            }
        });

        Object.keys(accessPattern).forEach(fileId => {
            if (accessPattern[fileId] > 10) { // Threshold for unusual access
                logger.warn(`Anomaly Detected: File ${fileId} accessed ${accessPattern[fileId]} times.`);
            }
        });
    });
};

module.exports = analyzeLogs;
