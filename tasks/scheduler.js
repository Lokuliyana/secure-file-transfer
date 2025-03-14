const cron = require('node-cron');
const analyzeLogs = require('../utils/anomalyDetection'); // Adjust path as necessary

// Schedule the anomaly detection to run every hour
cron.schedule('0 * * * *', () => {
    console.log('Running anomaly detection every hour');
    analyzeLogs();
});
