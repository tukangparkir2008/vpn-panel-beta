const fs = require('fs');
const path = require('path');

const logDir = path.join(__dirname, '../logs');
if (!fs.existsSync(logDir)) {
  fs.mkdirSync(logDir, { recursive: true });
}

const logFile = path.join(logDir, 'app.log');

const logger = {
  info: (message) => {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] INFO: ${message}\n`;
    console.log(logMessage);
    fs.appendFileSync(logFile, logMessage);
  },

  error: (message) => {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] ERROR: ${message}\n`;
    console.error(logMessage);
    fs.appendFileSync(logFile, logMessage);
  },

  warn: (message) => {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] WARN: ${message}\n`;
    console.warn(logMessage);
    fs.appendFileSync(logFile, logMessage);
  },

  debug: (message) => {
    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] DEBUG: ${message}\n`;
    if (process.env.NODE_ENV === 'development') {
      console.log(logMessage);
    }
    fs.appendFileSync(logFile, logMessage);
  }
};

module.exports = logger;
