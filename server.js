'use strict';

const express = require('express');
const morgan = require('morgan');
const bodyParser = require('body-parser');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware Configuration
app.use(morgan('dev')); // Logging middleware
app.use(bodyParser.json()); // Parse JSON bodies
app.use(bodyParser.urlencoded({ extended: true })); // Parse URL-encoded bodies

// Route Initialization
app.get('/api/vpn', (req, res) => {
    res.send('VPN REST API');
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
