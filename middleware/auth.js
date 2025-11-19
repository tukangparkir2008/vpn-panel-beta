// authentication middleware for VPN API

const jwt = require('jsonwebtoken');

// Middleware function to authenticate JWT tokens
const authenticateJWT = (req, res, next) => {
    const token = req.header('Authorization') && req.header('Authorization').split(' ')[1];
    
    if (!token) {
        return res.sendStatus(403); // Forbidden
    }
    
    jwt.verify(token, process.env.TOKEN_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403); // Forbidden
        }
        req.user = user;
        next();
    });
};

module.exports = authenticateJWT;