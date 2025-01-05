const jwt = require('jsonwebtoken');

const verifyToken = (req, res, next) => {
    const token = req.header('Authorization');

    // Check if the Authorization header exists and contains a token
    if (!token || !token.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'No token, authorization denied' });
    }

    // Remove 'Bearer ' prefix and proceed
    const tokenString = token.replace('Bearer ', '');

    try {
        const decoded = jwt.verify(tokenString, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).json({ message: 'Token is not valid' });
    }
};

module.exports = { verifyToken };
