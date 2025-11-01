const asyncHandler = require("express-async-handler");
const jwt = require("jsonwebtoken");

const validateToken = asyncHandler(async (req, res, next) => {
    let token;
    let authHeader = req.headers.Authorization || req.headers.authorization;

    if (authHeader && authHeader.startsWith("Bearer")) {
        token = authHeader.split(" ")[1];
        
        if (!token) {
            res.status(401);
            throw new Error("Token is missing.");
        }

        try {
            const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
            req.user = decoded.user;
            next();
        } catch (err) {
            res.status(401);
            throw new Error("User is not authorized");
        }
    } else {
        res.status(401);
        throw new Error("Authorization header is missing or invalid.");
    }
});

module.exports = validateToken;