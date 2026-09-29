const jwt = require("jsonwebtoken");
const User = require("../models/User");

const authMiddleware = async (req, res, next) => {
    try {
        // Get Authorization header
        const authHeader = req.headers.authorization;

        // Check whether token exists
        if (!authHeader || !authHeader.startsWith("Bearer ")) {
            return res.status(401).json({
                message: "Access denied. No token provided."
            });
        }

        // Extract token and verify signature/expiry
        const token = authHeader.split(" ")[1];
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // A refresh token is a valid JWT too (different secret would normally
        // catch this) — belt-and-suspenders check against token confusion.
        if (decoded.type !== "access") {
            return res.status(401).json({ message: "Invalid token type" });
        }

        // Re-read the user's CURRENT role from the DB, so role changes made by
        // an admin apply immediately instead of waiting for the token to expire.
        const user = await User.findById(decoded.userId).select("role tokenVersion").lean();

        if (!user) {
            return res.status(401).json({ message: "Invalid or expired token" });
        }

        // Revocation: logout / role change / reuse-detection bump tokenVersion,
        // which kills access tokens immediately (not after the 15 min expiry).
        // Tokens minted before this check existed carry no version -> rejected;
        // the client's silent refresh transparently issues a new one.
        if (typeof decoded.tokenVersion !== "number" || decoded.tokenVersion !== (user.tokenVersion || 0)) {
            return res.status(401).json({ message: "Invalid or expired token" });
        }

        if (user.role === "pending") {
            return res.status(403).json({ message: "Account awaiting admin approval" });
        }

        // Attach authenticated user information
        req.user = {
            userId: decoded.userId,
            role: user.role
        };

        next();

    } catch (error) {
        console.error("JWT verification error:", error.message);

        return res.status(401).json({
            message: "Invalid or expired token"
        });
    }
};

module.exports = authMiddleware;
