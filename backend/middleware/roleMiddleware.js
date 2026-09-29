const authorize = (...allowedRoles) => {
    return (req, res, next) => {

        // Check that authentication happened first
        if (!req.user) {
            return res.status(401).json({
                message: "Authentication required"
            });
        }

        // Check user's role
        if (!allowedRoles.includes(req.user.role)) {
            return res.status(403).json({
                message: "Access denied. Insufficient permissions."
            });
        }

        // Role is allowed
        next();
    };
};

module.exports = authorize;