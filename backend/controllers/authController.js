const bcrypt = require("bcryptjs");
const User = require("../models/User");
const {
    signAccessToken,
    signRefreshToken,
    verifyRefreshToken,
    setRefreshCookie,
    clearRefreshCookie,
    newJti
} = require("../utils/tokens");
const {
    normalizeEmail,
    emailProblem,
    passwordProblems
} = require("../utils/validators");

// =====================================================
// SIGNUP
// New accounts are always created as "pending". An admin
// assigns the real role afterwards (see adminController).
// =====================================================

const signup = async (req, res) => {
    try {
        const { name, email, password } = req.body || {};

        // Must be plain strings (also blocks NoSQL operator objects like {"$ne": null})
        if (
            typeof name !== "string" || !name.trim() ||
            typeof email !== "string" || !email.trim() ||
            typeof password !== "string" || !password
        ) {
            return res.status(400).json({
                message: "Name, email and password are required"
            });
        }

        const cleanName = name.trim();
        if (cleanName.length > 100) {
            return res.status(400).json({ message: "Name is too long" });
        }

        // Email: valid shape + must belong to the allowed domain
        const cleanEmail = normalizeEmail(email);
        const emailError = emailProblem(cleanEmail);
        if (emailError) {
            return res.status(400).json({ message: emailError });
        }

        // Password strength
        const problems = passwordProblems(password, cleanEmail);
        if (problems.length) {
            return res.status(400).json({
                message: `Password requirements not met: ${problems.join(", ")}`,
                errors: problems
            });
        }

        // Check whether email already exists
        const existingUser = await User.findOne({ email: cleanEmail });
        if (existingUser) {
            return res.status(409).json({
                message: "User with this email already exists"
            });
        }

        const passwordHash = await bcrypt.hash(password, 10);

        const user = await User.create({
            name: cleanName,
            email: cleanEmail,
            passwordHash,
            role: "pending"
        });

        res.status(201).json({
            message: "Account created. An admin must assign your role before you can sign in.",
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        // Two simultaneous signups with the same email -> unique index error
        if (error && error.code === 11000) {
            return res.status(409).json({
                message: "User with this email already exists"
            });
        }

        console.error("Signup error:", error);

        res.status(500).json({
            message: "Server error during signup"
        });
    }
};


// =====================================================
// LOGIN
// =====================================================

const login = async (req, res) => {
    try {
        const { email, password } = req.body || {};

        if (
            typeof email !== "string" || !email.trim() ||
            typeof password !== "string" || !password
        ) {
            return res.status(400).json({
                message: "Email and password are required"
            });
        }

        const user = await User.findOne({
            email: normalizeEmail(email)
        });

        // Don't reveal whether the email exists
        if (!user) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        const passwordMatch = await bcrypt.compare(
            password,
            user.passwordHash
        );

        if (!passwordMatch) {
            return res.status(401).json({
                message: "Invalid email or password"
            });
        }

        // Only tell the user their account is pending AFTER the password is proven right
        if (user.role === "pending") {
            return res.status(403).json({
                message: "Account awaiting admin approval",
                code: "PENDING_APPROVAL"
            });
        }

        const jti = newJti();
        user.currentRefreshJti = jti;
        await user.save();

        const accessToken = signAccessToken(user);
        const refreshToken = signRefreshToken(user, jti);
        setRefreshCookie(res, refreshToken);

        res.status(200).json({
            message: "Login successful",
            token: accessToken,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        console.error("Login error:", error);

        res.status(500).json({
            message: "Server error during login"
        });
    }
};


// =====================================================
// REFRESH — exchange the httpOnly refresh cookie for a
// new short-lived access token (and a rotated refresh cookie)
// =====================================================

const refresh = async (req, res) => {
    try {
        const token = req.cookies?.refreshToken;
        if (!token) {
            return res.status(401).json({ message: "No refresh token" });
        }

        let payload;
        try {
            payload = verifyRefreshToken(token);
        } catch (err) {
            clearRefreshCookie(res);
            return res.status(401).json({ message: "Invalid or expired refresh token" });
        }

        const user = await User.findById(payload.userId);

        // tokenVersion mismatch = this token was issued before a logout,
        // role change, or password change revoked it. Reject even though
        // the JWT signature itself is still valid.
        if (!user || user.tokenVersion !== payload.tokenVersion) {
            clearRefreshCookie(res);
            return res.status(401).json({ message: "Session has been revoked, please log in again" });
        }

        // Reuse detection: only the MOST RECENTLY issued refresh token is
        // valid. Presenting an older one (this jti no longer matches) means
        // either a race (harmless) or a stolen token being replayed after
        // the real client already rotated past it (not harmless) — treat it
        // as compromise and kill every token for this account.
        if (!payload.jti || payload.jti !== user.currentRefreshJti) {
            user.tokenVersion += 1;
            user.currentRefreshJti = null;
            await user.save();
            clearRefreshCookie(res);
            return res.status(401).json({ message: "Refresh token reuse detected, all sessions revoked" });
        }

        if (user.role === "pending") {
            clearRefreshCookie(res);
            return res.status(403).json({ message: "Account awaiting admin approval" });
        }

        // Rotate on every use: a stolen-but-unused old cookie stops working
        // the moment the legitimate user refreshes once (see reuse check above).
        const newJtiValue = newJti();
        user.currentRefreshJti = newJtiValue;
        await user.save();

        const newAccessToken = signAccessToken(user);
        const newRefreshToken = signRefreshToken(user, newJtiValue);
        setRefreshCookie(res, newRefreshToken);

        res.status(200).json({
            token: newAccessToken,
            user: {
                id: user._id,
                name: user.name,
                email: user.email,
                role: user.role
            }
        });

    } catch (error) {
        console.error("Refresh error:", error);
        res.status(500).json({ message: "Server error during refresh" });
    }
};


// =====================================================
// LOGOUT — clears the cookie AND bumps tokenVersion, so
// every access/refresh token issued before this moment
// (this device or any other) stops working immediately.
// =====================================================

const logout = async (req, res) => {
    try {
        const token = req.cookies?.refreshToken;
        if (token) {
            try {
                const payload = verifyRefreshToken(token);
                await User.updateOne({ _id: payload.userId }, { $inc: { tokenVersion: 1 }, $set: { currentRefreshJti: null } });
            } catch (err) {
                // token already invalid/expired -> nothing to revoke, just clear the cookie
            }
        }
        clearRefreshCookie(res);
        res.status(200).json({ message: "Logged out" });
    } catch (error) {
        console.error("Logout error:", error);
        res.status(500).json({ message: "Server error during logout" });
    }
};


module.exports = {
    signup,
    login,
    refresh,
    logout
};
