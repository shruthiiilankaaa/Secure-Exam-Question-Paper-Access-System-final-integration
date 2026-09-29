const express = require("express");

const {
    signup,
    login,
    refresh,
    logout
} = require("../controllers/authController");

const authMiddleware = require("../middleware/authMiddleware");
const authorize = require("../middleware/roleMiddleware");

const User = require("../models/User");
const {
    signupLimiter,
    loginIpLimiter,
    loginAccountLimiter
} = require("../middleware/rateLimiters");

const router = express.Router();


// =====================================================
// PUBLIC ROUTES
// =====================================================

router.post("/signup", signupLimiter, signup);

router.post("/login", loginIpLimiter, loginAccountLimiter, login);

router.post("/refresh", refresh);

router.post("/logout", logout);


// =====================================================
// PROTECTED PROFILE ROUTE
// =====================================================

router.get(
    "/profile",
    authMiddleware,
    (req, res) => {
        res.json({
            message: "You accessed a protected route",
            user: req.user
        });
    }
);


// =====================================================
// CURRENT USER
// =====================================================

router.get(
    "/me",
    authMiddleware,
    async (req, res) => {
        try {
            const user = await User.findById(req.user.userId)
                .select("-passwordHash");

            if (!user) {
                return res.status(404).json({
                    message: "User not found"
                });
            }

            res.status(200).json({
                user: {
                    id: user._id,
                    name: user.name,
                    email: user.email,
                    role: user.role
                }
            });

        } catch (error) {
            console.error("Get current user error:", error);

            res.status(500).json({
                message: "Server error"
            });
        }
    }
);


// =====================================================
// APPROVER DIRECTORY (setters pick approvers from this list)
// =====================================================

router.get(
    "/approvers",
    authMiddleware,
    async (req, res) => {
        try {
            const users = await User.find({ role: { $in: ["approver", "invigilator"] } })
                .select("name email role")
                .lean();

            res.json({
                users: users.map((u) => ({
                    id: u._id,
                    name: u.name,
                    email: u.email,
                    role: u.role
                }))
            });
        } catch (error) {
            console.error("Approver list error:", error);
            res.status(500).json({ message: "Server error" });
        }
    }
);


// =====================================================
// ROLE TEST ROUTES
// =====================================================

// Setter only
router.get(
    "/setter-test",
    authMiddleware,
    authorize("setter"),
    (req, res) => {
        res.json({
            message: "Setter access granted",
            user: req.user
        });
    }
);


// Approver only
router.get(
    "/approver-test",
    authMiddleware,
    authorize("approver"),
    (req, res) => {
        res.json({
            message: "Approver access granted",
            user: req.user
        });
    }
);


// Invigilator only
router.get(
    "/invigilator-test",
    authMiddleware,
    authorize("invigilator"),
    (req, res) => {
        res.json({
            message: "Invigilator access granted",
            user: req.user
        });
    }
);


module.exports = router;