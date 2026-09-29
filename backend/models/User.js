const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: true,
            trim: true
        },

        email: {
            type: String,
            required: true,
            unique: true,
            lowercase: true,
            trim: true
        },

        passwordHash: {
            type: String,
            required: true
        },

        // New accounts start as "pending" until an admin assigns a real role.
        // "admin" can only be created with `npm run seed:admin`, never via signup.
        role: {
            type: String,
            enum: ["setter", "approver", "invigilator", "admin", "pending"],
            default: "pending",
            required: true
        },

        // Bumped on logout, role change, or password change to instantly
        // invalidate every refresh (and access) token issued before that point,
        // without having to store/blacklist individual tokens.
        tokenVersion: {
            type: Number,
            default: 0
        },

        // jti of the one refresh token currently considered valid for this user
        // (single active session). Rotated on every /auth/refresh and /auth/login.
        // Replaying an OLDER refresh token — a sign it was stolen and used after
        // the legitimate client already rotated past it — is rejected AND treated
        // as compromise: tokenVersion is bumped, killing every outstanding token.
        currentRefreshJti: {
            type: String,
            default: null
        }
    },
    {
        timestamps: true
    }
);

const User = mongoose.model("User", userSchema);

module.exports = User;
