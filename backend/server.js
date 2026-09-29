// Load .env FIRST so every module below (rate limiters, validators...) sees it
require("dotenv").config();

// Refuse to start with missing / weak secrets
require("./config/env").validateEnv();

const express = require("express");
const cors = require("cors");
const path = require("path");
const multer = require("multer");
const cookieParser = require("cookie-parser");

const connectDB = require("./config/db");
const authRoutes = require("./routes/authRoutes");
const paperRoutes = require("./routes/paperRoutes");
const auditRoutes = require("./routes/auditRoutes");
const adminRoutes = require("./routes/adminRoutes");
const { apiLimiter } = require("./middleware/rateLimiters");

const app = express();
app.disable("x-powered-by");

// Only if deployed behind a reverse proxy / load balancer (so req.ip is the real client)
if (process.env.TRUST_PROXY) {
    app.set("trust proxy", Number(process.env.TRUST_PROXY) || process.env.TRUST_PROXY);
}

// Security headers. script-src 'self' (no inline JS) is the important one:
// it turns any HTML-injection bug into a non-event.
app.use((req, res, next) => {
    res.setHeader(
        "Content-Security-Policy",
        [
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data:",
            "font-src 'self'",
            "connect-src 'self'",
            "object-src 'none'",
            "base-uri 'none'",
            "form-action 'self'",
            "frame-ancestors 'none'"
        ].join("; ")
    );
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Referrer-Policy", "no-referrer");
    res.setHeader("Cross-Origin-Opener-Policy", "same-origin");
    if (process.env.NODE_ENV === "production") {
        res.setHeader("Strict-Transport-Security", "max-age=15552000; includeSubDomains");
    }
    next();
});

// The frontend is served from this same origin, so CORS is only needed if you
// host the UI elsewhere. Never reflect arbitrary origins with credentials.
if (process.env.CORS_ORIGIN) {
    app.use(cors({ origin: process.env.CORS_ORIGIN.split(",").map((s) => s.trim()), credentials: true }));
}
app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());

// Serve the frontend (static files from ../frontend)
app.use(express.static(path.join(__dirname, "..", "frontend")));

// Connect MongoDB
connectDB();

// Rate limit every API call
app.use("/api", apiLimiter);

app.use("/api/auth", authRoutes);
app.use("/api/papers", paperRoutes);
app.use("/api/audit", auditRoutes);
app.use("/api/admin", adminRoutes);

app.get("/api/health", (req, res) => {
    res.json({ message: "Secure Exam Question Paper System API is running" });
});

// 404 for unknown API routes (JSON, not an HTML page)
app.use("/api", (req, res) => res.status(404).json({ message: "Not found" }));

// Central error handler: never leak stack traces or internals.
// (Express 5 forwards rejected async handlers here automatically.)
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    if (res.headersSent) return next(err);

    if (err instanceof multer.MulterError) {
        const tooBig = err.code === "LIMIT_FILE_SIZE";
        return res.status(tooBig ? 413 : 400).json({
            message: tooBig ? "File is too large" : "Invalid upload"
        });
    }
    if (err && (err.type === "entity.parse.failed" || err.type === "entity.too.large")) {
        return res.status(err.status || 400).json({ message: "Invalid request body" });
    }
    if (err && err.name === "CastError") {
        return res.status(400).json({ message: "Invalid identifier" });
    }

    console.error("Unhandled error:", err);
    res.status(500).json({ message: "Server error" });
});

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
