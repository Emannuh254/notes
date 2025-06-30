require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const validator = require("validator");
const rateLimit = require("express-rate-limit");
const nodemailer = require("nodemailer");

const app = express();

// Secret key for JWT signing (keep it secure in .env)
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_key";

// Frontend URL to enable CORS properly
const FRONTEND_URL = process.env.CORS_ORIGIN || "https://emannuh254.github.io";

// Enable CORS with the specified frontend origin
app.use(
  cors({
    origin: FRONTEND_URL,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
  })
);

// Parse JSON bodies automatically
app.use(express.json());

// Setup MySQL connection pool for efficient DB access
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
});

// Create users table if it doesn't exist yet
db.query(
  `
  CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255),
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255),
    is_google BOOLEAN DEFAULT FALSE,
    reset_token VARCHAR(255),
    token_expires DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`,
  (err) => {
    if (err) console.error("❌ Error creating users table:", err.message);
    else console.log("✅ Users table ready!");
  }
);

// Rate limiting to protect login and signup endpoints from brute force
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // max 50 requests per IP in this window
  message: { error: "Too many requests. Try again later." },
});
app.use("/login", authLimiter);
app.use("/signup", authLimiter);

// Nodemailer setup for sending emails (forgot password)
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Health check route to confirm server is running
app.get("/", (req, res) => {
  res.send("✅ FlipMarket backend is alive");
});

// ------------------- SIGNUP -------------------
// Registers a new user with name, email, and password
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  // Validate required fields
  if (!name || !email || !password)
    return res.status(400).json({ error: "All fields are required" });

  // Validate name contains only letters and spaces
  if (!validator.isAlpha(name.replace(/\s/g, "")))
    return res.status(400).json({ error: "Name must contain only letters" });

  // Validate proper email format
  if (!validator.isEmail(email))
    return res.status(400).json({ error: "Invalid email format" });

  // Validate password length
  if (!validator.isLength(password, { min: 6 }))
    return res
      .status(400)
      .json({ error: "Password must be at least 6 characters" });

  // Check if user already exists
  db.query(
    "SELECT id FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) return res.status(500).json({ error: "Database error" });
      if (results.length > 0)
        return res.status(409).json({ message: "Email already exists" });

      try {
        // Hash password securely before storing
        const hashed = await bcrypt.hash(password, 10);

        // Insert new user into DB
        db.query(
          "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
          [name, email, hashed],
          (err) => {
            if (err) return res.status(500).json({ error: "Signup failed" });
            res.json({ message: "User created" });
          }
        );
      } catch (err) {
        res.status(500).json({ error: "Server error" });
      }
    }
  );
});

// ------------------- LOGIN -------------------
// Authenticates user by email and password
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  // Query user by email
  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) return res.status(500).json({ error: "Database error" });

      const user = results[0];
      if (!user) return res.status(401).json({ error: "User not found" });

      // If user registered via Google, disallow normal login
      if (user.is_google)
        return res.status(403).json({ error: "Use Google Sign-In instead" });

      // Verify password
      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(401).json({ error: "Invalid password" });

      // Sign JWT token with user info
      const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
        expiresIn: "7d",
      });

      // Respond with token and user info (exclude password)
      res.json({
        message: "Login successful",
        token,
        user: { name: user.name, email: user.email },
      });
    }
  );
});

// ------------------- GOOGLE SIGN-IN -------------------
// This route will insert a new Google user or update existing user's name
app.post("/google-signin", (req, res) => {
  const { name, email } = req.body;

  // Basic validation
  if (!name || !email)
    return res.status(400).json({ error: "Missing name or email" });

  // First, check if user already exists
  db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });

    if (results.length === 0) {
      // User does not exist - Insert new Google user (POST style)
      db.query(
        "INSERT INTO users (name, email, is_google) VALUES (?, ?, TRUE)",
        [name, email],
        (err) => {
          if (err)
            return res.status(500).json({ error: "Google user insert failed" });

          // Generate JWT token
          const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "7d" });

          res.json({
            message: "Google user created",
            token,
            user: { name, email },
          });
        }
      );
    } else {
      // User exists - Update user's name (PATCH style)
      db.query(
        "UPDATE users SET name = ?, is_google = TRUE WHERE email = ?",
        [name, email],
        (err) => {
          if (err)
            return res.status(500).json({ error: "Google user update failed" });

          const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "7d" });

          res.json({
            message: "Google user updated",
            token,
            user: { name, email },
          });
        }
      );
    }
  });
});

// ------------------- FORGOT PASSWORD -------------------
// Sends a reset password link to the user's email if it exists
app.post("/forgot-password", (req, res) => {
  const { email } = req.body;

  // Validate email format
  if (!validator.isEmail(email))
    return res.status(400).json({ error: "Invalid email" });

  // Generate a JWT token for password reset (expires in 1 hour)
  const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "1h" });
  const expireTime = new Date(Date.now() + 3600000); // 1 hour later

  // Save reset token and expiration to user record
  db.query(
    "UPDATE users SET reset_token = ?, token_expires = ? WHERE email = ?",
    [token, expireTime, email],
    (err, result) => {
      if (err) return res.status(500).json({ error: "Database error" });
      if (result.affectedRows === 0)
        return res.status(404).json({ error: "User not found" });

      // Prepare password reset link to frontend
      const resetLink = `${FRONTEND_URL}/reset-password.html?token=${token}`;
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Reset your password",
        html: `<p>Click <a href='${resetLink}'>here</a> to reset your password. Link expires in 1 hour.</p>`,
      };

      // Send reset link email
      transporter.sendMail(mailOptions, (err) => {
        if (err) return res.status(500).json({ error: "Email failed" });
        res.json({ message: "Reset link sent" });
      });
    }
  );
});

// ------------------- RESET PASSWORD -------------------
// Endpoint to reset password using valid token
app.post("/reset-password", async (req, res) => {
  const { token, newPassword } = req.body;

  // Validate inputs
  if (!token || !newPassword)
    return res.status(400).json({ error: "Missing token or password" });

  try {
    // Verify token validity
    const decoded = jwt.verify(token, JWT_SECRET);

    // Hash the new password
    const hashed = await bcrypt.hash(newPassword, 10);

    // Update password and clear reset token info
    db.query(
      "UPDATE users SET password = ?, reset_token = NULL, token_expires = NULL WHERE email = ? AND reset_token = ?",
      [hashed, decoded.email, token],
      (err, result) => {
        if (err) return res.status(500).json({ error: "Database error" });
        if (result.affectedRows === 0)
          return res.status(400).json({ error: "Invalid or expired token" });
        res.json({ message: "Password updated" });
      }
    );
  } catch {
    // Token verification failed
    res.status(400).json({ error: "Invalid or expired token" });
  }
});

// Start the server on specified port or 4000 by default
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
