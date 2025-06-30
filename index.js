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
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_key";
const FRONTEND_URL = process.env.CORS_ORIGIN || "https://emannuh254.github.io";

app.use(
  cors({
    origin: FRONTEND_URL,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
  })
);
app.use(express.json());

// MySQL connection
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

// Create users table if not exists
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

// Rate limiter
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { error: "Too many requests. Try again later." },
});
app.use("/login", authLimiter);
app.use("/signup", authLimiter);

// Nodemailer setup
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

// Health check
app.get("/", (req, res) => {
  res.send("✅ FlipMarket backend is alive");
});

// Signup
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: "All fields are required" });

  if (!validator.isAlpha(name.replace(" ", "")))
    return res.status(400).json({ error: "Name must contain only letters" });

  if (!validator.isEmail(email))
    return res.status(400).json({ error: "Invalid email format" });

  if (!validator.isLength(password, { min: 6 }))
    return res
      .status(400)
      .json({ error: "Password must be at least 6 characters" });

  db.query(
    "SELECT id FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) return res.status(500).json({ error: "Database error" });
      if (results.length > 0)
        return res.status(409).json({ message: "Email already exists" });

      try {
        const hashed = await bcrypt.hash(password, 10);
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

// Login
app.post("/login", (req, res) => {
  const { email, password } = req.body;
  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) return res.status(500).json({ error: "Database error" });
      const user = results[0];
      if (!user) return res.status(401).json({ error: "User not found" });
      if (user.is_google)
        return res.status(403).json({ error: "Use Google Sign-In instead" });

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(401).json({ error: "Invalid password" });

      const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
        expiresIn: "7d",
      });
      res.json({
        message: "Login successful",
        token,
        user: { name: user.name, email: user.email },
      });
    }
  );
});

// Google Sign-In
app.post("/google-signin", (req, res) => {
  const { name, email } = req.body;
  if (!name || !email)
    return res.status(400).json({ error: "Missing name or email" });

  const query = `INSERT INTO users (name, email, is_google) VALUES (?, ?, true)
    ON DUPLICATE KEY UPDATE name = VALUES(name)`;

  db.query(query, [name, email], (err) => {
    if (err)
      return res.status(500).json({ error: "Google user insert failed" });
    const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "7d" });
    res.json({ message: "Google user saved", token, user: { name, email } });
  });
});

// Forgot Password
app.post("/forgot-password", (req, res) => {
  const { email } = req.body;
  if (!validator.isEmail(email))
    return res.status(400).json({ error: "Invalid email" });

  const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "1h" });
  const expireTime = new Date(Date.now() + 3600000);

  db.query(
    "UPDATE users SET reset_token = ?, token_expires = ? WHERE email = ?",
    [token, expireTime, email],
    (err, result) => {
      if (err) return res.status(500).json({ error: "Database error" });
      if (result.affectedRows === 0)
        return res.status(404).json({ error: "User not found" });

      const resetLink = `${FRONTEND_URL}/reset-password.html?token=${token}`;
      const mailOptions = {
        from: process.env.EMAIL_USER,
        to: email,
        subject: "Reset your password",
        html: `<p>Click <a href='${resetLink}'>here</a> to reset your password. Link expires in 1 hour.</p>`,
      };

      transporter.sendMail(mailOptions, (err) => {
        if (err) return res.status(500).json({ error: "Email failed" });
        res.json({ message: "Reset link sent" });
      });
    }
  );
});

// Reset Password
app.post("/reset-password", async (req, res) => {
  const { token, newPassword } = req.body;
  if (!token || !newPassword)
    return res.status(400).json({ error: "Missing token or password" });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    const hashed = await bcrypt.hash(newPassword, 10);
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
    res.status(400).json({ error: "Invalid or expired token" });
  }
});

// Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
