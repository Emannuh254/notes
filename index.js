require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const validator = require("validator");

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_key";
const FRONTEND_URL = process.env.CORS_ORIGIN || "https://emannuh254.github.io";

// Middleware
app.use(
  cors({
    origin: FRONTEND_URL,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
  })
);
app.use(express.json());

// MySQL DB connection
const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
});

// Create users table if it doesn't exist
db.query(
  `CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255),
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255),
    is_google BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`,
  (err) => {
    if (err) console.error("❌ Error creating users table:", err.message);
    else console.log("✅ Users table ready!");
  }
);

// Root
app.get("/", (req, res) => {
  res.send("✅ FlipMarket backend is running");
});

// Signup
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password)
    return res.status(400).json({ error: "All fields are required" });

  if (!validator.isEmail(email))
    return res.status(400).json({ error: "Invalid email" });

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
        return res.status(409).json({ error: "Email already exists" });

      try {
        const hashed = await bcrypt.hash(password, 10);
        db.query(
          "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
          [name, email, hashed],
          (err) => {
            if (err) return res.status(500).json({ error: "Signup failed" });
            res.json({ message: "User created successfully" });
          }
        );
      } catch {
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
        return res
          .status(403)
          .json({ error: "Use Google Sign-In for this account" });

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

// Google Sign-In (automatic login or creation)
app.post("/google-signin", (req, res) => {
  const { name, email } = req.body;

  if (!name || !email)
    return res.status(400).json({ error: "Missing name or email" });

  db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });

    if (results.length === 0) {
      // New user
      db.query(
        "INSERT INTO users (name, email, is_google) VALUES (?, ?, TRUE)",
        [name, email],
        (err) => {
          if (err)
            return res
              .status(500)
              .json({ error: "Failed to insert Google user" });

          const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "7d" });
          res.json({
            message: "Google user created",
            token,
            user: { name, email },
          });
        }
      );
    } else {
      // Existing user (manual or google) — update and log in
      db.query(
        "UPDATE users SET name = ?, is_google = TRUE WHERE email = ?",
        [name, email],
        (err) => {
          if (err)
            return res
              .status(500)
              .json({ error: "Failed to update Google user" });

          const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "7d" });
          res.json({
            message: "Google user signed in",
            token,
            user: { name, email },
          });
        }
      );
    }
  });
});

// Check if email exists (for frontend toast)
app.get("/check-email", (req, res) => {
  const email = req.query.email;
  if (!validator.isEmail(email)) return res.json({ exists: false });

  db.query("SELECT id FROM users WHERE email = ?", [email], (err, results) => {
    if (err || results.length === 0) return res.json({ exists: false });
    res.json({ exists: true });
  });
});

// Start server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
