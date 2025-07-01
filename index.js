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

const FRONTEND_URL =
  process.env.CORS_ORIGIN || "https://emannuh254.github.io/login-page/";

app.use(
  cors({
    origin: FRONTEND_URL,
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
  })
);

app.use(express.json());

const db = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT,
  waitForConnections: true,
  connectionLimit: 10,
});

db.query(
  `CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255),
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255),
    is_google BOOLEAN DEFAULT FALSE,
    reset_token VARCHAR(255),
    token_expires DATETIME,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`,
  (err) => {
    if (err) console.error("❌ Error creating users table:", err.message);
    else console.log("✅ Users table ready!");
  }
);
// Ensure google_users table exists
db.query(
  `CREATE TABLE IF NOT EXISTS google_users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255),
    email VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`,
  (err) => {
    if (err)
      console.error("❌ Error creating google_users table:", err.message);
    else console.log("✅ Google Users table ready!");
  }
);

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: { error: "Too many requests. Try again later." },
});
app.use("/login", authLimiter);
app.use("/signup", authLimiter);

const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

app.get("/", (req, res) => {
  res.send("✅ FlipMarket backend is alive");
});

// ------------------- SIGNUP -------------------
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password)
    return res.status(400).json({ error: "All fields are required" });

  db.query(
    "SELECT id FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) return res.status(500).json({ error: "Server error" });

      if (results.length > 0) {
        return res.status(409).json({ error: "User already exists" }); // 👈 clear message for frontend toast
      }

      try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.query(
          "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
          [name, email, hashedPassword],
          (err) => {
            if (err) return res.status(500).json({ error: "Signup failed" });
            return res.json({ message: "Signed up successfully" }); // 👈 success toast trigger
          }
        );
      } catch (error) {
        return res.status(500).json({ error: "Server error" });
      }
    }
  );
});

// ------------------- LOGIN -------------------
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) return res.status(500).json({ error: "Server error" });

      const user = results[0];
      if (!user)
        return res.status(401).json({ error: "Invalid email or password" }); // 👈 for toast

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch)
        return res.status(401).json({ error: "Invalid email or password" }); // 👈 for toast

      const token = jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
        expiresIn: "7d",
      });

      return res.json({
        message: "Login successful", // 👈 for toast
        token,
        user: { name: user.name, email: user.email },
      });
    }
  );
});

// ------------------- GOOGLE SIGN-IN -------------------
// ✅ KEEP THIS ONE
app.post("/google-signin", (req, res) => {
  const { name, email } = req.body;

  if (!name || !email)
    return res.status(400).json({ error: "Missing name or email" });

  db.query("SELECT * FROM users WHERE email = ?", [email], (err, results) => {
    if (err) return res.status(500).json({ error: "Database error" });

    if (results.length === 0) {
      // No user exists — insert new Google user
      db.query(
        "INSERT INTO users (name, email, is_google) VALUES (?, ?, TRUE)",
        [name, email],
        (err) => {
          if (err)
            return res
              .status(500)
              .json({ error: "Failed to insert Google user" });

          const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "7d" });
          return res.json({
            message: "Google user created",
            token,
            user: { name, email },
          });
        }
      );
    } else {
      // User exists — allow upgrade to Google user
      db.query(
        "UPDATE users SET name = ?, is_google = TRUE WHERE email = ?",
        [name, email],
        (err) => {
          if (err)
            return res
              .status(500)
              .json({ error: "Failed to update Google user" });

          const token = jwt.sign({ email }, JWT_SECRET, { expiresIn: "7d" });
          return res.json({
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

// ------------------- RESET PASSWORD -------------------
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

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
