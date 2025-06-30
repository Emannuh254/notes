require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const bcrypt = require("bcrypt");

const app = express();

// ✅ CORS with whitelist from environment
app.use(
  cors({
    origin: process.env.CORS_ORIGIN || "*",
    methods: ["GET", "POST", "OPTIONS"],
    allowedHeaders: ["Content-Type"],
  })
);

app.use(express.json());

// ✅ MySQL Connection
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

// ✅ Create `users` table if it doesn't exist
db.query(
  `
  CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255),
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255),
    is_google BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )
`,
  (err) => {
    if (err) {
      console.error("❌ Error creating users table:", err.message);
    } else {
      console.log("✅ Users table is ready!");
    }
  }
);

// ✅ Health check
app.get("/", (req, res) => {
  res.send("✅ FlipMarket backend is alive");
});

// ✅ Signup Route with Duplicate Email Check
app.post("/signup", async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.status(400).json({ error: "All fields are required" });
  }

  // Disallow two-word names (as per your requirement)
  if (name.trim().split(" ").length > 1) {
    return res.status(400).json({ error: "Only first name is allowed" });
  }

  db.query(
    "SELECT id FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) return res.status(500).json({ error: "Database error" });

      if (results.length > 0) {
        return res.status(409).json({ message: "Email already exists" });
      }

      try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const query =
          "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";
        db.query(query, [name, email, hashedPassword], (err) => {
          if (err) {
            console.error("❌ Signup error:", err.message);
            return res.status(500).json({ error: "Signup failed" });
          }
          res.json({ message: "✅ Signup successful" });
        });
      } catch (err) {
        console.error("❌ Hashing error:", err.message);
        res.status(500).json({ error: "Server error" });
      }
    }
  );
});

// ✅ Login with Email & Password
app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.query(
    "SELECT * FROM users WHERE email = ?",
    [email],
    async (err, results) => {
      if (err) return res.status(500).json({ error: "Database error" });

      if (results.length === 0) {
        return res.status(401).json({ error: "User not found" });
      }

      const user = results[0];

      if (user.is_google) {
        return res.status(403).json({ error: "Use Google Sign-In instead" });
      }

      const isMatch = await bcrypt.compare(password, user.password);
      if (!isMatch) return res.status(401).json({ error: "Invalid password" });

      res.json({
        message: "✅ Login successful",
        user: { id: user.id, email: user.email },
      });
    }
  );
});

// ✅ Google Sign-In
app.post("/google-signin", (req, res) => {
  const { name, email } = req.body;

  if (!name || !email) {
    return res.status(400).json({ error: "Missing name or email" });
  }

  const query = `
    INSERT INTO users (name, email, is_google)
    VALUES (?, ?, true)
    ON DUPLICATE KEY UPDATE name = VALUES(name)
  `;

  db.query(query, [name, email], (err, result) => {
    if (err) {
      console.error("❌ Google Sign-in DB error:", err.message);
      return res.status(500).json({ error: "Google user insert failed" });
    }

    console.log("✅ Google user inserted or updated:", result);
    res.json({ message: "✅ Google user saved" });
  });
});

// ✅ Start the server
const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
