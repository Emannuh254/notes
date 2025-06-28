require("dotenv").config();
const express = require("express");
const cors = require("cors");
const mysql = require("mysql2");
const app = express();

app.use(cors());
app.use(express.json());

// ✅ Use a connection pool
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

// ✅ Create `users` table once the server starts
db.query(
  `CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
  )`,
  (err) => {
    if (err) {
      console.error("❌ Error creating users table:", err.message);
    } else {
      console.log("✅ Users table is ready!");
    }
  }
);

// ✅ Health check route
app.get("/", (req, res) => {
  res.send("✅ FlipMarket backend is alive");
});

// ✅ Signup route
app.post("/signup", (req, res) => {
  const { email, password } = req.body;
  const q = "INSERT INTO users (email, password) VALUES (?, ?)";
  db.query(q, [email, password], (err, result) => {
    if (err) {
      console.error("❌ Signup error:", err.message);
      return res.status(500).json({ error: err.message });
    }
    res.json({ message: "✅ Signup successful!" });
  });
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
