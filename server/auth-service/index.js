import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const app = express();
app.use(cors());
app.use(express.json());

const users = [];
const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret_key";
const PORT = process.env.PORT || 3001;

// Health check endpoint
app.get("/health", (req, res) => {
  res.json({ status: "healthy", service: "auth-service" });
});

// Register endpoint
app.post("/register", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  const existing = users.find((u) => u.username === username);
  if (existing) {
    return res.status(400).json({ error: "User already exists" });
  }

  const hashed = bcrypt.hashSync(password, 8);
  users.push({ username, password: hashed });

  console.log(`User registered: ${username}`);
  res.json({ success: true, message: "User registered successfully" });
});

// Login endpoint
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required" });
  }

  const user = users.find((u) => u.username === username);
  if (!user) {
    return res.status(404).json({ error: "User not found" });
  }

  const valid = bcrypt.compareSync(password, user.password);
  if (!valid) {
    return res.status(401).json({ error: "Invalid password" });
  }

  const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: "1h" });

  console.log(`User logged in: ${username}`);
  res.json({ token, username });
});

// Logout endpoint
app.post("/logout", (req, res) => {
  // For stateless JWT, logout is handled client-side by deleting token
  res.json({ success: true, message: "Logged out successfully" });
});

// Verify token endpoint (for other services)
app.post("/verify", (req, res) => {
  const { token } = req.body;

  if (!token) {
    return res.status(400).json({ error: "Token required" });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    res.json({ valid: true, username: decoded.username });
  } catch (err) {
    res.status(401).json({ valid: false, error: "Invalid or expired token" });
  }
});

app.listen(PORT, () => {
  console.log(`Auth service running on port ${PORT}`);
});
