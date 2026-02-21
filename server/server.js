import express from "express";
import cors from "cors";
import { registerUser, loginUser, logoutUser } from "./auth.js";
import nodemailer from "nodemailer";
import dotenv from "dotenv";
dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const PORT = 5001;

app.get("/", (req, res) => {
  res.send("ShelfX backend is running.");
});

app.post("/api/register", (req, res) => {
  const { username, password } = req.body;
  const result = registerUser({ username, password });
  if (result.error) return res.status(400).json({ error: result.error });
  res.json({ success: true });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const result = loginUser({ username, password });
  if (result.error) return res.status(400).json({ error: result.error });
  res.json({ token: result.token });
});

app.post("/api/logout", (req, res) => {
  // For stateless JWT, logout is handled client-side
  res.json(logoutUser());
});

app.post("/api/send-receipt", async (req, res) => {
  const { email, books, total } = req.body;
  if (!email || !books || !total) return res.status(400).json({ error: "Missing data" });

  // Check if env variables are loaded
  if (!process.env.EMAIL_USER || !process.env.EMAIL_PASS) {
    console.error("EMAIL_USER or EMAIL_PASS not set in .env file");
    return res.status(500).json({ error: "Email configuration missing" });
  }

  console.log("Attempting to send email from:", process.env.EMAIL_USER);
  
  // Configure nodemailer (example with Gmail, update with your credentials)
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

  const bookList = books.map(b => `${b.title} (x${b.quantity || 1}): $${b.price.toFixed(2)}`).join("<br>");
  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: "ShelfX Receipt",
    html: `<h2>Your ShelfX Receipt</h2><div>${bookList}</div><div style='margin-top:16px;font-weight:bold;'>Total: $${total.toFixed(2)}</div>`
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log("Email sent successfully to:", email);
    res.json({ success: true });
  } catch (err) {
    console.error("Email sending failed:", err.message);
    console.error("Full error:", err);
    res.status(500).json({ error: "Failed to send email: " + err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
