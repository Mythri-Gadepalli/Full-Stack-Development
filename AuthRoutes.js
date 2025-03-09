import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import User from "../models/User.js";

const router = express.Router();

// User Registration
router.post("/register", async (req, res) => {
  const { user, username, password } = req.body;

  if (!user || !username || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) {
      return res.status(400).json({ message: "Username already taken" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = new User({ user, username, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: "Account created successfully. You can now log in." });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// User Login
router.post("/login", async (req, res) => {
  const { user, username, password } = req.body;

  if (!user || !username || !password) {
    return res.status(400).json({ message: "All fields are required" });
  }

  try {
    const existingUser = await User.findOne({ username });
    if (!existingUser) {
      return res.status(400).json({ message: "Username does not exist." });
    }

    const isPasswordCorrect = await bcrypt.compare(password, existingUser.password);
    if (!isPasswordCorrect || existingUser.user !== user) {
      return res.status(400).json({ message: "Incorrect password/User." });
    }

    const token = jwt.sign({ userId: existingUser._id }, process.env.JWT_SECRET, { expiresIn: "1h" });

    res.status(200).json({ message: "Login successful", token });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

export default router;
