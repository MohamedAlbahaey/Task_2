import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import Joi from 'joi';
import { User } from '../models/User.js';

const registerSchema = Joi.object({
  name: Joi.string().min(2).max(60).required(),
  email: Joi.string().email().required(),
  password: Joi.string().min(6).required()
});

export async function register(req, res, next) {
  try {
    const { value, error } = registerSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.message });

    const existing = await User.findOne({ email: value.email });
    if (existing) return res.status(409).json({ message: 'Email already used' });

    const passwordHash = await bcrypt.hash(value.password, 10);
    const user = await User.create({ name: value.name, email: value.email, passwordHash });
    const token = signToken(user);
    res.status(201).json({ token, user: publicUser(user) });
  } catch (err) { next(err); }
}

const loginSchema = Joi.object({
  email: Joi.string().email().required(),
  password: Joi.string().required()
});

// TODO: implement login function
export async function login(req, res, next) {
  try {
    // 1️⃣ Validate input
    const { value, error } = loginSchema.validate(req.body);
    if (error) return res.status(400).json({ message: error.message });

    // 2️⃣ Check user existence
    const user = await User.findOne({ email: value.email });
    if (!user) return res.status(401).json({ message: "Invalid email or password" });

    // 3️⃣ Compare password
    const isMatch = await bcrypt.compare(value.password, user.passwordHash);
    if (!isMatch) return res.status(401).json({ message: "Invalid email or password" });

    // 4️⃣ If frontend sends a token to verify (e.g., in Authorization header or body)
    const token = req.headers.authorization?.split(" ")[1] || value.token;
    if (token) {
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        // Optional: check that token belongs to the same user
        if (decoded.id !== user._id.toString()) {
          return res.status(403).json({ message: "Token does not belong to this user" });
        }

        // ✅ Token valid and user authenticated
        return res.status(200).json({
          message: "Token verified successfully",
          user: publicUser(user),
        });
      } catch (err) {
        return res.status(401).json({ message: "Invalid or expired token" });
      }
    }

    // 5️⃣ If no token provided — optionally generate a new one (or just respond)
    // If you truly don’t want to create new tokens here, just respond with success.
    return res.status(200).json({
      message: "Login successful (no token verification needed)",
      user: publicUser(user),
    });

  } catch (err) {
    next(err);
  }
}


export async function me(req, res) {
  const user = await User.findById(req.user.id).lean();
  res.json({ user: user && publicUser(user) });
}

function signToken(user) {
  const payload = { id: user._id.toString(), name: user.name, role: user.role };
  return jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '7d' });
}

function publicUser(u) {
  return { id: u._id?.toString() || u.id, name: u.name, email: u.email, role: u.role };
}
