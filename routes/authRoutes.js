import express from "express";
import passport from "passport";  // import passport
import { registerController } from "../controllers/authController.js";
import rateLimit from "express-rate-limit";

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 100,
  standardHeaders: true,
  legacyHeaders: false,
});

const router = express.Router();

router.post("/register", limiter, registerController);

router.post("/login", limiter, (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) return next(err);

    if (!user) {
      return res.status(401).json({ success: false, message: info.message || "Login failed" });
    }

    // If you want to create JWT token (assuming user.createJWT exists)
    const token = user.createJWT();

    user.password = undefined; // hide password

    res.status(200).json({
      success: true,
      message: "Login successful",
      user,
      token,
    });
  })(req, res, next);
});

export default router;
