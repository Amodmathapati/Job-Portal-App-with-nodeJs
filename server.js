import swaggerUi from "swagger-ui-express";
import swaggerDoc from "swagger-jsdoc";

import express from "express";
import "express-async-errors";
import dotenv from "dotenv";
import colors from "colors";
import cors from "cors";
import morgan from "morgan";

import helmet from "helmet";
import xss from "xss-clean";
import mongoSanitize from "express-mongo-sanitize";

import passport from "passport";
import session from "express-session"; // only if you want session support

import connectDB from "./config/db.js";

import testRoutes from "./routes/testRoutes.js";
import authRoutes from "./routes/authRoutes.js";
import errroMiddelware from "./middelwares/errroMiddleware.js";
import jobsRoutes from "./routes/jobsRoute.js";
import userRoutes from "./routes/userRoutes.js";

// Load Passport config - you need to create this file with your strategies
import "./passportConfig.js";

dotenv.config();

connectDB();

const options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "Job Portal Application",
      description: "Node Expressjs Job Portal Application",
    },
    servers: [
      {
        url: "https://nodejs-job-portal-app.onrender.com",
      },
    ],
  },
  apis: ["./routes/*.js"],
};

const spec = swaggerDoc(options);

const app = express();

app.use(helmet());
app.use(xss());
app.use(mongoSanitize());
app.use(express.json());
app.use(cors());
app.use(morgan("dev"));

// If you want session support (optional)
// You can skip this if you are only using JWTs
app.use(
  session({
    secret: process.env.SESSION_SECRET || "some_secret_key",
    resave: false,
    saveUninitialized: false,
  })
);

// Initialize passport and session (if using sessions)
app.use(passport.initialize());
app.use(passport.session());

// Routes
app.use("/api/v1/test", testRoutes);
app.use("/api/v1/auth", authRoutes);
app.use("/api/v1/user", userRoutes);
app.use("/api/v1/job", jobsRoutes);

app.use("/api-doc", swaggerUi.serve, swaggerUi.setup(spec));

// Error middleware
app.use(errroMiddelware);

const PORT = process.env.PORT || 8080;

app.listen(PORT, () => {
  console.log(
    `Node Server Running In ${process.env.DEV_MODE} Mode on port no ${PORT}`
      .bgCyan.white
  );
});
