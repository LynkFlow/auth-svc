import express from "express";
import cookieParser from "cookie-parser";
import helmet from "helmet";
import config from "./src/config/env";
import authRoutes from "./src/routes/authRoutes";
import {
    errorHandler,
    notFoundHandler,
} from "./src/middleware/errorHandler";

const app = express();

if (config.trustProxy !== false) {
    app.set("trust proxy", config.trustProxy);
}

app.disable("x-powered-by");
app.use(helmet());
app.use(express.json({ limit: "10kb" }));
app.use(cookieParser());

app.get("/", (_req, res) => {
    res.status(200).json({
        success: true,
        message: "LF Auth Backend is running",
    });
});

app.use("/api/v1/auth", authRoutes);

app.use(notFoundHandler);
app.use(errorHandler);

export default app;
