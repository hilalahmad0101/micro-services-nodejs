import { Router } from "express";


const router = Router();

import { register, login, refreshTokens, logout, validateToken, getProfile, deleteUser } from "./auth.controller";
import { validateSchema } from "../../../shared/middleware";
import { loginSchema, refreshTokenSchema, registerSchema } from "./validation";


router.post("/register", validateSchema(registerSchema), register);
router.post("/login", validateSchema(loginSchema), login);
router.post("/refresh", validateSchema(refreshTokenSchema), refreshTokens);
router.post("/logout", validateSchema(refreshTokenSchema), logout);

// token validate endpoint
router.post("/validate", validateToken);

// protected routes

router.get("/profile", getProfile);
router.delete("/profile", deleteUser);


export default router;