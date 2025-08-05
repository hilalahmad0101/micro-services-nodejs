import { asyncHandler } from "../../../shared/middleware";
import { AuthService } from "./auth.service";
const authService = new AuthService();
import { Request, Response } from "express";
import { createErrorResponse, createSuccessResponse } from "../../../shared/utils";

// Controller for user registration
export const register = asyncHandler(async (req: Request, res: Response) => {
    const { email, password, confirmPassword } = req.body;
    const tokens = await authService.register(email, password, confirmPassword);
    return res.status(201).json(createSuccessResponse(tokens, "User registered successfully"));
});


// Controller for user login
export const login = asyncHandler(async (req: Request, res: Response) => {
    const { email, password } = req.body;
    const tokens = await authService.login(email, password);
    return res.status(200).json(createSuccessResponse(tokens, "User logged in successfully"));
});

// controller for refreshing tokens
export const refreshTokens = asyncHandler(async (req: Request, res: Response) => {
    const { refreshToken } = req.body;
    const tokens = await authService.refreshToken(refreshToken);
    return res.status(200).json(createSuccessResponse(tokens, "Tokens refreshed successfully"));
});


// Controller for user logout
export const logout = asyncHandler(async (req: Request, res: Response) => {
    const { refreshToken } = req.body;
    await authService.logout(refreshToken);
    return res.status(204).json(createSuccessResponse(null, "User logged out successfully"));
});


// Controller for validating JWT token
export const validateToken = asyncHandler(async (req: Request, res: Response) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json(createErrorResponse("Unauthorized"));
    }
    const token = authHeader.split(" ")[1];
    if (!token) {
        return res.status(401).json(createErrorResponse("Unauthorized"));
    }
    // Validate the token
    const payload = await authService.validateToken(token);
    return res.status(200).json(createSuccessResponse(payload, "Token is valid"));
});


export const getProfile = asyncHandler(async (req: Request, res: Response) => {

    const userId = req.user?.id;
    if (!userId) {
        return res.status(401).json(createErrorResponse("Unauthorized"));
    }
    const user = await authService.getUserById(userId);
    if (!user) {
        return res.status(404).json(createErrorResponse("User not found"));
    }
    return res.status(200).json(createSuccessResponse(user, "User profile retrieved successfully"));
});


// Controller for deleting a user

export const deleteUser = asyncHandler(async (req: Request, res: Response) => {
    const userId = req.user?.id;
    if (!userId) {
        return res.status(401).json(createSuccessResponse(null, "Unauthorized"));
    }
    await authService.deleteUser(userId);
    return res.status(204).json(createSuccessResponse(null, "User deleted successfully"));
});