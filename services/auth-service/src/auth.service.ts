import { refresh } from './../node_modules/effect/src/Resource';
import { AuthAccessToken, AuthRefreshToken, AuthTokens, JWTPayload, ServiceError } from '../../../shared/types';
import { loginSchema, registerSchema } from './validation';
import bcrypt from 'bcryptjs';
import prisma from './database';
import jwt, { SignOptions } from 'jsonwebtoken';
import { StringValue } from 'ms'
import { createServiceError } from '../../../shared/utils';

export class AuthService {
    private readonly jwtSecret: string;
    private readonly jwtRefreshSecret: string;
    private readonly jwtExpiresIn: string;
    private readonly jwtRefreshExpiresIn: string;
    private readonly bcryptRounds: number;

    constructor() {
        this.jwtSecret = process.env.JWT_SECRET!;
        this.jwtRefreshSecret = process.env.JWT_REFRESH_SECRET!;
        this.jwtExpiresIn = process.env.JWT_EXPIRES_IN || '1h';
        this.jwtRefreshExpiresIn = process.env.JWT_REFRESH_EXPIRES_IN || '7d';
        this.bcryptRounds = parseInt(process.env.BCRYPT_ROUNDS || '10', 10);

        if (!this.jwtSecret || !this.jwtRefreshSecret) {
            throw new Error('JWT secrets are not defined in environment variables');
        }
    }

    async register(email: string, password: string, confirmPassword: string): Promise<AuthTokens> {
        // Validate input
        const { error } = registerSchema.validate({ email, password, confirmPassword });
        if (error) {
            throw createServiceError(error.message, 400);
        }

        // Check if user already exists
        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser) {
            throw createServiceError('User already exists', 409);
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, this.bcryptRounds);

        // Save user to database
        const user = await prisma.user.create({
            data: {
                email,
                password: hashedPassword,
            },
        });

        // Generate tokens
        const accessToken = await this.generateAccessToken(user.id, user.email);
        const refreshToken = await this.generateRefreshToken(user.id, user.email);

        return {
            accessToken,
            refreshToken,
        } as AuthTokens;
    }

    async login(email: string, password: string): Promise<AuthTokens> {
        // Validate input
        const { error } = loginSchema.validate({ email, password });
        if (error) {
            throw createServiceError(error.message, 400);
        }

        // Find user by email
        const user = await prisma.user.findUnique({ where: { email } });
        if (!user) {
            throw createServiceError('Invalid email or password', 401);
        }

        // Check password
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            throw createServiceError('Invalid email or password', 401);
        }

        // Generate tokens
        const accessToken = await this.generateAccessToken(user.id, user.email);
        const refreshToken = await this.generateRefreshToken(user.id, user.email);

        return {
            accessToken,
            refreshToken,
        } as AuthTokens;
    }


    async refreshToken(refreshToken: string): Promise<AuthTokens> {
        try {

            const decoded = jwt.verify(refreshToken, this.jwtRefreshSecret) as JWTPayload;

            // check if the user exists
            const storedToken = await prisma.refreshToken.findUnique({ where: { token: refreshToken }, include: { user: true } });

            if (!storedToken || storedToken.expiresAt < new Date()) {
                throw createServiceError('Refresh token is invalid or expired', 401);
            }

            // Generate new tokens
            const accessToken = await this.generateAccessToken(storedToken.user.id, storedToken.user.email);

            const newRefreshToken = await this.generateRefreshToken(storedToken.user.id, storedToken.user.email);

            // Optionally, you can delete the old refresh token from the database
            await prisma.refreshToken.delete({ where: { id: storedToken.id } });

            return {
                accessToken,
                refreshToken: newRefreshToken,
            } as AuthTokens;

        } catch (error) {
            if (error instanceof ServiceError) {
                throw error;
            }
            throw createServiceError('Invalid refresh token', 401, error);
        }
    }

    async logout(refreshToken: string): Promise<void> {
        // Validate the refresh token
        const storedToken = await prisma.refreshToken.deleteMany({ where: { token: refreshToken } });
        if (!storedToken) {
            throw createServiceError('Refresh token not found', 404);
        }
    }

    async validateToken(token: string): Promise<JWTPayload> {
        try {
            const decoded = jwt.verify(token, this.jwtSecret) as JWTPayload;

            // Check if the user exists
            const user = await prisma.user.findUnique({ where: { id: decoded.userId } });
            if (!user) {
                throw createServiceError('User not found', 404);
            }
            return decoded;
        } catch (error) {
            if (error instanceof jwt.JsonWebTokenError) {
                throw createServiceError('Invalid access token', 401);
            }
            throw createServiceError('Token validation failed', 500, error);
        }
    }

    private async generateAccessToken(userId: string, email: string): Promise<AuthAccessToken> {
        const payload = {
            userId,
            email,
        };

        const accessTokenOptions: SignOptions = {
            expiresIn: this.jwtExpiresIn as StringValue,
        };

        const accessToken = jwt.sign(payload, this.jwtSecret, accessTokenOptions) as string;

        return {
            accessToken,
        } as AuthAccessToken;

    }

    private async generateRefreshToken(userId: string, email: string): Promise<AuthRefreshToken> {
        const payload = {
            userId,
            email,
        };

        const refreshTokenOptions: SignOptions = {
            expiresIn: this.jwtRefreshExpiresIn as StringValue,
        };

        const refreshToken = jwt.sign(payload, this.jwtRefreshSecret, refreshTokenOptions) as string;

        const expiresAt = new Date();
        expiresAt.setDate(expiresAt.getDate() + parseInt(this.jwtRefreshExpiresIn, 10));
        await prisma.refreshToken.create({
            data: {
                userId,
                token: refreshToken,
                expiresAt,
            },
        });

        return {
            refreshToken,
        } as AuthRefreshToken;
    }

    async getUserById(userId: string) {
        const user = await prisma.user.findUnique({
            where: { id: userId },
            select: {
                id: true,
                email: true,
                createdAt: true,
                updatedAt: true,
            },
        });

        // check if user exists
        if (!user) {
            throw createServiceError('User not found', 404);
        }

        return user;
    }

    async deleteUser(userId: string): Promise<void> {
        await prisma.user.delete({
            where: { id: userId }
        });
    }
}